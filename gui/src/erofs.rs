/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Minimal EROFS reader for uncompressed files (build.prop) from Android
//! system/vendor/product partitions.
//!
//! Supported inode data layouts:
//!   - FLAT_PLAIN (0): file data in contiguous blocks.
//!   - FLAT_INLINE (2): detected but rejected, tail-packed data needs extra work.
//! Compressed (1, 3) and chunk-based (4) inodes are detected and reported as
//! unsupported, since extracting them needs an LZ4/LZMA decompressor.
//!
//! On-disk layout verified against fs/erofs/erofs_fs.h in the Linux tree.

use anyhow::{Result, bail};

use crate::ext4::BlockReader;

const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5E1E2;
const EROFS_SUPER_OFFSET: u64 = 1024;

/// Inode data layouts (i_format bits 1..3).
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_COMPRESSED_FULL: u16 = 1;
const LAYOUT_FLAT_INLINE: u16 = 2;
const LAYOUT_COMPRESSED_COMPACT: u16 = 3;
const LAYOUT_CHUNK_BASED: u16 = 4;

const INODE_SLOT_SIZE: u64 = 32;

pub struct Erofs<R: BlockReader> {
    reader: R,
    block_size: u64,
    meta_blkaddr: u64,
    root_nid: u64,
    feature_incompat: u32,
}

#[derive(Clone, Copy)]
struct Inode {
    datalayout: u16,
    is_extended: bool,
    size: u64,
    /// First physical block of data (flat inodes only).
    startblk: u64,
}

impl<R: BlockReader> Erofs<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let sb = reader.read(EROFS_SUPER_OFFSET, 256)?;

        let magic = u32::from_le_bytes(sb[0..4].try_into().unwrap());
        if magic != EROFS_SUPER_MAGIC_V1 {
            bail!("not an EROFS filesystem (magic 0x{magic:08X})");
        }

        let blkszbits = sb[12] as u32;
        if blkszbits > 32 {
            bail!("invalid EROFS block size shift {blkszbits}");
        }
        let block_size = 1u64 << blkszbits;

        let feature_incompat = u32::from_le_bytes(sb[80..84].try_into().unwrap());

        // 48BIT moves the root nid to a 64-bit field later in the superblock.
        let root_nid = if feature_incompat & 0x80 != 0 {
            u64::from_le_bytes(sb[112..120].try_into().unwrap())
        } else {
            u16::from_le_bytes(sb[14..16].try_into().unwrap()) as u64
        };

        let meta_blkaddr = u32::from_le_bytes(sb[40..44].try_into().unwrap()) as u64;

        Ok(Self { reader, block_size, meta_blkaddr, root_nid, feature_incompat })
    }

    pub const fn block_size(&self) -> u64 {
        self.block_size
    }

    /// True when the image uses compression for at least some files.
    pub fn uses_compression(&self) -> bool {
        // BIT(1) of the compression-algorithms bitmap means LZMA; any set bit
        // means the image relies on a decompressor we do not have.
        self.feature_incompat & (0x02 | 0x10 | 0x20) != 0
    }

    fn inode_offset(&self, nid: u64) -> u64 {
        (self.meta_blkaddr << self.log2_block_size()) + nid * INODE_SLOT_SIZE
    }

    const fn log2_block_size(&self) -> u32 {
        // Recovered from block_size at construction time would need a stored
        // field; compute it from the guaranteed power-of-two block size.
        self.block_size.trailing_zeros()
    }

    fn read_inode(&mut self, nid: u64) -> Result<Inode> {
        let off = self.inode_offset(nid);
        let raw = self.reader.read(off, 64)?;

        let format = u16::from_le_bytes(raw[0..2].try_into().unwrap());
        let is_extended = format & 0x01 != 0;
        let datalayout = (format >> 1) & 0x07;

        let size = if is_extended {
            u64::from_le_bytes(raw[8..16].try_into().unwrap())
        } else {
            u32::from_le_bytes(raw[8..12].try_into().unwrap()) as u64
        };

        // Flat inodes store the starting block in i_u (le32), with the high
        // 16 bits in the i_nb union for extended inodes.
        let startblk_lo = if is_extended {
            u32::from_le_bytes(raw[16..20].try_into().unwrap()) as u64
        } else {
            u32::from_le_bytes(raw[12..16].try_into().unwrap()) as u64
        };
        let startblk_hi = if is_extended {
            u16::from_le_bytes(raw[6..8].try_into().unwrap()) as u64
        } else {
            0
        };

        Ok(Inode { datalayout, is_extended, size, startblk: (startblk_hi << 32) | startblk_lo })
    }

    /// Walks a directory inode and returns the nid of `name`.
    fn lookup(&mut self, dir_nid: u64, name: &str) -> Result<Option<u64>> {
        let dir = self.read_inode(dir_nid)?;

        match dir.datalayout {
            LAYOUT_FLAT_PLAIN | LAYOUT_FLAT_INLINE => {}
            LAYOUT_COMPRESSED_FULL
            | LAYOUT_COMPRESSED_COMPACT
            | LAYOUT_CHUNK_BASED => {
                bail!("directory uses an unsupported EROFS layout ({})", dir.datalayout)
            }
            _ => bail!("unknown EROFS inode layout {}", dir.datalayout),
        }

        let max_blocks = dir.size.div_ceil(self.block_size);
        for block in 0..max_blocks {
            let physical = (dir.startblk + block) * self.block_size;
            let data = self.reader.read_block(physical, self.block_size as usize)?;

            if let Some(nid) = Self::find_in_dir_block(&data, name, self.block_size as usize) {
                return Ok(Some(nid));
            }
        }

        Ok(None)
    }

    /// Scans one EROFS directory block, mirroring erofs_fill_dentries():
    /// de[0].nameoff both ends the dirent array and starts the name area.
    fn find_in_dir_block(block: &[u8], name: &str, block_size: usize) -> Option<u64> {
        if block.len() < 4 {
            return None;
        }

        let nameoff0 = u16::from_le_bytes(block[0..2].try_into().ok()?) as usize;
        if nameoff0 == 0 || nameoff0 >= block_size || nameoff0 % 12 != 0 || nameoff0 > block.len() {
            return None;
        }

        let dirents_end = nameoff0;
        let mut pos = 0usize;

        while pos + 12 <= dirents_end {
            let nid = u64::from_le_bytes(block[pos..pos + 8].try_into().ok()?);
            let nameoff = u16::from_le_bytes(block[pos + 8..pos + 10].try_into().ok()?) as usize;

            // Name length comes from the next dirent's nameoff, or the block
            // end for the trailing entry.
            let namelen = if pos + 12 + 12 <= dirents_end {
                let next = u16::from_le_bytes(block[pos + 12..pos + 14].try_into().ok()?) as usize;
                next.saturating_sub(nameoff)
            } else {
                block_size.saturating_sub(nameoff)
            };

            if nameoff + namelen <= block.len()
                && namelen == name.len()
                && &block[nameoff..nameoff + namelen] == name.as_bytes()
            {
                return Some(nid);
            }

            pos += 12;
        }

        None
    }

    pub fn read_file(&mut self, path: &[&str]) -> Result<Option<Vec<u8>>> {
        let mut nid = self.root_nid;

        for component in path {
            let Some(next) = self.lookup(nid, component)? else {
                return Ok(None);
            };
            nid = next;
        }

        let inode = self.read_inode(nid)?;

        match inode.datalayout {
            LAYOUT_FLAT_PLAIN => {}
            LAYOUT_FLAT_INLINE => {
                bail!("EROFS tail-packed inline data is not supported yet")
            }
            LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => {
                bail!("file is stored compressed; EROFS decompression is not supported")
            }
            LAYOUT_CHUNK_BASED => bail!("chunk-based EROFS files are not supported"),
            _ => bail!("unknown EROFS inode layout {}", inode.datalayout),
        }

        if inode.size > MAX_FILE_BYTES {
            bail!("file is {} bytes, larger than the {} byte limit", inode.size, MAX_FILE_BYTES);
        }

        let mut data = Vec::with_capacity(inode.size as usize);
        let mut remaining = inode.size;
        let mut block = inode.startblk;

        while remaining > 0 {
            let mut chunk = self.reader.read_block(block * self.block_size, self.block_size as usize)?;
            let take = remaining.min(self.block_size) as usize;
            chunk.truncate(take);
            let take_now = chunk.len();
            data.extend_from_slice(&chunk);
            remaining -= take_now as u64;
            block += 1;
        }

        Ok(Some(data))
    }
}

/// Shared limit with the ext4 reader so neither parser can run away on memory.
const MAX_FILE_BYTES: u64 = 0x40_0000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext4::VecReader;

    /// Builds a tiny EROFS image: superblock, one inode slot for the root
    /// directory and one for the file, plus a directory block and data block.
    fn build_image(contents: &[u8]) -> Vec<u8> {
        let block_size: u64 = 4096;
        let mut img = vec![0u8; 8 * block_size as usize];

        // Superblock at 1024.
        let sb = 1024usize;
        img[sb..sb + 4].copy_from_slice(&EROFS_SUPER_MAGIC_V1.to_le_bytes());
        img[sb + 12] = 12; // blkszbits -> 4096
        img[sb + 14..sb + 16].copy_from_slice(&1u16.to_le_bytes()); // root nid
        img[sb + 40..sb + 44].copy_from_slice(&1u32.to_le_bytes()); // meta_blkaddr (block 1)

        // Metadata area at block 1. Root dir (nid 1) at slot 0, file (nid 2) at slot 1.
        let meta = block_size as usize;
        // Root directory inode: flat, 1 block of dirents, starting at block 3.
        img[meta..meta + 2].copy_from_slice(&(LAYOUT_FLAT_PLAIN << 1).to_le_bytes()); // compact, flat
        img[meta + 8..meta + 12].copy_from_slice(&(block_size as u32).to_le_bytes()); // size = 1 block
        img[meta + 12..meta + 16].copy_from_slice(&3u32.to_le_bytes()); // startblk

        let file = meta + INODE_SLOT_SIZE as usize;
        img[file..file + 2].copy_from_slice(&(LAYOUT_FLAT_PLAIN << 1).to_le_bytes());
        img[file + 8..file + 12].copy_from_slice(&(contents.len() as u32).to_le_bytes());
        img[file + 12..file + 16].copy_from_slice(&4u32.to_le_bytes()); // data at block 4

        // Directory block at block 3: one dirent for "system" -> nid 2.
        let dir = 3 * block_size as usize;
        let nameoff = 12usize; // names start right after the single dirent
        img[dir..dir + 8].copy_from_slice(&2u64.to_le_bytes()); // nid
        img[dir + 8..dir + 10].copy_from_slice(&(nameoff as u16).to_le_bytes());
        img[dir + 10] = 1; // file type regular
        img[dir + 12..dir + 18].copy_from_slice(b"system");

        // File data at block 4.
        let data = 4 * block_size as usize;
        img[data..data + contents.len()].copy_from_slice(contents);

        img
    }

    #[test]
    fn read_file_from_erofs_image() {
        let contents = b"ro.build.version.release=13\nro.product.brand=TestBrand\n";
        let image = build_image(contents);

        let mut fs = Erofs::new(VecReader(image)).expect("valid EROFS image");
        let data = fs.read_file(&["system"]).expect("lookup succeeds");

        assert_eq!(data.as_deref(), Some(contents));
    }

    #[test]
    fn rejects_non_erofs() {
        let image = vec![0u8; 64 * 1024];
        assert!(Erofs::new(VecReader(image)).is_err());
    }
}
