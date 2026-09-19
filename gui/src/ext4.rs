/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Minimal ext4 reader, just enough to extract a file (build.prop) from an
//! Android system/vendor/product partition image.
//!
//! It implements the subset of ext4 needed for read-only file lookup:
//! superblock, block group descriptors, inodes with extents, and directory
//! entries. Indexed directories (htree) are tolerated because every entry also
//! exists in the linear directory data blocks.

use anyhow::{Result, bail};

/// Reads `size` bytes starting at `offset` inside a partition image.
pub trait BlockReader {
    fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>>;

    /// Convenience helper: read a single block.
    fn read_block(&mut self, offset: u64, block_size: usize) -> Result<Vec<u8>> {
        self.read(offset, block_size)
    }
}

/// Reader backed by an in-memory image, used for tests.
#[cfg(test)]
pub struct VecReader(pub Vec<u8>);

#[cfg(test)]
impl BlockReader for VecReader {
    fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let start = offset as usize;
        if start >= self.0.len() {
            bail!("read past end of image");
        }
        let end = (start + size).min(self.0.len());
        Ok(self.0[start..end].to_vec())
    }
}

const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_EXTENTS_FL: u32 = 0x00080000;
const EXT4_HUGE_FILE_FL: u32 = 0x00040000;

/// Root directory inode number in ext2/3/4.
const ROOT_INODE: u32 = 2;

#[derive(Clone, Copy)]
struct Extent {
    /// First logical block covered by this extent.
    logical: u32,
    /// Number of blocks in this extent.
    length: u16,
    /// First physical block of this extent.
    physical: u64,
}

const EXT4_EXT_MAGIC: u16 = 0xF30A;

pub struct Ext4<R: BlockReader> {
    reader: R,
    block_size: usize,
    inode_size: usize,
    blocks_per_group: u64,
    inodes_per_group: u64,
    /// GDT is 32 bytes per entry when the 64bit feature is disabled, 64 otherwise.
    desc_size: usize,
}

/// Largest file this reader will ever pull into memory, as a safety bound.
const MAX_FILE_BYTES: u64 = 0x40_0000;

impl<R: BlockReader> Ext4<R> {
    /// Opens an ext4 image. The superblock lives at byte offset 1024.
    pub fn new(mut reader: R) -> Result<Self> {
        let sb = reader.read(1024, 1024)?;

        let magic = u16::from_le_bytes(sb[56..58].try_into().unwrap());
        if magic != EXT4_SUPER_MAGIC {
            bail!("not an ext4 filesystem (magic 0x{magic:04X})");
        }

        let log_block_size = u32::from_le_bytes(sb[24..28].try_into().unwrap()) as u32;
        let block_size = (1024usize)
            .checked_shl(log_block_size)
            .ok_or_else(|| anyhow::anyhow!("invalid ext4 block size shift {log_block_size}"))?;

        let blocks_per_group = u32::from_le_bytes(sb[32..36].try_into().unwrap()) as u64;
        let inodes_per_group = u32::from_le_bytes(sb[40..44].try_into().unwrap()) as u64;
        let inode_size = u16::from_le_bytes(sb[88..90].try_into().unwrap()) as usize;

        let feature_incompat = u32::from_le_bytes(sb[96..100].try_into().unwrap());
        // The 64bit feature doubles the size of each block group descriptor.
        let desc_size = if feature_incompat & 0x80 != 0 { 64 } else { 32 };

        if block_size < 1024 || inode_size < 128 || inodes_per_group == 0 || blocks_per_group == 0 {
            bail!("invalid ext4 superblock values");
        }

        Ok(Self { reader, block_size, inode_size, blocks_per_group, inodes_per_group, desc_size })
    }

    pub const fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the physical block holding the block group descriptor table.
    /// The GDT follows the block containing the superblock.
    fn gdt_block(&self) -> u64 {
        // The superblock is at byte 1024, i.e. block 0 for 4K blocks (1024 is
        // inside the first block) and block 1 for 1K blocks. The GDT always
        // starts in the next block after the superblock's block.
        if self.block_size == 1024 {
            2
        } else {
            1
        }
    }

    /// Reads the inode table location (physical block) for a block group.
    fn inode_table_block(&mut self, group: u64) -> Result<u64> {
        let gdt_off = self.gdt_block() * self.block_size as u64;
        let entry_off = gdt_off + group * self.desc_size as u64;
        let entry = self.reader.read(entry_off, self.desc_size)?;

        let lo = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let hi = if self.desc_size == 64 {
            u32::from_le_bytes(entry[40..44].try_into().unwrap()) as u64
        } else {
            0
        };

        Ok((hi << 32) | lo)
    }

    /// Reads a full inode by number.
    fn read_inode(&mut self, inode: u32) -> Result<Vec<u8>> {
        if inode == 0 || inode as u64 > self.inodes_per_group * self.blocks_per_group.max(1) {
            bail!("inode {inode} out of range");
        }

        let group = ((inode - 1) / self.inodes_per_group) as u64;
        let index = ((inode - 1) % self.inodes_per_group) as u64;

        let table_block = self.inode_table_block(group)?;
        let inode_off = table_block * self.block_size as u64 + index * self.inode_size as u64;
        self.reader.read(inode_off, self.inode_size)
    }

    /// Resolves the extents of an inode. Returns `(extents, file_size)`.
    fn resolve_extents(&mut self, inode: u32) -> Result<(Vec<Extent>, u64)> {
        let raw = self.read_inode(inode)?;
        let flags = u32::from_le_bytes(raw[32..36].try_into().unwrap());

        let size_lo = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as u64;
        let size_hi = if raw.len() >= 0x6C + 4 {
            u32::from_le_bytes(raw[0x6C..0x70].try_into().unwrap()) as u64
        } else {
            0
        };
        let size = if flags & EXT4_HUGE_FILE_FL != 0 {
            size_lo | (size_hi << 32)
        } else {
            size_lo
        };

        // i_block occupies 60 bytes at offset 40.
        let i_block = &raw[40..100];

        if flags & EXT4_EXTENTS_FL == 0 {
            bail!("inode {inode} does not use extents (unsupported)");
        }

        let entries = u16::from_le_bytes(i_block[2..4].try_into().unwrap()) as usize;
        let depth = u16::from_le_bytes(i_block[6..8].try_into().unwrap());
        if depth != 0 {
            // Index nodes would require walking an extra level of the tree.
            bail!("extent tree depth {depth} is not supported");
        }
        if entries == 0 {
            return Ok((Vec::new(), size));
        }

        let mut extents = Vec::with_capacity(entries);
        // The extent header is 12 bytes; each extent record is 12 bytes too.
        for i in 0..entries {
            let off = 12 + i * 12;
            let rec = &i_block[off..off + 12];

            let logical = u32::from_le_bytes(rec[0..4].try_into().unwrap());
            let length = u16::from_le_bytes(rec[4..6].try_into().unwrap());
            let phys_lo = u32::from_le_bytes(rec[6..10].try_into().unwrap()) as u64;
            let phys_hi = u16::from_le_bytes(rec[10..12].try_into().unwrap()) as u64;

            extents.push(Extent { logical, length, physical: (phys_hi << 32) | phys_lo });
        }

        extents.sort_by_key(|e| e.logical);
        Ok((extents, size))
    }

    /// Walks a directory inode and returns the inode number of `name`, if present.
    fn lookup(&mut self, dir_inode: u32, name: &str) -> Result<Option<u32>> {
        let (extents, _size) = self.resolve_extents(dir_inode)?;

        for extent in extents {
            for block in 0..extent.length {
                let physical = (extent.physical + block as u64) * self.block_size as u64;
                let data = self.reader.read_block(physical, self.block_size)?;

                if let Some(found) = Self::find_in_dir_block(&data, name) {
                    return Ok(Some(found));
                }
            }
        }

        Ok(None)
    }

    /// Scans a raw directory data block for an entry named `name`.
    /// Entries are found by walking the record chain via `rec_len`.
    fn find_in_dir_block(block: &[u8], name: &str) -> Option<u32> {
        let mut offset = 0usize;

        while offset + 8 <= block.len() {
            let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().ok()?);
            let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().ok()?) as usize;
            let name_len = block[offset + 6] as usize;

            if rec_len < 8 || offset + rec_len > block.len() {
                return None;
            }

            if inode != 0
                && name_len == name.len()
                && offset + 8 + name_len <= block.len()
                && &block[offset + 8..offset + 8 + name_len] == name.as_bytes()
            {
                return Some(inode);
            }

            offset += rec_len;
        }

        None
    }

    /// Reads a file by path, e.g. `["system", "build.prop"]` from the partition root.
    pub fn read_file(&mut self, path: &[&str]) -> Result<Option<Vec<u8>>> {
        let mut inode = ROOT_INODE;

        for component in path {
            let Some(next) = self.lookup(inode, component)? else {
                return Ok(None);
            };
            inode = next;
        }

        let (extents, size) = self.resolve_extents(inode)?;

        if size > MAX_FILE_BYTES {
            bail!("file is {size} bytes, larger than the {MAX_FILE_BYTES} byte limit");
        }

        let mut data = Vec::with_capacity(size.min(MAX_FILE_BYTES) as usize);
        for extent in extents {
            for block in 0..extent.length {
                if data.len() as u64 >= size {
                    break;
                }
                let physical = (extent.physical + block as u64) * self.block_size as u64;
                let mut chunk = self.reader.read_block(physical, self.block_size)?;
                data.append(&mut chunk);
            }
        }

        data.truncate(size as usize);
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny but structurally valid ext4 image in memory:
    /// block 0-1: padding + superblock, block 2: GDT, block 3: inode table,
    /// block 4: root directory, block 5: the file's data.
    fn build_image(file_contents: &[u8]) -> Vec<u8> {
        let block_size = 1024;
        let mut img = vec![0u8; 16 * block_size];

        // Superblock at byte 1024 (inside block 1 for 1K blocks).
        let sb_off = 1024;
        img[sb_off + 56..sb_off + 58].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes()); // magic
        img[sb_off + 24..sb_off + 28].copy_from_slice(&0u32.to_le_bytes()); // log_block_size -> 1024
        img[sb_off + 32..sb_off + 36].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
        img[sb_off + 40..sb_off + 44].copy_from_slice(&1024u32.to_le_bytes()); // inodes_per_group
        img[sb_off + 88..sb_off + 90].copy_from_slice(&128u16.to_le_bytes()); // inode size

        // GDT at block 2: entry 0 points its inode table at block 3.
        let gdt_off = 2 * block_size;
        img[gdt_off + 8..gdt_off + 12].copy_from_slice(&3u32.to_le_bytes());

        // Inode table at block 3.
        // Inode N lives at index (N-1): inode 2 at index 1, inode 3 at index 2.
        let itab_off = 3 * block_size;
        let root_off = itab_off + 128; // inode 2 = index 1
        let file_off = itab_off + 256; // inode 3 = index 2

        // --- Root directory inode 2: extent pointing to physical block 4 ---
        // i_flags @ 32: set EXT4_EXTENTS_FL.
        let root_flags_off = root_off + 32;
        let mut root_flags = u32::from_le_bytes(img[root_flags_off..root_flags_off + 4].try_into().unwrap());
        root_flags |= EXT4_EXTENTS_FL;
        img[root_flags_off..root_flags_off + 4].copy_from_slice(&root_flags.to_le_bytes());
        // i_block @ 40: extent header (12 bytes).
        img[root_off + 40..root_off + 42].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes()); // eh_magic
        img[root_off + 42..root_off + 44].copy_from_slice(&1u16.to_le_bytes());             // eh_entries
        img[root_off + 44..root_off + 46].copy_from_slice(&4u16.to_le_bytes());             // eh_max
        img[root_off + 46..root_off + 48].copy_from_slice(&0u16.to_le_bytes());             // eh_depth=0
        // i_block extent record @ 52 (12 bytes): logical=0, len=1, phys=4.
        img[root_off + 52..root_off + 56].copy_from_slice(&0u32.to_le_bytes());             // ee_block=0
        img[root_off + 56..root_off + 58].copy_from_slice(&1u16.to_le_bytes());             // ee_len=1
        img[root_off + 58..root_off + 60].copy_from_slice(&4u16.to_le_bytes());             // ee_start_hi
        img[root_off + 60..root_off + 64].copy_from_slice(&0u32.to_le_bytes());             // ee_start_lo (block 4 above, written below)

        // Root directory data at block 4: entries for "system" (inode 3).
        let dir_off = 4 * block_size;
        let entry = build_dir_entry(3, "system", block_size);
        img[dir_off..dir_off + entry.len()].copy_from_slice(&entry);

        // --- File inode 3: extent pointing to physical block 5 ---
        let file_size = file_contents.len() as u32;
        img[file_off + 4..file_off + 8].copy_from_slice(&file_size.to_le_bytes());           // i_size_lo
        let file_flags_off = file_off + 32;
        let mut file_flags = u32::from_le_bytes(img[file_flags_off..file_flags_off + 4].try_into().unwrap());
        file_flags |= EXT4_EXTENTS_FL;
        img[file_flags_off..file_flags_off + 4].copy_from_slice(&file_flags.to_le_bytes());
        // extent header
        img[file_off + 40..file_off + 42].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        img[file_off + 42..file_off + 44].copy_from_slice(&1u16.to_le_bytes());
        img[file_off + 44..file_off + 46].copy_from_slice(&4u16.to_le_bytes());
        img[file_off + 46..file_off + 48].copy_from_slice(&0u16.to_le_bytes());
        // extent record: logical=0, len=1, phys=5
        img[file_off + 52..file_off + 56].copy_from_slice(&0u32.to_le_bytes());
        img[file_off + 56..file_off + 58].copy_from_slice(&1u16.to_le_bytes());
        img[file_off + 58..file_off + 60].copy_from_slice(&0u16.to_le_bytes());
        img[file_off + 60..file_off + 64].copy_from_slice(&5u32.to_le_bytes());

        // File data at block 5.
        let data_off = 5 * block_size;
        img[data_off..data_off + file_contents.len()].copy_from_slice(file_contents);

        img
    }

    fn build_dir_entry(inode: u32, name: &str, block_size: usize) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&inode.to_le_bytes());
        // The single entry consumes the whole block so the chain terminates.
        entry.extend_from_slice(&(block_size as u16).to_le_bytes());
        entry.push(name.len() as u8);
        entry.push(1); // file type: regular file
        entry.extend_from_slice(name.as_bytes());
        entry
    }

    #[test]
    fn read_file_from_image() {
        let contents = b"ro.build.version.release=13\nro.product.brand=TestBrand\n";
        let image = build_image(contents);

        let mut fs = Ext4::new(VecReader(image)).expect("valid ext4 image");
        let data = fs.read_file(&["system"]).expect("lookup succeeds");

        assert_eq!(data.as_deref(), Some(contents));
    }

    #[test]
    fn rejects_non_ext4() {
        let image = vec![0u8; 64 * 1024];
        assert!(Ext4::new(VecReader(image)).is_err());
    }
}
