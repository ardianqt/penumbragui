/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Penumbra Contributors
*/

use anyhow::{Result, bail};
use log::info;

use penumbra::storage::{Partition, PartitionKind};
use penumbra::{Device, PortType};

use crate::ext4::BlockReader;

const LP_MAGIC: u32 = 0x414C5020;
const LP_NAME_LEN: usize = 36;

#[derive(Debug, Clone)]
pub struct LpExtent {
    pub start_block: u64,
    pub num_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct LpPartition {
    pub name: String,
    pub first_extent_index: u32,
    pub num_extents: u32,
}

pub struct SuperLp {
    pub partitions: Vec<LpPartition>,
    pub extents: Vec<LpExtent>,
    pub block_size: u32,
}

impl SuperLp {
    pub fn new(reader: &mut impl BlockReader) -> Result<Self> {
        let hdr = reader.read(0, 4096)?;

        let magic = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if magic != LP_MAGIC {
            bail!("not LP metadata (magic 0x{magic:08X})");
        }

        let header_size = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as u64;
        let pe_size = u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as usize;
        let pe_count = u32::from_le_bytes(hdr[20..24].try_into().unwrap()) as usize;
        let ext_size = u32::from_le_bytes(hdr[24..28].try_into().unwrap()) as usize;
        let ext_count = u32::from_le_bytes(hdr[28..32].try_into().unwrap()) as usize;
        let block_size = u32::from_le_bytes(hdr[32..36].try_into().unwrap());

        info!("[Report] LP: {pe_count} partitions, {ext_count} extents, block_size={block_size}");

        let mut partitions = Vec::with_capacity(pe_count);
        let mut off = header_size;
        for _ in 0..pe_count {
            let entry = reader.read(off, pe_size)?;
            let name = String::from_utf8_lossy(&entry[..LP_NAME_LEN])
                .trim_end_matches('\0')
                .to_string();
            let fei = u32::from_le_bytes(entry[LP_NAME_LEN..LP_NAME_LEN + 4].try_into().unwrap());
            let ne = u32::from_le_bytes(
                entry[LP_NAME_LEN + 4..LP_NAME_LEN + 8].try_into().unwrap(),
            );
            partitions.push(LpPartition { name, first_extent_index: fei, num_extents: ne });
            off += pe_size as u64;
        }

        let mut extents = Vec::with_capacity(ext_count);
        for _ in 0..ext_count {
            let e = reader.read(off, ext_size)?;
            let start = u64::from_le_bytes(e[0..8].try_into().unwrap());
            let num = u64::from_le_bytes(e[8..16].try_into().unwrap());
            extents.push(LpExtent { start_block: start, num_blocks: num });
            off += ext_size as u64;
        }

        Ok(Self { partitions, extents, block_size })
    }

    pub fn get_extents(&self, name: &str) -> Option<Vec<LpExtent>> {
        let p = self.partitions.iter().find(|p| p.name == name)?;
        let s = p.first_extent_index as usize;
        Some(self.extents[s..s + p.num_extents as usize].to_vec())
    }

    pub fn names(&self) -> Vec<&str> {
        self.partitions.iter().map(|p| p.name.as_str()).collect()
    }
}

pub struct LogicalReader<'a, 'b> {
    device: &'a mut Device<'b, PortType>,
    super_base: u64,
    kind: PartitionKind,
    extents: Vec<LpExtent>,
    block_size: u64,
    size: u64,
}

impl<'a, 'b> LogicalReader<'a, 'b> {
    pub fn new(
        device: &'a mut Device<'b, PortType>,
        super_part: &Partition,
        extents: Vec<LpExtent>,
        block_size: u32,
    ) -> Self {
        let bs = block_size as u64;
        let size = extents.iter().map(|e| e.num_blocks).sum::<u64>() * bs;
        Self { device, super_base: super_part.address, kind: super_part.kind, extents, block_size: bs, size }
    }
}

impl BlockReader for LogicalReader<'_, '_> {
    fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if offset >= self.size {
            bail!("read past end of logical partition");
        }
        let take = size.min((self.size - offset) as usize);

        let mut remaining = offset;
        let mut phys = self.super_base;
        for ext in &self.extents {
            let ext_bytes = ext.num_blocks * self.block_size;
            if remaining < ext_bytes {
                phys += ext.start_block * self.block_size + remaining;
                break;
            }
            remaining -= ext_bytes;
            phys += ext_bytes;
        }

        let mut buf = Vec::with_capacity(take);
        self.device.read_offset(phys, take, self.kind, &mut buf, |_, _| {})?;
        Ok(buf)
    }
}
