/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Reads Android `build.prop` properties from the on-device partitions and
//! builds the human-readable device information report shown after connect.
//!
//! Properties are read from the `system`, `vendor` and `product` partitions.
//! The filesystem is auto-detected per partition: ext4, EROFS (uncompressed),
//! or unrecognized. Compressed EROFS is detected but not supported since it
//! needs LZ4/LZMA decompression. Values from `system` are authoritative;
//! `vendor` and `product` only fill gaps.

use std::collections::HashMap;

use anyhow::Result;
use log::{info, warn};
use serde::{Deserialize, Serialize};

use penumbra::storage::{Partition, PartitionKind};
use penumbra::{Device, PortType};

use crate::ext4::{BlockReader, Ext4};
use crate::erofs::Erofs;

/// Partitions scanned for build.prop, in authoritive order.
const PROP_PARTITIONS: &[&str] = &["system", "vendor", "product"];

/// Largest build.prop we are willing to pull into memory.
const MAX_PROP_BYTES: u64 = 0x10_0000;

/// Detected on-disk filesystem type of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsKind {
    Ext4,
    Erofs { compressed: bool },
    Sparse,
    Unknown,
}

impl FsKind {
    fn label(self) -> &'static str {
        match self {
            FsKind::Ext4 => "ext4",
            FsKind::Erofs { compressed: false } => "erofs",
            FsKind::Erofs { compressed: true } => "erofs (compressed)",
            FsKind::Sparse => "sparse",
            FsKind::Unknown => "unknown",
        }
    }
}

const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EROFS_SUPER_MAGIC: u32 = 0xE0F5E1E2;
const SPARSE_HEADER_MAGIC: u32 = 0xED26FF3A;

/// Reads the first `n` bytes of a partition via a raw block reader and
/// classifies the filesystem by its superblock magic.
fn probe_fs(reader: &mut impl BlockReader) -> FsKind {
    // ext4/EROFS: superblock lives at offset 1024. Read 2048 to cover both.
    // Sparse: header magic at offset 0.
    let head = match reader.read(0, 2048) {
        Ok(h) if h.len() >= 2048 => h,
        _ => return FsKind::Unknown,
    };

    // Android sparse magic at offset 0.
    if head.len() >= 4 && u32::from_le_bytes(head[0..4].try_into().unwrap()) == SPARSE_HEADER_MAGIC {
        return FsKind::Sparse;
    }

    let sb = &head[1024..];

    if sb.len() >= 84 {
        let erofs_magic = u32::from_le_bytes(sb[0..4].try_into().unwrap());
        if erofs_magic == EROFS_SUPER_MAGIC {
            let feature_incompat = u32::from_le_bytes(sb[80..84].try_into().unwrap());
            // Compressed EROFS if COMPR_CFGS, BIG_PCLUSTER, or FRAGMENTS bits set.
            let compressed = feature_incompat & (0x02 | 0x04 | 0x10 | 0x20) != 0;
            return FsKind::Erofs { compressed };
        }
    }

    if sb.len() >= 58 {
        let ext4_magic = u16::from_le_bytes(sb[56..58].try_into().unwrap());
        if ext4_magic == EXT4_SUPER_MAGIC {
            return FsKind::Ext4;
        }
    }

    FsKind::Unknown
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeviceReport {
    pub chipset_type: String,
    pub security_patch: String,
    pub build_date: String,
    pub build_number: String,
    pub incremental: String,
    pub sdk_version: String,
    pub device_brand: String,
    pub android_ver: String,
}

impl DeviceReport {
    /// Emits the report to the log console as a boxed table.
    pub fn log(&self) {
        let row = |label: &str, value: &str| {
            info!("{label:<14}: {value}")
        };

        info!("╔══════════════════════════════════════════════╗");
        info!("║           DEVICE INFORMATION                 ║");
        info!("╠══════════════════════════════════════════════╣");
        row("Chipset Type", &self.chipset_type);
        row("Security Patch", &self.security_patch);
        row("Build Date", &self.build_date);
        row("Build Number", &self.build_number);
        row("Incremental", &self.incremental);
        row("SDK Version", &self.sdk_version);
        row("Device Brand", &self.device_brand);
        row("Android Ver", &self.android_ver);
        info!("╚══════════════════════════════════════════════╝");
    }
}

/// Bridges the ext4/erofs reader to on-device flash reads through the DA.
struct DeviceBlockReader<'reader, 'device> {
    device: &'reader mut Device<'device, PortType>,
    base: u64,
    kind: PartitionKind,
    size: u64,
}

impl<'reader, 'device> DeviceBlockReader<'reader, 'device> {
    fn new(device: &'reader mut Device<'device, PortType>, partition: &Partition) -> Self {
        Self { device, base: partition.address, kind: partition.kind, size: partition.size as u64 }
    }
}

impl<'reader, 'device> BlockReader for DeviceBlockReader<'reader, 'device> {
    fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if offset >= self.size {
            anyhow::bail!("read past end of partition");
        }

        let remaining = self.size - offset;
        let size = size.min(remaining as usize);

        let mut buffer = Vec::with_capacity(size);
        self.device
            .read_offset(self.base + offset, size, self.kind, &mut buffer, |_, _| {})?;

        Ok(buffer)
    }
}

pub struct DeviceReporter;

impl DeviceReporter {
    /// Collects build.prop from every readable partition and merges the values.
    /// `chipset` is reported as-is since it comes from the BROM handshake.
    pub fn run(device: &mut Device<'_, PortType>, chipset: &str) -> Result<DeviceReport> {
        let mut props_per_partition: Vec<HashMap<String, String>> = Vec::new();

        for name in PROP_PARTITIONS {
            let Some(partition) = device.get_partition(name) else {
                continue;
            };

            match Self::read_partition_props(device, &partition) {
                Ok(props) if !props.is_empty() => props_per_partition.push(props),
                Ok(_) => info!("[Report] {name} partition has no build.prop"),
                Err(e) => warn!("[Report] {name} build.prop unavailable: {e}"),
            }
        }

        let report = DeviceReport {
            chipset_type: chipset.to_string(),
            security_patch: Self::first(&props_per_partition, &[
                "ro.build.version.security_patch",
                "ro.vendor.build.security_patch",
            ]),
            build_date: Self::first(&props_per_partition, &["ro.build.date", "ro.vendor.build.date"]),
            build_number: Self::first(&props_per_partition, &["ro.build.display.id", "ro.build.id"]),
            incremental: Self::first(&props_per_partition, &[
                "ro.build.version.incremental",
                "ro.vendor.build.version.incremental",
            ]),
            sdk_version: Self::first(&props_per_partition, &[
                "ro.build.version.sdk",
                "ro.vendor.build.version.sdk",
            ]),
            device_brand: Self::first(&props_per_partition, &[
                "ro.product.brand",
                "ro.product.vendor.brand",
                "ro.product.manufacturer",
            ]),
            android_ver: Self::first(&props_per_partition, &[
                "ro.build.version.release",
                "ro.vendor.build.version.release",
            ]),
        };

        Ok(report)
    }

    /// Reads and parses build.prop from a single partition, auto-detecting
    /// the filesystem and dispatching to the right parser.
    fn read_partition_props(
        device: &mut Device<'_, PortType>,
        partition: &Partition,
    ) -> Result<HashMap<String, String>> {
        let mut reader = DeviceBlockReader::new(device, partition);
        let fs_kind = probe_fs(&mut reader);

        info!("[Report] {} filesystem: {}", partition.name, fs_kind.label());

        match fs_kind {
            FsKind::Ext4 => Self::read_ext4(reader, &partition.name),
            FsKind::Erofs { compressed: false } => Self::read_erofs(reader, &partition.name),
            FsKind::Erofs { compressed: true } => {
                warn!(
                    "[Report] {} is compressed EROFS; build.prop unavailable without a decompressor",
                    partition.name
                );
                Ok(HashMap::new())
            }
            FsKind::Sparse => {
                warn!(
                    "[Report] {} has an Android sparse header (unexpected from raw flash read)",
                    partition.name
                );
                Ok(HashMap::new())
            }
            FsKind::Unknown => {
                info!("[Report] {} filesystem not recognized; skipping", partition.name);
                Ok(HashMap::new())
            }
        }
    }

    fn read_ext4(
        reader: DeviceBlockReader<'_, '_>,
        partition_name: &str,
    ) -> Result<HashMap<String, String>> {
        let mut fs = Ext4::new(reader)?;

        let candidates: Vec<Vec<&str>> = if partition_name == "system" {
            vec![vec!["build.prop"], vec!["system", "build.prop"]]
        } else {
            vec![vec!["build.prop"], vec![partition_name, "build.prop"]]
        };

        let data = candidates
            .iter()
            .find_map(|path| fs.read_file(path).transpose())
            .transpose()?;

        Self::to_props(data)
    }

    fn read_erofs(
        reader: DeviceBlockReader<'_, '_>,
        partition_name: &str,
    ) -> Result<HashMap<String, String>> {
        let mut fs = Erofs::new(reader)?;

        let candidates: Vec<Vec<&str>> = if partition_name == "system" {
            vec![vec!["build.prop"], vec!["system", "build.prop"]]
        } else {
            vec![vec!["build.prop"], vec![partition_name, "build.prop"]]
        };

        let data = candidates
            .iter()
            .find_map(|path| fs.read_file(path).transpose())
            .transpose()?;

        Self::to_props(data)
    }

    fn to_props(data: Option<Vec<u8>>) -> Result<HashMap<String, String>> {
        let Some(data) = data else {
            return Ok(HashMap::new());
        };

        if data.len() as u64 > MAX_PROP_BYTES {
            anyhow::bail!("build.prop is unusually large ({} bytes)", data.len());
        }

        Ok(Self::parse_props(&data))
    }

    /// Parses `key=value` lines, skipping comments and malformed lines.
    fn parse_props(data: &[u8]) -> HashMap<String, String> {
        let text = String::from_utf8_lossy(data);
        let mut props = HashMap::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        props
    }

    /// Returns the first non-empty value for any of the candidate keys, scanning
    /// partitions in authoritive order. Falls back to "N/A".
    fn first(sources: &[HashMap<String, String>], keys: &[&str]) -> String {
        for source in sources {
            for key in keys {
                if let Some(value) = source.get(*key) {
                    if !value.is_empty() {
                        return value.to_string();
                    }
                }
            }
        }

        "N/A".to_string()
    }
}
