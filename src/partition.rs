// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Partition file systems (PFS0 and HFS0) parsed at any offset of a source,
//! keeping the raw header so it can be rewritten for a new layout.

use crate::bytes::{c_string, u32_le, u64_le};
use crate::error::{Result, fail};
use crate::storage::{ReadAt, read_array};

/// Largest header (plus the padding up to the first file) that is read
/// into memory.
pub(crate) const MAX_HEADER: u64 = 64 << 20;

/// A file in a PFS0 or an HFS0.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// File name.
    pub name: String,
    /// Absolute offset of the file data within the source.
    pub offset: u64,
    /// File size in bytes.
    pub size: u64,
}

/// The two partition file system flavors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartitionKind {
    /// `PFS0`, 0x18 byte entries (NSP, NCA sections).
    Pfs0,
    /// `HFS0`, 0x40 byte entries with a hashed region size and its SHA-256
    /// (XCI partitions).
    Hfs0,
}

impl PartitionKind {
    pub(crate) fn magic(self) -> &'static [u8; 4] {
        match self {
            PartitionKind::Pfs0 => b"PFS0",
            PartitionKind::Hfs0 => b"HFS0",
        }
    }

    pub(crate) fn entry_size(self) -> u64 {
        match self {
            PartitionKind::Pfs0 => 0x18,
            PartitionKind::Hfs0 => 0x40,
        }
    }

    fn name(self) -> &'static str {
        match self {
            PartitionKind::Pfs0 => "PFS0",
            PartitionKind::Hfs0 => "HFS0",
        }
    }
}

/// A parsed PFS0/HFS0.
#[derive(Clone, Debug)]
pub struct PartitionFs {
    pub(crate) kind: PartitionKind,
    /// Files in table order. Offsets are absolute in the source.
    pub(crate) entries: Vec<Entry>,
    /// Source bytes from the start of the header up to the lowest file
    /// offset, kept for the virtual image builder.
    #[cfg_attr(not(feature = "ncz"), allow(dead_code))]
    pub(crate) raw: Vec<u8>,
    /// File offsets in the table are relative to `base + header_size`.
    #[cfg_attr(not(feature = "ncz"), allow(dead_code))]
    pub(crate) header_size: u64,
}

impl PartitionFs {
    /// PFS0 or HFS0.
    pub fn kind(&self) -> PartitionKind {
        self.kind
    }

    /// Files in table order. Offsets are absolute in the source.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The first file named `name`.
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Parse the PFS0 that makes up all of `src` (an NSP or an NCA
    /// section), checking that every file lies inside it.
    pub fn parse_pfs0<R: ReadAt + ?Sized>(src: &R) -> Result<Self> {
        Self::parse(src, 0, src.size()?, PartitionKind::Pfs0)
    }

    /// Parse the file system at `base` of `src`. Every file must end at or
    /// before `limit` (an absolute offset in `src`, which may lie past its
    /// end). The header and the padding up to the lowest file offset may not
    /// exceed 64 MiB.
    pub fn parse<R: ReadAt + ?Sized>(
        src: &R,
        base: u64,
        limit: u64,
        kind: PartitionKind,
    ) -> Result<Self> {
        let k = kind.name();
        let head: [u8; 0x10] = read_array(src, base)?;
        if &head[..4] != kind.magic() {
            fail!(InvalidMagic, "missing {k} magic at {base:#x}");
        }
        let count = u32_le(&head, 4) as u64;
        let str_size = u32_le(&head, 8) as u64;
        // count and str_size are u32, so this cannot overflow.
        let header_size = 0x10 + count * kind.entry_size() + str_size;
        if header_size > MAX_HEADER {
            fail!(InvalidData, "{k} header too large");
        }
        let mut raw = vec![0u8; header_size as usize];
        src.read_at(base, &mut raw)?;
        let es = kind.entry_size() as usize;
        let str_base = 0x10 + count as usize * es;
        let Some(data_start) = base.checked_add(header_size) else {
            fail!(OutOfRange, "{k} header out of range");
        };
        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let e = &raw[0x10 + i * es..];
            let rel = u64_le(e, 0);
            let size = u64_le(e, 8);
            let name_off = u32_le(e, 16) as u64;
            if name_off >= str_size {
                fail!(InvalidData, "{k} entry {i}: bad name offset");
            }
            let name = c_string(&raw[str_base + name_off as usize..]);
            let Some(offset) = data_start
                .checked_add(rel)
                .filter(|&o| o.checked_add(size).is_some_and(|end| end <= limit))
            else {
                fail!(OutOfRange, "{k} entry {name:?} out of bounds");
            };
            entries.push(Entry { name, offset, size });
        }
        // The table need not be sorted by offset.
        if let Some(first) = entries.iter().map(|e| e.offset).min() {
            let first = first - base;
            if first > MAX_HEADER {
                fail!(InvalidData, "{k} first file too far");
            }
            if first > header_size {
                let at = raw.len();
                raw.resize(first as usize, 0);
                src.read_at(data_start, &mut raw[at..])?;
            }
        }
        Ok(PartitionFs {
            kind,
            entries,
            raw,
            header_size,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::fuzz;
    use sha2::{Digest, Sha256};

    /// Lay out a PFS0/HFS0 with `files` packed in order, each aligned to
    /// `align`, and the header padded to a multiple of 0x20. HFS0 entries
    /// hash their first `min(0x200, size)` bytes.
    pub fn build_fs(kind: PartitionKind, files: &[(&str, &[u8])], align: usize) -> Vec<u8> {
        let es = kind.entry_size() as usize;
        let mut strtab = Vec::new();
        for (name, _) in files {
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        let mut header_size = 0x10 + files.len() * es + strtab.len();
        let pad = (0x20 - header_size % 0x20) % 0x20;
        strtab.resize(strtab.len() + pad, 0);
        header_size += pad;

        let mut out = vec![0u8; header_size];
        out[..4].copy_from_slice(kind.magic());
        out[4..8].copy_from_slice(&(files.len() as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(strtab.len() as u32).to_le_bytes());
        let st = 0x10 + files.len() * es;
        out[st..st + strtab.len()].copy_from_slice(&strtab);
        let mut name_off = 0u32;
        for (i, (name, data)) in files.iter().enumerate() {
            if i > 0 {
                out.resize(out.len().div_ceil(align) * align, 0);
            }
            let rel = (out.len() - header_size) as u64;
            let e = &mut out[0x10 + i * es..0x10 + (i + 1) * es];
            e[0..8].copy_from_slice(&rel.to_le_bytes());
            e[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
            e[16..20].copy_from_slice(&name_off.to_le_bytes());
            if kind == PartitionKind::Hfs0 {
                let hs = data.len().min(0x200);
                e[20..24].copy_from_slice(&(hs as u32).to_le_bytes());
                e[0x20..0x40].copy_from_slice(&Sha256::digest(&data[..hs]));
            }
            name_off += name.len() as u32 + 1;
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn parse_both_kinds() {
        let files: &[(&str, &[u8])] = &[("a.nca", &[1; 5]), ("b.tik", &[2; 3])];
        for (kind, align) in [(PartitionKind::Pfs0, 1), (PartitionKind::Hfs0, 0x200)] {
            let img = build_fs(kind, files, align);
            let fs = PartitionFs::parse(&img, 0, img.len() as u64, kind).unwrap();
            assert_eq!(fs.entries.len(), 2);
            assert_eq!(fs.entries[1].name, "b.tik");
            let e = &fs.entries[1];
            assert_eq!(img.read_vec(e.offset, e.size as usize).unwrap(), [2; 3]);
            assert_eq!(fs.raw.len() as u64, fs.entries[0].offset);
            // A limit before the last file end is rejected.
            assert!(PartitionFs::parse(&img, 0, img.len() as u64 - 1, kind).is_err());
        }
    }

    /// `img` (built by [`build_fs`]) with the table entries `i` and `j`
    /// swapped, so the table is no longer sorted by offset.
    pub fn swap_entries(img: &mut [u8], kind: PartitionKind, i: usize, j: usize) {
        let es = kind.entry_size() as usize;
        let (a, b) = (0x10 + i * es, 0x10 + j * es);
        let tmp = img[a..a + es].to_vec();
        img.copy_within(b..b + es, a);
        img[b..b + es].copy_from_slice(&tmp);
    }

    #[test]
    fn unsorted_table() {
        let files: &[(&str, &[u8])] = &[("a.nca", &[1; 5]), ("b.tik", &[2; 3])];
        let mut img = build_fs(PartitionKind::Pfs0, files, 1);
        swap_entries(&mut img, PartitionKind::Pfs0, 0, 1);
        let fs = PartitionFs::parse(&img, 0, img.len() as u64, PartitionKind::Pfs0).unwrap();
        assert_eq!(fs.entries[0].name, "b.tik");
        assert_eq!(fs.raw.len() as u64, fs.entries[1].offset);
        for (e, (_, data)) in fs.entries.iter().zip(files.iter().rev()) {
            assert_eq!(img.read_vec(e.offset, e.size as usize).unwrap(), *data);
        }
    }

    #[test]
    fn rejects_bad_headers() {
        let mut img = build_fs(PartitionKind::Pfs0, &[("a", &[0; 4])], 1);
        assert!(PartitionFs::parse(&img, 0, img.len() as u64, PartitionKind::Hfs0).is_err());
        // Huge entry count and string table.
        img[4..12].copy_from_slice(&[0xff; 8]);
        assert!(PartitionFs::parse(&img, 0, u64::MAX, PartitionKind::Pfs0).is_err());
        // Offset that overflows.
        let mut img = build_fs(PartitionKind::Pfs0, &[("a", &[0; 4])], 1);
        img[0x10..0x18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(PartitionFs::parse(&img, 0, u64::MAX, PartitionKind::Pfs0).is_err());
    }

    #[test]
    fn fuzz_no_panic() {
        for kind in [PartitionKind::Pfs0, PartitionKind::Hfs0] {
            let img = build_fs(kind, &[("a.nca", &[1; 0x30]), ("b.tik", &[2; 0x10])], 0x20);
            fuzz(&img, 5, |b| {
                let _ = PartitionFs::parse(&b, 0, b.len() as u64, kind);
            });
        }
    }
}
