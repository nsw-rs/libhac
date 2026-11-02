// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standard-type PFS0 builder. PFS0s are read with
//! [`crate::partition::PartitionFs::parse_pfs0`].

/// String table size of the header written by [`Pfs0Builder`] (port of
/// `CustomPartitionFileSystemBuilder.CalcStringTableSize`, Standard type).
fn string_table_size(names: &[&str]) -> u32 {
    let start = 0x10 + names.len() * 0x18;
    let size: usize = names.iter().map(|n| n.len() + 1).sum();
    let mut end = (start + size).div_ceil(0x20) * 0x20;
    // When already aligned, add an extra 0x20 block like Nintendo does.
    if end == start + size {
        end += 0x20;
    }
    (end - start) as u32
}

/// Writer of Standard-type PFS0 metadata for files laid out back to back
/// in the order they are added. The file data follows the header.
#[derive(Clone, Debug, Default)]
pub struct Pfs0Builder {
    files: Vec<(String, u64)>,
}

impl Pfs0Builder {
    /// A builder with no files.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a file of `size` bytes.
    pub fn add_file(&mut self, name: impl Into<String>, size: u64) -> &mut Self {
        self.files.push((name.into(), size));
        self
    }

    /// The header and file table, padded like Nintendo's Standard NSPs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let files = &self.files;
        let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
        let st_size = string_table_size(&names);
        let mut out = Vec::new();
        out.extend_from_slice(b"PFS0");
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        out.extend_from_slice(&st_size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let mut offset = 0u64;
        let mut name_off = 0u32;
        for (name, size) in files {
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&name_off.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            offset += size;
            name_off += name.len() as u32 + 1;
        }
        let table_start = out.len();
        for (name, _) in files {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        out.resize(table_start + st_size as usize, 0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::PartitionFs;
    use crate::storage::ReadAt;

    #[test]
    fn padding_rule() {
        // 0x10 + 0x18 = 0x28 start; "a.nca\0" = 6 bytes -> end 0x2E, aligned 0x40.
        assert_eq!(string_table_size(&["a.nca"]), 0x18);
        // start 0x28, 0x18 bytes of names -> end 0x40 already aligned -> +0x20.
        let name = "x".repeat(0x17);
        assert_eq!(string_table_size(&[&name]), 0x38);
    }

    #[test]
    fn round_trip() {
        let mut out = Pfs0Builder::new()
            .add_file("one.nca", 3)
            .add_file("two.tik", 10)
            .to_bytes();
        out.extend_from_slice(&[1, 2, 3]);
        out.extend_from_slice(&[4; 10]);
        let mem = out;
        let pfs = PartitionFs::parse_pfs0(&mem).unwrap();
        assert_eq!(pfs.entries().len(), 2);
        assert_eq!(pfs.entries()[1].name, "two.tik");
        let e = pfs.entries();
        assert_eq!(
            mem.read_vec(e[0].offset, e[0].size as usize).unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            mem.read_vec(e[1].offset, e[1].size as usize).unwrap(),
            vec![4; 10]
        );
        assert_eq!(e[0].offset % 0x20, 0);
    }
}
