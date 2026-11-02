// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! XCI (game card image) header and partition table.

use crate::bytes::u64_le;
use crate::error::{Result, fail};
use crate::partition::{Entry, MAX_HEADER, PartitionFs, PartitionKind};
use crate::storage::{ReadAt, read_array};

/// Game card media unit: offsets in the header count these.
pub(crate) const MEDIA_UNIT: u64 = 0x200;

/// Size of the key area that precedes the header in a full dump.
pub(crate) const KEY_AREA_SIZE: u64 = 0x1000;

/// Size of the card header read by [`XciRoot::parse`].
pub(crate) const HEADER_SIZE: u64 = 0x200;

// Header field offsets, relative to the header start. Some are only
// patched by the virtual image builder.
pub(crate) const MAGIC: usize = 0x100;
#[cfg_attr(not(feature = "ncz"), allow(dead_code))]
pub(crate) const SECURE_OFFSET: usize = 0x104;
#[cfg_attr(not(feature = "ncz"), allow(dead_code))]
pub(crate) const VALID_DATA_END: usize = 0x118;
pub(crate) const ROOT_OFFSET: usize = 0x130;
pub(crate) const ROOT_HEADER_SIZE: usize = 0x138;
#[cfg_attr(not(feature = "ncz"), allow(dead_code))]
pub(crate) const ROOT_HEADER_HASH: usize = 0x140;
#[cfg_attr(not(feature = "ncz"), allow(dead_code))]
pub(crate) const NORMAL_AREA_END: usize = 0x18c;

/// The card header and the root HFS0 that lists the partitions (`update`,
/// `normal`, `secure`, `logo`).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct XciRoot {
    /// Offset of the card header: 0, or 0x1000 when the image starts with
    /// the key area.
    pub header_offset: u64,
    /// Absolute offset of the root HFS0.
    #[cfg_attr(not(feature = "ncz"), allow(dead_code))]
    pub(crate) root_offset: u64,
    /// Size of the hashed part of the root HFS0 header.
    #[cfg_attr(not(feature = "ncz"), allow(dead_code))]
    pub(crate) root_header_size: u64,
    /// The root HFS0. Its entries are the partitions, opened with
    /// [`XciRoot::partition`].
    pub root: PartitionFs,
}

impl XciRoot {
    /// Find the card header, with or without the key area in front, and
    /// parse the root HFS0. The last partition may end up to one media
    /// unit past the end of `src`, since some tools round its size up
    /// without writing the padding.
    pub fn parse<R: ReadAt + ?Sized>(src: &R) -> Result<Self> {
        let size = src.size()?;
        let mut hdr: [u8; HEADER_SIZE as usize] = read_array(src, 0)?;
        let mut header_offset = 0;
        if &hdr[MAGIC..MAGIC + 4] != b"HEAD" {
            header_offset = KEY_AREA_SIZE;
            hdr = read_array(src, header_offset)?;
            if &hdr[MAGIC..MAGIC + 4] != b"HEAD" {
                fail!(InvalidMagic, "missing XCI HEAD magic");
            }
        }
        let root_offset = header_offset.checked_add(u64_le(&hdr, ROOT_OFFSET));
        let root_header_size = u64_le(&hdr, ROOT_HEADER_SIZE);
        let Some(root_offset) = root_offset
            .filter(|&o| o >= header_offset + HEADER_SIZE && o <= MAX_HEADER)
            .filter(|_| root_header_size <= MAX_HEADER)
        else {
            fail!(InvalidData, "bad XCI HFS0 offset");
        };
        let limit = size.div_ceil(MEDIA_UNIT) * MEDIA_UNIT;
        let root = PartitionFs::parse(src, root_offset, limit, PartitionKind::Hfs0)?;
        Ok(XciRoot {
            header_offset,
            root_offset,
            root_header_size,
            root,
        })
    }

    /// Parse the HFS0 of partition `p` (an entry of [`XciRoot::root`]) in
    /// `src`, the image this root was parsed from.
    pub fn partition<R: ReadAt + ?Sized>(&self, src: &R, p: &Entry) -> Result<PartitionFs> {
        // The root parse checked that the partition end does not overflow.
        PartitionFs::parse(src, p.offset, p.offset + p.size, PartitionKind::Hfs0)
            .map_err(|e| e.prefixed(&format!("partition {}", p.name)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bytes::u32_le;
    use crate::partition::tests::build_fs;
    use sha2::{Digest, Sha256};

    /// Wrap `parts` in a root HFS0 behind a minimal card header.
    pub fn build_xci(parts: &[(&str, Vec<u8>)], key_area: bool) -> Vec<u8> {
        const ROOT: usize = 0x200;
        let files: Vec<(&str, &[u8])> = parts.iter().map(|(n, d)| (*n, d.as_slice())).collect();
        let root = build_fs(PartitionKind::Hfs0, &files, MEDIA_UNIT as usize);
        let root_hdr = u32_le(&root, 8) as usize + 0x10 + parts.len() * 0x40;
        let hdr_off = if key_area { KEY_AREA_SIZE as usize } else { 0 };
        let mut out: Vec<u8> = (0..hdr_off).map(|i| i as u8).collect();
        out.resize(hdr_off + ROOT, 0);
        let h = &mut out[hdr_off..];
        h[MAGIC..MAGIC + 4].copy_from_slice(b"HEAD");
        h[ROOT_OFFSET..ROOT_OFFSET + 8].copy_from_slice(&(ROOT as u64).to_le_bytes());
        h[ROOT_HEADER_SIZE..ROOT_HEADER_SIZE + 8].copy_from_slice(&(root_hdr as u64).to_le_bytes());
        h[ROOT_HEADER_HASH..ROOT_HEADER_HASH + 32]
            .copy_from_slice(&Sha256::digest(&root[..root_hdr]));
        let end = (ROOT + root.len()) as u64;
        let units = (end.div_ceil(MEDIA_UNIT) - 1) as u32;
        h[VALID_DATA_END..VALID_DATA_END + 4].copy_from_slice(&units.to_le_bytes());
        for (i, (name, _)) in parts.iter().enumerate() {
            if *name == "secure" {
                let rel = u64_le(&root, 0x10 + i * 0x40);
                let secure = ((ROOT + root_hdr) as u64 + rel) / MEDIA_UNIT;
                let secure = (secure as u32).to_le_bytes();
                h[SECURE_OFFSET..SECURE_OFFSET + 4].copy_from_slice(&secure);
                h[NORMAL_AREA_END..NORMAL_AREA_END + 4].copy_from_slice(&secure);
            }
        }
        out.extend_from_slice(&root);
        out
    }

    #[test]
    fn parse_with_and_without_key_area() {
        let secure = build_fs(PartitionKind::Hfs0, &[("x.nca", &[9; 0x300])], 0x200);
        let parts = [
            ("update", build_fs(PartitionKind::Hfs0, &[], 0x200)),
            ("secure", secure),
        ];
        for key_area in [false, true] {
            let img = build_xci(&parts, key_area);
            let x = XciRoot::parse(&img).unwrap();
            assert_eq!(x.header_offset, if key_area { 0x1000 } else { 0 });
            let names: Vec<_> = x.root.entries().iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["update", "secure"]);
            let s = x.partition(&img, &x.root.entries()[1]).unwrap();
            assert_eq!(s.entries()[0].name, "x.nca");
            assert_eq!(
                img.read_vec(s.entries()[0].offset, 0x300).unwrap(),
                [9; 0x300]
            );
        }
        assert!(XciRoot::parse(&vec![0u8; 0x1200]).is_err());
    }

    #[test]
    fn fuzz_no_panic() {
        let secure = build_fs(PartitionKind::Hfs0, &[("x.nca", &[9; 0x40])], 0x200);
        let img = build_xci(&[("secure", secure)], false);
        crate::testutil::fuzz(&img, 13, |b| {
            if let Ok(x) = XciRoot::parse(&b) {
                for p in x.root.entries() {
                    let _ = x.partition(&b, p);
                }
            }
        });
    }
}
