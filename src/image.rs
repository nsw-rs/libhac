// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Virtual NSP/XCI images of NSZ/XCZ containers.
//!
//! [`build`] picks the right builder for a container. [`build_nsp`] and
//! [`build_xci`] lay the container out again with every
//! `.ncz` replaced by the NCA it decompresses to (see [`crate::ncz`]),
//! patching offsets, sizes, names and HFS0 hashes. [`build_keep`] instead
//! restores the source image byte for byte from an `NSZKEEP1` trailer.
//! Nothing is decompressed until the image is read.

mod keep;

pub use keep::build_keep;

use crate::bytes::{c_str, quoted, u32_le};
use crate::error::{Result, fail};
use crate::ncz::{NCA_HEADER_SIZE, NczReader};
use crate::partition::{Entry, PartitionFs, PartitionKind};
use crate::storage::{ReadAt, SubStorage, read_array};
use crate::xci::{self, MEDIA_UNIT, XciRoot};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A shared random access source.
pub type Shared = Arc<dyn ReadAt + Send + Sync>;

struct Segment {
    offset: u64,
    len: u64,
    src: Shared,
}

/// A virtual file made of segments of other sources. Bytes not covered by
/// a segment read as zero.
#[derive(Default)]
pub struct Image {
    size: u64,
    /// Sorted by offset, not overlapping.
    segments: Vec<Segment>,
}

impl Image {
    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// True for a zero-length image.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Append `src[0..len]` at `offset`, which is not below the current
    /// size.
    fn add(&mut self, offset: u64, src: Shared, len: u64) {
        if len > 0 {
            self.segments.push(Segment { offset, len, src });
        }
        self.size = self.size.max(offset + len);
    }
}

impl ReadAt for Image {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        crate::storage::check_range(off, buf.len(), self.size)?;
        let end = off + buf.len() as u64;
        // End of the bytes filled so far.
        let mut pos = off;
        let first = self.segments.partition_point(|s| s.offset + s.len <= off);
        for s in self.segments[first..].iter().take_while(|s| s.offset < end) {
            let lo = off.max(s.offset);
            let hi = end.min(s.offset + s.len);
            buf[(pos - off) as usize..(lo - off) as usize].fill(0);
            s.src.read_at(
                lo - s.offset,
                &mut buf[(lo - off) as usize..(hi - off) as usize],
            )?;
            pos = hi;
        }
        buf[(pos - off) as usize..].fill(0);
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        Ok(self.len())
    }
}

/// The image the NSZ or XCZ `src` decompresses to: the source restored
/// byte for byte when it has an `NSZKEEP1` trailer (see [`build_keep`]),
/// else the layout rebuilt by [`build_nsp`] or [`build_xci`]. A PFS0 magic
/// at offset 0 means an NSZ, anything else is parsed as an XCZ.
pub fn build(src: Shared) -> Result<Image> {
    let xci = read_array::<4, _>(&*src, 0)? != *b"PFS0";
    if let Some(img) = build_keep(Arc::clone(&src), xci)? {
        return Ok(img);
    }
    if xci { build_xci(src) } else { build_nsp(src) }
}

/// Content of file `e` of `src`, decompressed when `ncz` is set.
fn open_entry(src: &Shared, e: &Entry, ncz: bool) -> Result<Shared> {
    let sub = SubStorage::new(Arc::clone(src), e.offset, e.size)?;
    if !ncz {
        return Ok(Arc::new(sub));
    }
    match NczReader::open(sub) {
        // Image reads jump around (FUSE readahead, concurrent readers), which
        // would decode a solid stream again from the start each time.
        Ok(r) if r.is_solid() => fail!(
            Unsupported,
            "{}: solid NCZ (not block compressed)",
            quoted(&e.name)
        ),
        Ok(r) => Ok(Arc::new(r)),
        Err(err) => Err(err.prefixed(&quoted(&e.name))),
    }
}

fn is_ncz(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".ncz")
}

/// File `e` of `src`, with `.ncz` files decompressed, and how many of its
/// first bytes are read without decompressing: the raw header of an NCZ,
/// all of any other file.
fn ncz_conv(src: &Shared, e: &Entry) -> Result<(Shared, u64)> {
    let ncz = is_ncz(&e.name);
    let cheap = if ncz { NCA_HEADER_SIZE } else { u64::MAX };
    Ok((open_entry(src, e, ncz)?, cheap))
}

/// Largest hashed region of an HFS0 entry or of the root HFS0. It is read
/// when the image is built. Real ones are the first 0x200 bytes of a file,
/// or the header of a partition, and for the logo partition its files too.
const MAX_HASHED: u64 = 1 << 20;

/// Fail when two files of `fs` share bytes. Each entry is opened on its
/// own, so a crafted table that lists one file many times would cost that
/// file's tables once per entry.
pub(super) fn check_disjoint(fs: &PartitionFs) -> Result<()> {
    // The parse checked that no file end overflows.
    let mut spans: Vec<_> = fs.entries.iter().filter(|e| e.size > 0).collect();
    spans.sort_unstable_by_key(|e| e.offset);
    for w in spans.windows(2) {
        if w[1].offset < w[0].offset + w[0].size {
            fail!(
                InvalidData,
                "{} and {} overlap",
                quoted(&w[0].name),
                quoted(&w[1].name)
            );
        }
    }
    Ok(())
}

/// Lay out `fs` with its files replaced by `conv`, packed in the original
/// table order from the lowest original file offset, each aligned to
/// `align`. With `rename_ncz`, `.ncz` names become `.nca`. `conv` also
/// returns how many first bytes of the file are cheap to read (see
/// [`ncz_conv`]): a hashed region, read here, must stay within them.
/// Returns the image, each file's new offset, and how many first bytes of
/// the image are cheap to read.
fn rebuild(
    mut fs: PartitionFs,
    align: u64,
    rename_ncz: bool,
    mut conv: impl FnMut(&Entry) -> Result<(Shared, u64)>,
) -> Result<(Image, Vec<u64>, u64)> {
    check_disjoint(&fs)?;
    let es = fs.kind.entry_size() as usize;
    let str_base = 0x10 + fs.entries.len() * es;
    let mut offsets = Vec::with_capacity(fs.entries.len());
    let mut contents = Vec::with_capacity(fs.entries.len());
    let mut pos = fs.raw.len() as u64;
    // The image is cheap to read up to `cheap`, and past it while `open`:
    // up to the first file that is not all cheap.
    let mut cheap = pos;
    let mut open = true;
    for (i, e) in fs.entries.iter().enumerate() {
        let (c, c_cheap) = conv(e)?;
        let size = c.size()?;
        if i > 0 {
            let Some(p) = pos.checked_next_multiple_of(align) else {
                fail!(InvalidData, "{} image too large", quoted(&e.name));
            };
            pos = p;
        }
        offsets.push(pos);
        let Some(next) = pos.checked_add(size) else {
            fail!(InvalidData, "{} image too large", quoted(&e.name));
        };
        if open {
            // Padding before the file reads as zero.
            cheap = pos + c_cheap.min(size);
            open = c_cheap >= size;
        }

        let ent = 0x10 + i * es;
        let raw = &mut fs.raw;
        raw[ent..ent + 8].copy_from_slice(&(pos - fs.header_size).to_le_bytes());
        raw[ent + 8..ent + 16].copy_from_slice(&size.to_le_bytes());
        if rename_ncz && is_ncz(&e.name) {
            // .ncz -> .nca keeps the name length, only the last byte
            // changes (z -> a, Z -> A). It is set, not shifted, since two
            // entries may share a name. The name ends with the string
            // table, as in the parse: `raw` can hold more than the header.
            let name = str_base + u32_le(raw, ent + 16) as usize;
            let last = name + c_str(&raw[name..fs.header_size as usize]).len() - 1;
            raw[last] = if e.name.ends_with('Z') { b'A' } else { b'a' };
        }
        if fs.kind == PartitionKind::Hfs0 {
            let hs = u32_le(raw, ent + 20) as u64;
            if hs > 0 {
                // The region is read here. Past the cheap part of the file
                // (the raw header of an NCZ) that would decompress it.
                if hs > MAX_HASHED || hs.min(size) > c_cheap {
                    fail!(
                        InvalidData,
                        "HFS0 entry {}: hashed region too large",
                        quoted(&e.name)
                    );
                }
                let mut buf = vec![0u8; hs.min(size) as usize];
                c.read_at(0, &mut buf)?;
                raw[ent + 0x20..ent + 0x40].copy_from_slice(&Sha256::digest(&buf));
            }
        }
        contents.push((c, size));
        pos = next;
    }
    let mut img = Image::default();
    let len = fs.raw.len() as u64;
    img.add(0, Arc::new(fs.raw), len);
    for (&at, (c, size)) in offsets.iter().zip(contents) {
        img.add(at, c, size);
    }
    Ok((img, offsets, cheap))
}

/// The NSP an NSZ decompresses to, as written by `nsz -D`.
pub fn build_nsp(src: Shared) -> Result<Image> {
    let fs = PartitionFs::parse_pfs0(&*src)?;
    Ok(rebuild(fs, 1, true, |e| ncz_conv(&src, e))?.0)
}

/// The XCI an XCZ decompresses to. Every NCA matches the original, but the
/// layout and the HFS0 headers are rebuilt.
pub fn build_xci(src: Shared) -> Result<Image> {
    let x = XciRoot::parse(&*src)?;
    let (hdr_off, root_off) = (x.header_offset, x.root_offset);
    let (rv, offsets, cheap) = rebuild(x.root.clone(), MEDIA_UNIT, false, |p| {
        let fs = x.partition(&*src, p)?;
        let (img, _, cheap) = rebuild(fs, MEDIA_UNIT, true, |e| ncz_conv(&src, e))?;
        Ok((Arc::new(img) as Shared, cheap))
    })?;
    // The hashed part of the root header is read below.
    if x.root_header_size > MAX_HASHED || x.root_header_size.min(rv.size) > cheap {
        fail!(InvalidData, "XCI root header: hashed region too large");
    }

    // The root offset is at most MAX_HEADER, checked by the parse.
    let mut head = src.read_vec(0, root_off as usize)?;
    let h = &mut head[hdr_off as usize..];
    let Some(end) = root_off.checked_add(rv.size) else {
        fail!(InvalidData, "XCI too large");
    };
    let mut root_hdr = vec![0u8; x.root_header_size as usize];
    let n = (root_hdr.len() as u64).min(rv.size) as usize;
    rv.read_at(0, &mut root_hdr[..n])?;
    h[xci::ROOT_HEADER_HASH..xci::ROOT_HEADER_HASH + 32]
        .copy_from_slice(&Sha256::digest(&root_hdr));

    let units = |n: u64| -> Result<[u8; 4]> {
        match u32::try_from(n) {
            Ok(u) => Ok(u.to_le_bytes()),
            Err(_) => fail!(InvalidData, "XCI too large"),
        }
    };
    let old_secure = u32_le(h, xci::SECURE_OFFSET);
    for (e, &off) in x.root.entries.iter().zip(&offsets) {
        if e.name != "secure" {
            continue;
        }
        let new_secure = units((root_off + off - hdr_off) / MEDIA_UNIT)?;
        h[xci::SECURE_OFFSET..xci::SECURE_OFFSET + 4].copy_from_slice(&new_secure);
        if u32_le(h, xci::NORMAL_AREA_END) == old_secure {
            h[xci::NORMAL_AREA_END..xci::NORMAL_AREA_END + 4].copy_from_slice(&new_secure);
        }
    }
    // nsz copies the header of the original XCI into the XCZ verbatim, so
    // the stored value does not describe the XCZ layout: derive it from the
    // image.
    let end = (end - hdr_off).div_ceil(MEDIA_UNIT) - 1;
    h[xci::VALID_DATA_END..xci::VALID_DATA_END + 4].copy_from_slice(&units(end)?);

    let mut img = Image::default();
    img.add(0, Arc::new(head), root_off);
    let size = rv.size;
    img.add(root_off, Arc::new(rv), size);
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::ncz::tests::{check_random_reads, solid_test_ncz, test_ncz, tiny_ncz};
    use crate::partition::tests::build_fs;
    use crate::xci::tests::build_xci as build_test_xci;

    pub(super) type Files = Vec<(&'static str, Vec<u8>)>;

    /// Matching file lists before (.ncz) and after (.nca) decompression.
    pub(super) fn ncz_files() -> (Files, Files) {
        let (ncz1, nca1) = test_ncz(10);
        let (ncz2, nca2) = test_ncz(11);
        let tik = vec![0x7a; 0x2c0];
        let small = tik[..0x123].to_vec();
        let compressed = vec![
            ("aaaa.cnmt.nca", small.clone()),
            ("bbbb.ncz", ncz1),
            ("cccc.tik", tik.clone()),
            ("dddd.NCZ", ncz2),
        ];
        let plain = vec![
            ("aaaa.cnmt.nca", small),
            ("bbbb.nca", nca1),
            ("cccc.tik", tik),
            ("dddd.NCA", nca2),
        ];
        (compressed, plain)
    }

    pub(super) fn fs(kind: PartitionKind, files: &[(&str, Vec<u8>)], align: usize) -> Vec<u8> {
        let f: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (*n, d.as_slice())).collect();
        build_fs(kind, &f, align)
    }

    pub(super) fn read_all(r: &impl ReadAt) -> Vec<u8> {
        let mut b = vec![0u8; r.size().unwrap() as usize];
        r.read_at(0, &mut b).unwrap();
        b
    }

    #[test]
    fn nsp() {
        let (compressed, plain) = ncz_files();
        let nsz = fs(PartitionKind::Pfs0, &compressed, 1);
        let want = fs(PartitionKind::Pfs0, &plain, 1);
        let v = build_nsp(Arc::new(nsz.clone())).unwrap();
        assert!(read_all(&v) == want, "virtual NSP mismatch");
        assert_eq!(v.len(), want.len() as u64);
        check_random_reads(&v, &want);
        assert!(read_all(&build(Arc::new(nsz)).unwrap()) == want);
    }

    fn xci_parts(files: &[(&'static str, Vec<u8>)]) -> Files {
        let m = MEDIA_UNIT as usize;
        vec![
            ("update", fs(PartitionKind::Hfs0, &[], m)),
            ("normal", fs(PartitionKind::Hfs0, &files[..1], m)),
            ("secure", fs(PartitionKind::Hfs0, files, m)),
        ]
    }

    #[test]
    fn xci() {
        let (compressed, plain) = ncz_files();
        for key_area in [false, true] {
            for orig_header in [false, true] {
                let mut xcz = build_test_xci(&xci_parts(&compressed), key_area);
                let want = build_test_xci(&xci_parts(&plain), key_area);
                if orig_header {
                    // nsz copies the original XCI header into the XCZ
                    // verbatim.
                    let h = if key_area { 0x1000 } else { 0 };
                    xcz[h..h + 0x200].copy_from_slice(&want[h..h + 0x200]);
                }
                let v = build_xci(Arc::new(xcz.clone())).unwrap();
                assert!(
                    read_all(&v) == want,
                    "key_area={key_area} orig_header={orig_header}: virtual XCI mismatch"
                );
                check_random_reads(&v, &want);
                assert!(read_all(&build(Arc::new(xcz)).unwrap()) == want);
            }
        }

        // nsz rounds the secure partition size up to a media unit without
        // writing the padding.
        let mut xcz = build_test_xci(&xci_parts(&compressed), false);
        let e = 0x200 + 0x10 + 2 * 0x40 + 8;
        let size = crate::bytes::u64_le(&xcz, e);
        let padded = (size / MEDIA_UNIT + 1) * MEDIA_UNIT;
        xcz[e..e + 8].copy_from_slice(&padded.to_le_bytes());
        let v = build_xci(Arc::new(xcz)).unwrap();
        assert!(read_all(&v) == build_test_xci(&xci_parts(&plain), false));
    }

    #[test]
    fn unsorted_nsp() {
        let (compressed, plain) = ncz_files();
        let mut nsz = fs(PartitionKind::Pfs0, &compressed, 1);
        crate::partition::tests::swap_entries(&mut nsz, PartitionKind::Pfs0, 0, 3);
        let v = read_all(&build_nsp(Arc::new(nsz)).unwrap());
        let out = PartitionFs::parse_pfs0(&v).unwrap();
        let mut want = plain.clone();
        want.swap(0, 3);
        for (e, (name, data)) in out.entries().iter().zip(&want) {
            assert_eq!(e.name, *name);
            assert!(v.read_vec(e.offset, e.size as usize).unwrap() == *data);
        }
    }

    /// Offset of field `field` of entry `i` in a file system at `base`.
    fn entry_field(kind: PartitionKind, base: usize, i: usize, field: usize) -> usize {
        base + 0x10 + i * kind.entry_size() as usize + field
    }

    /// Entries that share bytes are refused: each one is opened on its own.
    #[test]
    fn overlapping_entries() {
        let (compressed, _) = ncz_files();
        let overlap =
            |r: Result<Image>| matches!(r, Err(Error::InvalidData(m)) if m.contains("overlap"));

        // Entry 3 moved onto entry 1.
        let mut nsz = fs(PartitionKind::Pfs0, &compressed, 1);
        let (from, to) = (
            entry_field(PartitionKind::Pfs0, 0, 1, 0),
            entry_field(PartitionKind::Pfs0, 0, 3, 0),
        );
        nsz.copy_within(from..from + 16, to);
        assert!(overlap(build_nsp(Arc::new(nsz))));

        // Two root entries over one partition.
        let mut xcz = build_test_xci(&xci_parts(&compressed), false);
        let (from, to) = (
            entry_field(PartitionKind::Hfs0, 0x200, 2, 0),
            entry_field(PartitionKind::Hfs0, 0x200, 1, 0),
        );
        xcz.copy_within(from..from + 16, to);
        assert!(overlap(build_xci(Arc::new(xcz))));

        // Entries of no size share no bytes. As partitions they could be
        // listed any number of times, each with its header read and kept:
        // a partition must hold its own header.
        let mut xcz = build_test_xci(&xci_parts(&compressed), false);
        let size = entry_field(PartitionKind::Hfs0, 0x200, 0, 8);
        xcz[size..size + 8].fill(0);
        let r = build_xci(Arc::new(xcz));
        assert!(matches!(r, Err(Error::OutOfRange(_))), "{:?}", r.err());
    }

    /// The hashed region of an HFS0 entry is read at build time: it must be
    /// small, and inside the raw header of an NCZ.
    #[test]
    fn hashed_region_limits() {
        let (compressed, _) = ncz_files();
        let m = MEDIA_UNIT as usize;
        // Entry 1 is an NCZ, entry 2 a plain file.
        for (i, hashed) in [(1, NCA_HEADER_SIZE as u32 + 1), (2, MAX_HASHED as u32 + 1)] {
            let mut secure = fs(PartitionKind::Hfs0, &compressed, m);
            let at = entry_field(PartitionKind::Hfs0, 0, i, 20);
            secure[at..at + 4].copy_from_slice(&hashed.to_le_bytes());
            let xcz = build_test_xci(&[("secure", secure)], false);
            let r = build_xci(Arc::new(xcz));
            assert!(
                matches!(&r, Err(Error::InvalidData(m)) if m.contains("hashed region")),
                "entry {i}: {:?}",
                r.err()
            );
        }
        // A partition can be hashed past its header, as the logo one is,
        // but only over plain files: entry 1 (normal) holds one, entry 2
        // (secure) an NCZ after it.
        for (i, ok) in [(1, true), (2, false)] {
            let mut xcz = build_test_xci(&xci_parts(&compressed), false);
            let at = entry_field(PartitionKind::Hfs0, 0x200, i, 20);
            xcz[at..at + 4].copy_from_slice(&(MAX_HASHED as u32).to_le_bytes());
            let r = build_xci(Arc::new(xcz));
            if ok {
                assert!(r.is_ok(), "entry {i}: {:?}", r.err());
            } else {
                assert!(
                    matches!(&r, Err(Error::InvalidData(m)) if m.contains("hashed region")),
                    "entry {i}: {:?}",
                    r.err()
                );
            }
        }
        // A plain file after an NCZ is past the cheap part too.
        let secure = fs(PartitionKind::Hfs0, &compressed[..3], m);
        let mut xcz = build_test_xci(&[("secure", secure)], false);
        let at = entry_field(PartitionKind::Hfs0, 0x200, 0, 20);
        xcz[at..at + 4].copy_from_slice(&(MAX_HASHED as u32).to_le_bytes());
        let r = build_xci(Arc::new(xcz));
        assert!(
            matches!(&r, Err(Error::InvalidData(m)) if m.contains("hashed region")),
            "{:?}",
            r.err()
        );

        // So is the hashed part of the root header: it is capped, and
        // must not reach into an NCZ either.
        for hashed in [MAX_HASHED + 1, MAX_HASHED] {
            let mut xcz = build_test_xci(&xci_parts(&compressed), false);
            let at = xci::ROOT_HEADER_SIZE;
            xcz[at..at + 8].copy_from_slice(&hashed.to_le_bytes());
            let r = build_xci(Arc::new(xcz));
            assert!(
                matches!(&r, Err(Error::InvalidData(m)) if m.contains("hashed region")),
                "{hashed:#x}: {:?}",
                r.err()
            );
        }
    }

    /// `.ncz` becomes `.nca` in the string table, whatever the table looks
    /// like.
    #[test]
    fn ncz_renames() {
        let (ncz, nca) = tiny_ncz(false);
        // Two entries with one name.
        let files = [("aa.ncz", ncz.clone()), ("bb.ncz", ncz.clone())];
        let mut nsz = fs(PartitionKind::Pfs0, &files, 1);
        let at = entry_field(PartitionKind::Pfs0, 0, 1, 16);
        nsz[at..at + 4].fill(0);
        let v = read_all(&build_nsp(Arc::new(nsz)).unwrap());
        let out = PartitionFs::parse_pfs0(&v).unwrap();
        assert_eq!(out.entries()[0].name, "aa.nca");
        assert_eq!(out.entries()[1].name, "aa.nca");

        // A last name that ends with the string table, and bytes that are
        // not zero between the header and the file.
        let mut nsz = b"PFS0".to_vec();
        for v in [1u32, 5, 0] {
            nsz.extend(v.to_le_bytes());
        }
        nsz.extend(16u64.to_le_bytes());
        nsz.extend((ncz.len() as u64).to_le_bytes());
        nsz.extend([0; 8]);
        nsz.extend(b"A.NCZ");
        nsz.extend([b'Q'; 16]);
        let head = nsz.len();
        nsz.extend(&ncz);
        let v = read_all(&build_nsp(Arc::new(nsz.clone())).unwrap());
        assert_eq!(v[0x28..head], *b"A.NCAQQQQQQQQQQQQQQQQ");
        assert!(v[head..] == nca);
    }

    /// Random changes to a container never panic, in the build or in the
    /// reads that follow.
    #[test]
    fn fuzz_no_panic() {
        let hs = NCA_HEADER_SIZE as usize;
        let (ncz, _) = tiny_ncz(false);
        let files = [("aaaa.ncz", ncz.clone()), ("bbbb.tik", vec![7; 0x40])];
        let nsz = fs(PartitionKind::Pfs0, &files, 1);
        let secure = fs(PartitionKind::Hfs0, &files, MEDIA_UNIT as usize);
        let xcz = build_test_xci(&[("secure", secure)], false);
        for (seed, img) in [(7, nsz), (8, xcz)] {
            // The raw NCA header is not parsed: leave it out of the sample.
            let at = img.windows(64).position(|w| w == &ncz[..64]).unwrap();
            let sample = [&img[..at], &img[at + hs..]].concat();
            crate::testutil::fuzz(&sample, seed, |b| {
                let src = match b.split_at_checked(at) {
                    Some((head, tail)) => [head, &ncz[..hs], tail].concat(),
                    None => b.to_vec(),
                };
                let Ok(v) = build(Arc::new(src)) else {
                    return;
                };
                crate::testutil::probe_reads(&v);
            });
        }
    }

    #[test]
    fn solid_container() {
        let nsz = fs(PartitionKind::Pfs0, &[("eeee.ncz", solid_test_ncz().0)], 1);
        assert!(matches!(
            build_nsp(Arc::new(nsz)),
            Err(Error::Unsupported(_))
        ));
    }
}
