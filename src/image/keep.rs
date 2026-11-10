// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `NSZKEEP1` trailer: nsz `--keep` can append, after the container, what
//! is needed to restore the source NSP/XCI byte for byte:
//!
//! ```text
//! [zstd stream: gap bytes] [zstd frame: JSON map] [u64 gap size, u64 map size, "NSZKEEP1"]
//! ```
//!
//! The map segments tile the source in order: `[off, len]` takes the next
//! `len` gap bytes, `[off, len, partition, index]` is a container file
//! copied as is, with a trailing `1` when it is an NCZ to decompress.
//! The gap stream is decompressed on demand, as the image is read.

use super::{Image, Shared, check_disjoint, open_entry};
use crate::bytes::{quoted, u64_le};
use crate::error::{Error, Result, fail};
use crate::partition::{Entry, PartitionFs};
use crate::storage::{ReadAt, check_range, read_array};
use crate::xci::XciRoot;
use crate::zstd::ReadDecoder;
use serde::Deserialize;
use serde::de::{Deserializer, Error as _, IgnoredAny, SeqAccess, Visitor};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"NSZKEEP1";
const FOOTER_SIZE: u64 = 24;
/// Largest map, packed or not. The one of a card image with 200 files is
/// under 8 KiB.
const MAX_MAP: u64 = 1 << 20;
/// Bound on the gap bytes kept in memory. Uniform fill blocks do not count.
const MAX_LITERAL: u64 = 64 << 20;
const FILL_BLOCK: usize = 0x200;
/// Gap bytes decompressed per read of the zstd stream, a multiple of
/// [`FILL_BLOCK`].
const DECODE_CHUNK: usize = 64 << 10;
/// Bound on the runs indexing the decoded gap bytes.
const MAX_RUNS: usize = 1 << 20;
/// Largest zstd window accepted in the trailer streams (128 MiB).
const MAX_WINDOW_LOG: u32 = 27;

/// The version of a map. It is read on its own, since a map of another
/// version may have another shape.
#[derive(Deserialize)]
struct MapVersion {
    #[serde(default, alias = "Version")]
    version: i64,
}

#[derive(Deserialize)]
struct KeepMap {
    #[serde(default, alias = "Size")]
    size: u64,
    #[serde(default, alias = "Segments")]
    segments: Vec<MapSegment>,
}

/// A map segment: offset and length in the source, then nothing for gap
/// bytes, or the partition and the index of a container file, with a
/// trailing `1` when it is an NCZ to decompress.
struct MapSegment {
    off: u64,
    len: u64,
    /// Partition, index, and whether it is an NCZ.
    file: Option<(String, u64, bool)>,
}

impl<'de> Deserialize<'de> for MapSegment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Shape;

        impl<'de> Visitor<'de> for Shape {
            type Value = MapSegment;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[offset, length] or [offset, length, partition, index], or the latter with a 1")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> std::result::Result<MapSegment, A::Error> {
                let short = |n| A::Error::invalid_length(n, &self);
                let off = s.next_element()?.ok_or_else(|| short(0))?;
                let len = s.next_element()?.ok_or_else(|| short(1))?;
                let Some(part) = s.next_element::<String>()? else {
                    return Ok(MapSegment {
                        off,
                        len,
                        file: None,
                    });
                };
                let idx = s.next_element()?.ok_or_else(|| short(3))?;
                let ncz = match s.next_element::<u64>()? {
                    None => false,
                    Some(1) => true,
                    Some(_) => return Err(A::Error::custom("bad NCZ flag")),
                };
                if s.next_element::<IgnoredAny>()?.is_some() {
                    return Err(short(6));
                }
                Ok(MapSegment {
                    off,
                    len,
                    file: Some((part, idx, ncz)),
                })
            }
        }
        d.deserialize_seq(Shape)
    }
}

/// Sequential reader over a byte range of a source.
struct RangeReader {
    src: Shared,
    pos: u64,
    end: u64,
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf
            .len()
            .min((self.end - self.pos).try_into().unwrap_or(usize::MAX));
        match self.src.read_at(self.pos, &mut buf[..n]) {
            Ok(()) => {
                self.pos += n as u64;
                Ok(n)
            }
            Err(Error::Io(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

type Decoder = ReadDecoder<RangeReader>;

/// A zstd stream decoder over `src[pos..pos + len]` with a bounded window.
fn decoder(src: &Shared, pos: u64, len: u64) -> Result<Decoder> {
    let r = RangeReader {
        src: Arc::clone(src),
        pos,
        end: pos + len,
    };
    ReadDecoder::new(r, MAX_WINDOW_LOG)
}

/// Turn an error of a zstd stream into an [`Error`]. Corrupt or truncated
/// data is [`Error::InvalidData`], so only real I/O errors stay
/// [`Error::Io`].
fn stream_error(what: &str, e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::Other | io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            Error::InvalidData(format!("{what}: {e}"))
        }
        _ => Error::Io(e),
    }
}

/// The source image restored from the `--keep` trailer of the NSZ (or the
/// XCZ when `xci` is set) `src`. `None` when `src` has no trailer or its
/// version is unknown.
///
/// The footer, the map and the container files it references are checked
/// here, but the gap stream is only decompressed as the image is read, so
/// a corrupt or truncated gap stream fails those reads instead.
pub fn build_keep(src: Shared, xci: bool) -> Result<Option<Image>> {
    let size = src.size()?;
    if size < FOOTER_SIZE {
        return Ok(None);
    }
    let footer: [u8; FOOTER_SIZE as usize] = read_array(&*src, size - FOOTER_SIZE)?;
    if &footer[16..] != MAGIC {
        return Ok(None);
    }
    let gap_size = u64_le(&footer, 0);
    let map_size = u64_le(&footer, 8);
    let map_off = (size - FOOTER_SIZE).checked_sub(map_size);
    let Some((map_off, gap_off)) = map_off
        .filter(|_| map_size <= MAX_MAP)
        .and_then(|m| Some((m, m.checked_sub(gap_size)?)))
    else {
        fail!(InvalidData, "bad --keep trailer footer");
    };
    let mut raw = Vec::new();
    decoder(&src, map_off, map_size)?
        .take(MAX_MAP + 1)
        .read_to_end(&mut raw)
        .map_err(|e| stream_error("--keep map", e))?;
    if raw.len() as u64 > MAX_MAP {
        fail!(InvalidData, "--keep map: too large");
    }
    let bad_map = |e| Error::InvalidData(format!("--keep map: {e}"));
    let v: MapVersion = serde_json::from_slice(&raw).map_err(bad_map)?;
    if v.version != 1 {
        return Ok(None);
    }
    let m: KeepMap = serde_json::from_slice(&raw).map_err(bad_map)?;

    let mut gap_lens = m.segments.iter().filter(|s| s.file.is_none());
    let Some(total) = gap_lens.try_fold(0u64, |sum, s| sum.checked_add(s.len)) else {
        fail!(InvalidData, "--keep gaps too large");
    };
    let mut files = container_files(&*src, xci)?;
    let gaps = Arc::new(Gaps {
        src: Arc::clone(&src),
        off: gap_off,
        len: gap_size,
        total,
        state: Mutex::default(),
    });
    let mut img = Image::default();
    let mut gap_pos = 0u64;
    let mut pos = 0u64;
    for (i, MapSegment { off, len: n, file }) in m.segments.into_iter().enumerate() {
        if off != pos || n > m.size - pos {
            fail!(InvalidData, "--keep segment {i}: bad offset or length");
        }
        let Some((part, idx, ncz)) = file else {
            let g = GapSlice {
                gaps: Arc::clone(&gaps),
                start: gap_pos,
                len: n,
            };
            // Decompressed by the first read that reaches it.
            img.add(pos, Arc::new(g), n);
            gap_pos += n;
            pos += n;
            continue;
        };
        // Taken out of the map: a file is in the source once, and a map
        // that used it again would open it again each time.
        let key = (part, idx);
        let Some(e) = files.remove(&key) else {
            fail!(
                InvalidData,
                "--keep segment {i}: file {idx} of partition {} is missing or used twice",
                quoted(&key.0)
            );
        };
        let r = open_entry(&src, &e, ncz)?;
        let rs = r.size()?;
        if rs != n {
            fail!(
                InvalidData,
                "--keep segment {i}: {} is {rs} bytes, want {n}",
                quoted(&e.name)
            );
        }
        img.add(pos, r, n);
        pos += n;
    }
    if pos != m.size {
        fail!(InvalidData, "--keep segments do not cover the source");
    }
    Ok(Some(img))
}

/// Content of a run of gap bytes.
enum Run {
    /// Uniform blocks of one byte.
    Fill(u8),
    Literal(Vec<u8>),
}

/// The gap stream, decompressed on demand. A zstd stream can only be read
/// in order, so the bytes decoded so far are indexed as runs: a read never
/// decompresses past its end, and never decompresses anything twice.
struct Gaps {
    src: Shared,
    off: u64,
    len: u64,
    /// Gap bytes the map takes from the stream.
    total: u64,
    state: Mutex<GapState>,
}

#[derive(Default)]
struct GapState {
    dec: Option<Decoder>,
    /// Stream bytes decoded so far.
    decoded: u64,
    /// Stream position and content of each run. The runs are sorted and
    /// tile `0..decoded`.
    runs: Vec<(u64, Run)>,
    /// Literal bytes kept in `runs`.
    literal: u64,
    /// Why the stream is unusable, once a decode failed on corrupt data.
    /// Decoding again would only fail at the same place.
    failed: Option<String>,
}

impl GapState {
    fn push(&mut self, run: Run) -> Result<()> {
        if self.runs.len() >= MAX_RUNS {
            fail!(InvalidData, "too many gap runs");
        }
        self.runs.push((self.decoded, run));
        Ok(())
    }

    /// Decode in [`DECODE_CHUNK`] reads until `end` stream bytes are known,
    /// classifying each [`FILL_BLOCK`]: uniform blocks become fill runs, so
    /// long paddings cost no memory.
    fn decode_to(&mut self, g: &Gaps, end: u64) -> Result<()> {
        let mut dec = match self.dec.take() {
            Some(d) => d,
            None => decoder(&g.src, g.off, g.len)?,
        };
        let mut buf = vec![0u8; DECODE_CHUNK];
        while self.decoded < end {
            let chunk = &mut buf[..(g.total - self.decoded).min(DECODE_CHUNK as u64) as usize];
            dec.read_exact(chunk)
                .map_err(|e| stream_error("gap stream", e))?;
            for b in chunk.chunks(FILL_BLOCK) {
                self.add_block(b)?;
            }
        }
        // Past the last gap byte the decoder, with its window, is of no
        // more use.
        if self.decoded < g.total {
            self.dec = Some(dec);
        }
        Ok(())
    }

    /// Append the decoded block `b` to the runs.
    fn add_block(&mut self, b: &[u8]) -> Result<()> {
        let c = b[0];
        if b.iter().all(|&x| x == c) {
            if !matches!(self.runs.last(), Some((_, Run::Fill(f))) if *f == c) {
                self.push(Run::Fill(c))?;
            }
        } else {
            self.literal += b.len() as u64;
            if self.literal > MAX_LITERAL {
                fail!(InvalidData, "too many literal gap bytes");
            }
            match self.runs.last_mut() {
                Some((_, Run::Literal(v))) => v.extend_from_slice(b),
                _ => self.push(Run::Literal(b.to_vec()))?,
            }
        }
        self.decoded += b.len() as u64;
        Ok(())
    }
}

impl Gaps {
    /// Read stream bytes at `pos`. `pos + buf.len()` is at most `total`.
    fn read(&self, pos: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = pos + buf.len() as u64;
        let mut st = self.state.lock().unwrap_or_else(|p| {
            // A panic during a decode leaves the decoder and the index out
            // of step: start over.
            let mut st = p.into_inner();
            *st = GapState::default();
            self.state.clear_poison();
            st
        });
        if let Some(msg) = &st.failed {
            return Err(Error::InvalidData(msg.clone()));
        }
        if st.decoded < end
            && let Err(e) = st.decode_to(self, end)
        {
            if matches!(e, Error::Io(_)) {
                // Restart from the stream start on the next read, so a
                // transient I/O error does not stick.
                *st = GapState::default();
            } else {
                st.failed = Some(e.to_string());
            }
            return Err(e);
        }
        let mut i = st.runs.partition_point(|r| r.0 <= pos) - 1;
        let mut at = pos;
        let mut out = buf;
        while !out.is_empty() {
            let (start, run) = &st.runs[i];
            let next = st.runs.get(i + 1).map_or(st.decoded, |r| r.0);
            let n = (next - at).min(out.len() as u64) as usize;
            let (head, tail) = out.split_at_mut(n);
            match run {
                Run::Fill(c) => head.fill(*c),
                Run::Literal(v) => {
                    let o = (at - start) as usize;
                    head.copy_from_slice(&v[o..o + n]);
                }
            }
            out = tail;
            at += n as u64;
            i += 1;
        }
        Ok(())
    }
}

/// The `len` gap bytes at `start` of the stream.
struct GapSlice {
    gaps: Arc<Gaps>,
    start: u64,
    len: u64,
}

impl ReadAt for GapSlice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.gaps.read(self.start + offset, buf)
    }
    fn size(&self) -> Result<u64> {
        Ok(self.len)
    }
}

/// The files of an NSZ (partition `""`) or of each XCZ partition, by
/// partition name and position.
fn container_files(src: &dyn ReadAt, xci: bool) -> Result<HashMap<(String, u64), Entry>> {
    let mut files = HashMap::new();
    if !xci {
        let fs = PartitionFs::parse_pfs0(src)?;
        check_disjoint(&fs)?;
        for (i, e) in fs.entries.into_iter().enumerate() {
            files.insert((String::new(), i as u64), e);
        }
        return Ok(files);
    }
    let x = XciRoot::parse(src)?;
    check_disjoint(&x.root)?;
    for p in &x.root.entries {
        let fs = x.partition(src, p)?;
        check_disjoint(&fs)?;
        for (i, e) in fs.entries.into_iter().enumerate() {
            files.insert((p.name.clone(), i as u64), e);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fs, ncz_files, read_all};
    use super::super::{build, build_nsp, is_ncz};
    use super::*;
    use crate::ncz::tests::{check_random_reads, tiny_ncz};
    use crate::partition::PartitionKind;
    use crate::xci::MEDIA_UNIT;
    use serde_json::Value;

    /// Append to `container` a trailer that restores `orig`, with the files
    /// of `h` (parsed from `orig`) taken from the container.
    fn append_trailer(
        container: &[u8],
        orig: &[u8],
        h: &PartitionFs,
        compressed: &[(&str, Vec<u8>)],
        version: i64,
    ) -> Vec<u8> {
        let mut gaps = Vec::new();
        let mut segs: Vec<Value> = Vec::new();
        let mut pos = 0u64;
        let mut gap = |segs: &mut Vec<Value>, pos: &mut u64, end: u64| {
            if end > *pos {
                segs.push(serde_json::json!([*pos, end - *pos]));
                gaps.extend_from_slice(&orig[*pos as usize..end as usize]);
                *pos = end;
            }
        };
        for (i, e) in h.entries.iter().enumerate() {
            gap(&mut segs, &mut pos, e.offset);
            let mut seg = serde_json::json!([e.offset, e.size, "", i]);
            if is_ncz(compressed[i].0) {
                seg.as_array_mut().unwrap().push(1.into());
            }
            segs.push(seg);
            pos = e.offset + e.size;
        }
        gap(&mut segs, &mut pos, orig.len() as u64);
        let m = serde_json::json!({
            "version": version, "size": orig.len(), "sha256": "", "segments": segs,
        });
        with_map(container, &gaps, m.to_string().as_bytes())
    }

    /// `src` (with a trailer) with its gap stream changed by `f` and the
    /// footer fixed to match.
    fn edit_gaps(src: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let foot = src.len() - FOOTER_SIZE as usize;
        let gap_size = u64_le(src, foot) as usize;
        let map_size = u64_le(src, foot + 8) as usize;
        let map_off = foot - map_size;
        let gap_off = map_off - gap_size;
        let mut gaps = src[gap_off..map_off].to_vec();
        f(&mut gaps);
        let mut out = src[..gap_off].to_vec();
        out.extend_from_slice(&gaps);
        out.extend_from_slice(&src[map_off..foot]);
        out.extend_from_slice(&(gaps.len() as u64).to_le_bytes());
        out.extend_from_slice(&(map_size as u64).to_le_bytes());
        out.extend_from_slice(MAGIC);
        out
    }

    /// `data` that counts its reads.
    struct Counted {
        data: Vec<u8>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl ReadAt for Counted {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.data.read_at(offset, buf)
        }
        fn size(&self) -> Result<u64> {
            self.data.size()
        }
    }

    #[test]
    fn keep_lazy_gaps() {
        let (compressed, plain) = ncz_files();
        let nsz = fs(PartitionKind::Pfs0, &compressed, 1);
        let mut orig = fs(PartitionKind::Pfs0, &plain, MEDIA_UNIT as usize);
        orig.resize(orig.len() + 0x1123, 0xff);
        let h = PartitionFs::parse_pfs0(&orig).unwrap();
        let good = append_trailer(&nsz, &orig, &h, &compressed, 1);
        let file = &h.entries[1];
        let tail = orig.len() - 0x100;

        let garbage = edit_gaps(&good, |g| g.fill(0xab));
        let truncated = edit_gaps(&good, |g| g.truncate(g.len() - 4));
        for (name, src, at) in [("garbage", garbage, 0), ("truncated", truncated, tail)] {
            // The gap stream is not decompressed by the build.
            let src = Arc::new(Counted {
                data: src,
                reads: Default::default(),
            });
            let v = build_keep(src.clone(), false).unwrap().unwrap();
            let mut b = vec![0u8; file.size as usize];
            v.read_at(file.offset, &mut b).unwrap();
            assert!(b == orig[file.offset as usize..][..b.len()], "{name}");
            // A corrupt stream fails every read, but is decoded only once.
            let mut reads = 0;
            for i in 0..2 {
                let mut b = [0u8; 0x100];
                let r = v.read_at(at as u64, &mut b);
                assert!(matches!(r, Err(Error::InvalidData(_))), "{name}: {r:?}");
                let n = src.reads.load(std::sync::atomic::Ordering::Relaxed);
                if i == 1 {
                    assert_eq!(n, reads, "{name}: decoded again");
                }
                reads = n;
            }
        }
    }

    /// `container` with a trailer made of the gap bytes `gaps` and the map
    /// `map`.
    fn with_map(container: &[u8], gaps: &[u8], map: &[u8]) -> Vec<u8> {
        let gaps = crate::zstd::compress(gaps);
        let map = crate::zstd::compress(map);
        let mut src = container.to_vec();
        src.extend_from_slice(&gaps);
        src.extend_from_slice(&map);
        src.extend_from_slice(&(gaps.len() as u64).to_le_bytes());
        src.extend_from_slice(&(map.len() as u64).to_le_bytes());
        src.extend_from_slice(MAGIC);
        src
    }

    /// Only the shapes nsz writes are segments, and only a map of version
    /// 1 has to have them.
    #[test]
    fn map_shapes() {
        let (ncz, nca) = tiny_ncz(false);
        let nsz = fs(PartitionKind::Pfs0, &[("aaaa.ncz", ncz)], 1);
        let n = nca.len();
        let build = |map: Value| {
            let src = with_map(&nsz, &[9; 4], map.to_string().as_bytes());
            build_keep(Arc::new(src), false)
        };
        let segments =
            |segs: Value| serde_json::json!({"version": 1, "size": n + 4, "segments": segs});

        let v = build(segments(serde_json::json!([[0, n, "", 0, 1], [n, 4]])));
        let v = v.unwrap().unwrap();
        assert!(read_all(&v) == [&nca[..], &[9; 4]].concat());
        for bad in [
            serde_json::json!([[0, n, "", 0, 1], [n]]),
            serde_json::json!([[0, n, "", 0, 1], [n, 4, ""]]),
            serde_json::json!([[0, n, "", 0, 1], [n, 4, null, null]]),
            serde_json::json!([[0, n, "", 0, 2], [n, 4]]),
            serde_json::json!([[0, n, "", 0, 1, 1], [n, 4]]),
            serde_json::json!([[0, n, 0, 0, 1], [n, 4]]),
            serde_json::json!([[0, n, "", 0, 1], [n, -4]]),
            serde_json::json!([[0, n, "", 0, 1], [n, 4.0]]),
            serde_json::json!({"0": [0, n]}),
        ] {
            let r = build(segments(bad.clone()));
            assert!(matches!(r, Err(Error::InvalidData(_))), "{bad}");
        }
        // Another version may look like anything.
        let other = serde_json::json!({"version": 2, "size": "big", "segments": {"a": 1}});
        assert!(matches!(build(other), Ok(None)));
        assert!(build(serde_json::json!([1])).is_err());

        let pad = "x".repeat(MAX_MAP as usize);
        let big = serde_json::json!({"version": 1, "size": 0, "segments": [], "pad": pad});
        let r = build(big);
        assert!(matches!(&r, Err(Error::InvalidData(m)) if m.contains("too large")));
    }

    /// The decoder of the gap stream is dropped with its last byte.
    #[test]
    fn gap_decoder_is_dropped() {
        let data: Vec<u8> = (0..3 * DECODE_CHUNK).map(|i| (i / 3) as u8).collect();
        let packed = crate::zstd::compress(&data);
        let gaps = Gaps {
            len: packed.len() as u64,
            src: Arc::new(packed),
            off: 0,
            total: data.len() as u64,
            state: Mutex::default(),
        };
        let mut b = vec![0u8; 0x1000];
        gaps.read(0, &mut b).unwrap();
        assert!(b == data[..0x1000]);
        assert!(gaps.state.lock().unwrap().dec.is_some());
        gaps.read(gaps.total - 0x1000, &mut b).unwrap();
        assert!(b == data[data.len() - 0x1000..]);
        assert!(gaps.state.lock().unwrap().dec.is_none());
        // Everything is indexed now: reads need no decoder.
        gaps.read(0x800, &mut b).unwrap();
        assert!(b == data[0x800..0x1800]);
    }

    /// Random changes to the map or to the end of the trailer never panic.
    #[test]
    fn fuzz_no_panic() {
        let (ncz, nca) = tiny_ncz(false);
        let files = [("aaaa.ncz", ncz), ("bbbb.tik", vec![7; 0x40])];
        let plain = [("aaaa.nca", nca), ("bbbb.tik", vec![7; 0x40])];
        let nsz = fs(PartitionKind::Pfs0, &files, 1);
        let orig = fs(PartitionKind::Pfs0, &plain, MEDIA_UNIT as usize);
        let h = PartitionFs::parse_pfs0(&orig).unwrap();
        let good = append_trailer(&nsz, &orig, &h, &files, 1);
        let try_build = |src: Vec<u8>| {
            let Ok(Some(v)) = build_keep(Arc::new(src), false) else {
                return;
            };
            crate::testutil::probe_reads(&v);
        };

        let foot = good.len() - FOOTER_SIZE as usize;
        let map_off = foot - u64_le(&good, foot + 8) as usize;
        let gap_size = u64_le(&good, foot);
        let map = crate::zstd::decompress(&good[map_off..foot], MAX_MAP as usize).unwrap();
        let mut enc = crate::zstd::Encoder::new().unwrap();
        crate::testutil::fuzz(&map, 11, |m| {
            let m = enc.compress(m).unwrap();
            let mut src = good[..map_off].to_vec();
            src.extend_from_slice(&m);
            src.extend_from_slice(&gap_size.to_le_bytes());
            src.extend_from_slice(&(m.len() as u64).to_le_bytes());
            src.extend_from_slice(MAGIC);
            try_build(src);
        });
        // The gap stream, the packed map and the footer.
        let tail = good.len() - nsz.len();
        crate::testutil::fuzz(&good[nsz.len()..], 12, |t| {
            if t.len() == tail {
                try_build([&nsz, t].concat());
            }
        });
    }

    /// A map that names one container file in every segment would open it
    /// once per segment.
    #[test]
    fn file_used_twice() {
        let (compressed, plain) = ncz_files();
        let n = plain[0].1.len();
        let m = serde_json::json!({
            "version": 1, "size": 2 * n, "segments": [[0, n, "", 0], [n, n, "", 0]],
        });
        let container = fs(PartitionKind::Pfs0, &compressed, 1);
        let src = with_map(&container, &[], m.to_string().as_bytes());
        let r = build_keep(Arc::new(src), false);
        assert!(
            matches!(&r, Err(Error::InvalidData(m)) if m.contains("used twice")),
            "{:?}",
            r.err()
        );
    }

    #[test]
    fn keep_trailer() {
        let (compressed, plain) = ncz_files();
        let nsz = fs(PartitionKind::Pfs0, &compressed, 1);
        // The source has zero alignment gaps, a literal header and a 0xff
        // fill ending in a partial block.
        let mut orig = fs(PartitionKind::Pfs0, &plain, MEDIA_UNIT as usize);
        orig.resize(orig.len() + 0x1123, 0xff);
        let h = PartitionFs::parse_pfs0(&orig).unwrap();

        let src = append_trailer(&nsz, &orig, &h, &compressed, 1);
        let v = build_keep(Arc::new(src.clone()), false).unwrap().unwrap();
        assert!(read_all(&v) == orig, "restored image mismatch");
        check_random_reads(&v, &orig);

        // The trailer wins over the rebuild, but must not disturb it.
        assert!(read_all(&build(Arc::new(src.clone())).unwrap()) == orig);
        let rv = build_nsp(Arc::new(src)).unwrap();
        assert!(read_all(&rv) == fs(PartitionKind::Pfs0, &plain, 1));

        for (name, s) in [
            ("no trailer", nsz.clone()),
            (
                "unknown version",
                append_trailer(&nsz, &orig, &h, &compressed, 2),
            ),
        ] {
            assert!(matches!(build_keep(Arc::new(s), false), Ok(None)), "{name}");
        }
    }
}
