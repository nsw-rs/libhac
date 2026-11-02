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

use super::{Image, Shared, open_entry};
use crate::bytes::u64_le;
use crate::error::{Error, Result, fail};
use crate::partition::{Entry, PartitionFs};
use crate::storage::{ReadAt, check_range, read_array};
use crate::xci::XciRoot;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"NSZKEEP1";
const FOOTER_SIZE: u64 = 24;
const MAX_MAP: u64 = 16 << 20;
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

#[derive(Deserialize)]
struct KeepMap {
    #[serde(default, alias = "Version")]
    version: i64,
    #[serde(default, alias = "Size")]
    size: u64,
    #[serde(default, alias = "Segments")]
    segments: Vec<Vec<Value>>,
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

type Decoder = zstd::stream::read::Decoder<'static, io::BufReader<RangeReader>>;

/// A zstd stream decoder over `src[pos..pos + len]` with a bounded window.
fn decoder(src: &Shared, pos: u64, len: u64) -> Result<Decoder> {
    let r = RangeReader {
        src: Arc::clone(src),
        pos,
        end: pos + len,
    };
    let mut d = zstd::stream::read::Decoder::new(r)?;
    d.window_log_max(MAX_WINDOW_LOG)?;
    Ok(d)
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
    let m: KeepMap =
        serde_json::from_slice(&raw).map_err(|e| Error::InvalidData(format!("--keep map: {e}")))?;
    if m.version != 1 {
        return Ok(None);
    }

    // Gap segments are `[off, len]`; anything malformed fails below.
    let gap_lens = m.segments.iter().filter(|s| s.len() == 2);
    let Some(total) = gap_lens
        .map(|s| s.get(1).and_then(Value::as_u64).unwrap_or(0))
        .try_fold(0u64, u64::checked_add)
    else {
        fail!(InvalidData, "--keep gaps too large");
    };
    let files = container_files(&*src, xci)?;
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
    for (i, seg) in m.segments.iter().enumerate() {
        let off = seg.first().and_then(Value::as_u64);
        let n = seg.get(1).and_then(Value::as_u64);
        let (Some(off), Some(n)) = (off, n) else {
            fail!(InvalidData, "--keep segment {i}: bad offset or length");
        };
        if off != pos || n > m.size - pos {
            fail!(InvalidData, "--keep segment {i}: bad offset or length");
        }
        if seg.len() == 2 {
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
        }
        let part = seg.get(2).and_then(Value::as_str);
        let idx = seg.get(3).and_then(Value::as_u64);
        let ncz = match seg.get(4) {
            None => Some(false),
            Some(v) => (v.as_i64() == Some(1)).then_some(true),
        };
        let (Some(part), Some(idx), Some(ncz), true) = (part, idx, ncz, seg.len() <= 5) else {
            fail!(InvalidData, "--keep segment {i}: bad file reference");
        };
        let Some(e) = files.get(&(part.to_string(), idx)) else {
            fail!(
                InvalidData,
                "--keep segment {i}: no file {idx} in partition {part:?}"
            );
        };
        let r = open_entry(&src, e, ncz)?;
        let rs = r.size()?;
        if rs != n {
            fail!(
                InvalidData,
                "--keep segment {i}: {} is {rs} bytes, want {n}",
                e.name
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
        self.dec = Some(dec);
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
        for (i, e) in fs.entries.into_iter().enumerate() {
            files.insert((String::new(), i as u64), e);
        }
        return Ok(files);
    }
    let x = XciRoot::parse(src)?;
    for p in &x.root.entries {
        let fs = x.partition(src, p)?;
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
    use crate::ncz::tests::check_random_reads;
    use crate::partition::PartitionKind;
    use crate::xci::MEDIA_UNIT;

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
        let gap_stream = zstd::bulk::compress(&gaps, 3).unwrap();
        let map = zstd::bulk::compress(m.to_string().as_bytes(), 3).unwrap();
        let mut out = container.to_vec();
        out.extend_from_slice(&gap_stream);
        out.extend_from_slice(&map);
        out.extend_from_slice(&(gap_stream.len() as u64).to_le_bytes());
        out.extend_from_slice(&(map.len() as u64).to_le_bytes());
        out.extend_from_slice(MAGIC);
        out
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
