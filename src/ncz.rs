// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NCZ: an NCA with its sections decrypted and zstd compressed, as written
//! by nsz. [`NczReader`] serves the original NCA, decompressed and
//! re-encrypted on the fly.
//!
//! Layout: the first 0x4000 bytes of the NCA as they are, then `NCZSECTN`
//! with the section table (offset, size, crypto type, key, counter), then
//! the rest of the NCA from 0x4000 on, compressed one of two ways:
//!
//! - block: `NCZBLOCK` with the block size and the compressed length of each
//!   block, then the blocks, compressed independently. A block whose length
//!   is not smaller than its decompressed size is stored raw. Reads are
//!   random access.
//! - solid: one zstd stream. It has no random access: reads that move
//!   forward continue the stream, a read before the current position
//!   decodes it again from the start. Read it sequentially.

use crate::bytes::{array_at, u32_le, u64_le};
use crate::crypto::CtrKey;
use crate::error::{Error, Result, fail};
use crate::storage::{ReadAt, check_range};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The part of the NCA that NCZ stores uncompressed.
pub(crate) const NCA_HEADER_SIZE: u64 = 0x4000;

/// Number of decompressed blocks kept by the cache shared by all readers.
const CACHE_BLOCKS: usize = 16;

/// Bytes of decompressed blocks kept by that cache. Blocks can be up to
/// 4 GiB, so the count alone does not bound memory. The most recent block
/// is always kept.
const CACHE_BYTES: usize = 64 << 20;

/// A decompressed block.
type Block = Arc<Vec<u8>>;

struct Section {
    offset: u64,
    size: u64,
    /// `None` for plaintext.
    ctr: Option<CtrKey>,
}

/// An NCZ read as the NCA it was made from.
pub struct NczReader<S> {
    src: S,
    size: u64,
    sections: Vec<Section>,
    body: Body,
}

/// How the NCA past the raw header is compressed.
enum Body {
    Block(Blocks),
    Solid(Mutex<Solid>),
}

/// Block table of a block NCZ.
struct Blocks {
    /// Cache key of this reader.
    id: u64,
    block_size: u64,
    decompressed_size: u64,
    /// Offset in `src` and compressed length of each block.
    blocks: Vec<(u64, u32)>,
}

/// Compressed bytes read from `src` per refill of a solid stream.
const SOLID_INPUT: usize = 0x20000;

fn zstd_err(e: std::io::Error) -> Error {
    Error::InvalidData(format!("NCZ zstd: {e}"))
}

/// Decoding state of a solid stream.
struct Solid {
    dec: zstd::stream::raw::Decoder<'static>,
    /// Offsets in `src` of the stream start and end.
    start: u64,
    end: u64,
    /// Offset in `src` of the next compressed bytes to read.
    next_in: u64,
    /// Compressed bytes read but not consumed yet: `input[used..filled]`.
    input: Box<[u8]>,
    used: usize,
    filled: usize,
    /// Decompressed bytes produced so far.
    pos: u64,
}

impl Solid {
    fn new(start: u64, end: u64) -> Result<Self> {
        Ok(Solid {
            dec: zstd::stream::raw::Decoder::new().map_err(zstd_err)?,
            start,
            end,
            next_in: start,
            input: vec![0; SOLID_INPUT].into_boxed_slice(),
            used: 0,
            filled: 0,
            pos: 0,
        })
    }

    /// Go back to the start of the stream.
    fn rewind(&mut self) -> Result<()> {
        use zstd::stream::raw::Operation;
        self.next_in = self.start;
        self.used = 0;
        self.filled = 0;
        self.pos = 0;
        self.dec.reinit().map_err(zstd_err)
    }

    /// Fill `out` with the stream from decompressed offset `pos`. A `pos`
    /// behind the current position decodes again from the start; bytes
    /// skipped to reach `pos` are decoded into `out` and overwritten.
    fn read_at(&mut self, src: &impl ReadAt, pos: u64, out: &mut [u8]) -> Result<()> {
        let mut res = Ok(());
        if pos < self.pos {
            res = self.rewind();
        }
        while res.is_ok() && self.pos < pos && !out.is_empty() {
            let n = (pos - self.pos).min(out.len() as u64) as usize;
            res = self.fill(src, &mut out[..n]);
        }
        if res.is_ok() {
            res = self.fill(src, out);
        }
        if let Err(e) = res {
            // The decoder state is unusable after an error.
            self.rewind()?;
            return Err(e);
        }
        Ok(())
    }

    /// Fill `out` with the next decompressed bytes of the stream.
    fn fill(&mut self, src: &impl ReadAt, out: &mut [u8]) -> Result<()> {
        use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
        let mut done = 0;
        while done < out.len() {
            if self.used == self.filled {
                let n = (self.end - self.next_in).min(SOLID_INPUT as u64) as usize;
                if n == 0 {
                    fail!(InvalidData, "NCZ zstd stream ends early");
                }
                src.read_at(self.next_in, &mut self.input[..n])?;
                self.next_in += n as u64;
                self.used = 0;
                self.filled = n;
            }
            let mut inb = InBuffer::around(&self.input[self.used..self.filled]);
            let mut outb = OutBuffer::around(&mut out[done..]);
            self.dec.run(&mut inb, &mut outb).map_err(zstd_err)?;
            let (consumed, produced) = (inb.pos(), outb.pos());
            if consumed == 0 && produced == 0 {
                fail!(InvalidData, "NCZ zstd stream stalled");
            }
            self.used += consumed;
            done += produced;
            self.pos += produced as u64;
        }
        Ok(())
    }
}

impl<S: ReadAt> NczReader<S> {
    /// Open the NCZ that makes up all of `src`.
    pub fn open(src: S) -> Result<Self> {
        let src_size = src.size()?;
        let read =
            |pos: u64, len: usize| src.read_vec(pos, len).map_err(|e| e.prefixed("NCZ header"));
        let hdr = read(NCA_HEADER_SIZE, 16)?;
        if &hdr[..8] != b"NCZSECTN" {
            fail!(InvalidMagic, "missing NCZSECTN");
        }
        let count = u64_le(&hdr, 8);
        if count == 0 || count > 0x10000 {
            fail!(InvalidData, "bad NCZ section count {count}");
        }
        let mut pos = NCA_HEADER_SIZE + 16;
        let raw = read(pos, count as usize * 0x40)?;
        pos += raw.len() as u64;

        let mut sections = Vec::with_capacity(count as usize + 1);
        for e in raw.as_chunks::<0x40>().0 {
            let ct = u64_le(e, 16);
            let ctr = match ct {
                3 | 4 => Some(CtrKey::new(&array_at(e, 0x20)?, array_at(e, 0x30)?)),
                _ => None,
            };
            sections.push(Section {
                offset: u64_le(e, 0),
                size: u64_le(e, 8),
                ctr,
            });
        }
        let first = sections[0].offset;
        if first > NCA_HEADER_SIZE {
            let gap = Section {
                offset: NCA_HEADER_SIZE,
                size: first - NCA_HEADER_SIZE,
                ctr: None,
            };
            sections.insert(0, gap);
        }
        // The first section of a small NCA may start inside the raw header,
        // so the NCA ends at the last section end, not at header + sum of
        // sizes.
        let mut size = NCA_HEADER_SIZE;
        for s in &sections {
            let Some(end) = s.offset.checked_add(s.size) else {
                fail!(InvalidData, "NCZ sections too large");
            };
            size = size.max(end);
        }

        // A solid stream starts with the zstd frame magic, so it is never
        // mistaken for NCZBLOCK.
        if src_size.saturating_sub(pos) < 8 || read(pos, 8)? != b"NCZBLOCK" {
            let solid = Solid::new(pos, src_size)?;
            return Ok(NczReader {
                src,
                size,
                sections,
                body: Body::Solid(Mutex::new(solid)),
            });
        }
        let bh = read(pos, 24)?;
        let exp = bh[11];
        // nsz allows blocks of up to 2^32 bytes (default 2^20), so decoding
        // one valid block of a legal file can need that much memory.
        if !(14..=32).contains(&exp) {
            fail!(InvalidData, "bad NCZBLOCK block size exponent {exp}");
        }
        let block_size = 1u64 << exp;
        let n = u32_le(&bh, 12) as u64;
        let decompressed_size = u64_le(&bh, 16);
        if n != decompressed_size.div_ceil(block_size) {
            fail!(
                InvalidData,
                "NCZBLOCK: {n} blocks for {decompressed_size} bytes"
            );
        }
        pos += 24;
        if 4 * n > src_size.saturating_sub(pos) {
            fail!(OutOfRange, "NCZ block table exceeds file size");
        }
        let lens = read(pos, 4 * n as usize)?;
        pos += lens.len() as u64;
        let mut blocks = Vec::with_capacity(n as usize);
        for l in lens.as_chunks::<4>().0 {
            let len = u32_le(l, 0);
            blocks.push((pos, len));
            let Some(next) = pos.checked_add(len as u64) else {
                fail!(OutOfRange, "NCZ blocks exceed file size");
            };
            pos = next;
        }
        if pos > src_size {
            fail!(OutOfRange, "NCZ blocks exceed file size");
        }
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Ok(NczReader {
            src,
            size,
            sections,
            body: Body::Block(Blocks {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                block_size,
                decompressed_size,
                blocks,
            }),
        })
    }

    /// True for a solid NCZ, which only reads fast sequentially.
    pub fn is_solid(&self) -> bool {
        matches!(self.body, Body::Solid(_))
    }

    /// Apply AES-CTR to the parts of `buf` (at NCA offset `off`) that fall
    /// in encrypted sections past the raw header.
    fn crypt(&self, buf: &mut [u8], off: u64) {
        let end = off + buf.len() as u64;
        for s in &self.sections {
            let Some(key) = &s.ctr else {
                continue;
            };
            let lo = off.max(s.offset).max(NCA_HEADER_SIZE);
            let hi = end.min(s.offset + s.size);
            if lo < hi {
                key.apply(lo, &mut buf[(lo - off) as usize..(hi - off) as usize]);
            }
        }
    }
}

impl Blocks {
    /// Fill `out` with the decompressed stream from offset `pos`, zeros
    /// past its end.
    fn read(&self, src: &impl ReadAt, pos: u64, out: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < out.len() {
            let pos = pos + done as u64;
            let id = pos / self.block_size;
            let inner = (pos % self.block_size) as usize;
            let data = match usize::try_from(id) {
                Ok(id) if id < self.blocks.len() => self.block(src, id)?,
                _ => Block::default(),
            };
            if inner >= data.len() {
                // Past the decompressed stream: nothing left to copy.
                out[done..].fill(0);
                break;
            }
            let n = (out.len() - done).min(data.len() - inner);
            out[done..done + n].copy_from_slice(&data[inner..inner + n]);
            done += n;
        }
        Ok(())
    }

    /// Block `id` decompressed, from the cache when possible.
    fn block(&self, src: &impl ReadAt, id: usize) -> Result<Block> {
        let key = (self.id, id);
        let cell = {
            let mut c = cache();
            if let Some(data) = c.get(key) {
                return Ok(data);
            }
            // Concurrent reads of one block (e.g. kernel readahead) wait
            // for a single decode instead of each decoding it.
            if let Some((_, p)) = c.pending.iter().find(|(k, _)| *k == key) {
                let p = Arc::clone(p);
                drop(c);
                if let Some(data) = p.wait() {
                    return Ok(Arc::clone(data));
                }
                // The decode failed: try again to get the error.
                return self.decode(src, id).map(Arc::new);
            }
            let p = Arc::new(OnceLock::new());
            c.pending.push((key, Arc::clone(&p)));
            PendingGuard { key, cell: p }
        };
        let res = self.decode(src, id).map(Arc::new);
        let mut c = cache();
        c.pending.retain(|(k, _)| *k != key);
        if let Ok(data) = &res {
            c.put(key, Arc::clone(data));
        }
        drop(c);
        let _ = cell.cell.set(res.as_ref().ok().cloned());
        res
    }

    /// Read and decompress block `id`.
    fn decode(&self, src: &impl ReadAt, id: usize) -> Result<Vec<u8>> {
        let mut size = self.block_size;
        if id == self.blocks.len() - 1 {
            let rem = self.decompressed_size % self.block_size;
            if rem > 0 {
                size = rem;
            }
        }
        let (pos, clen) = self.blocks[id];
        // A raw or compressed block is at most the file's own bytes, so it is
        // zeroed and read in place. A decompressed block can be far larger
        // than its compressed bytes: it is only reserved, and zstd writes it
        // into the spare capacity, so a corrupt block that stops early never
        // touches the rest.
        let reserve = |n: u64| -> Result<Vec<u8>> {
            let mut v = Vec::new();
            if v.try_reserve_exact(n as usize).is_err() {
                fail!(InvalidData, "NCZ block {id}: cannot allocate {n} bytes");
            }
            Ok(v)
        };
        let alloc = |n: u64| -> Result<Vec<u8>> {
            let mut v = reserve(n)?;
            v.resize(n as usize, 0);
            Ok(v)
        };
        if (clen as u64) >= size {
            let mut data = alloc(size)?;
            src.read_at(pos, &mut data)?;
            return Ok(data);
        }
        let mut comp = alloc(clen as u64)?;
        src.read_at(pos, &mut comp)?;
        let mut data = reserve(size)?;
        let n = zstd::bulk::Decompressor::new()
            .and_then(|mut d| d.decompress_to_buffer(&comp, &mut data))
            .map_err(|e| Error::InvalidData(format!("NCZ block {id}: {e}")))?;
        if n as u64 != size {
            fail!(InvalidData, "NCZ block {id}: got {n} bytes, want {size}");
        }
        Ok(data)
    }
}

impl<S: ReadAt> ReadAt for NczReader<S> {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        check_range(off, buf.len(), self.size)?;
        let mut done = 0;
        if off < NCA_HEADER_SIZE {
            let n = buf.len().min((NCA_HEADER_SIZE - off) as usize);
            self.src.read_at(off, &mut buf[..n])?;
            done = n;
        }
        if done < buf.len() {
            // Decompressed stream position = NCA offset - 0x4000.
            let pos = off + done as u64 - NCA_HEADER_SIZE;
            let out = &mut buf[done..];
            match &self.body {
                Body::Block(b) => b.read(&self.src, pos, out)?,
                Body::Solid(s) => {
                    let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
                    s.read_at(&self.src, pos, out)?;
                }
            }
        }
        self.crypt(buf, off);
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

type Key = (u64, usize);

/// Result of a decode in progress.
type Pending = OnceLock<Option<Block>>;

/// Most recently used decompressed blocks of all readers, so memory stays
/// bounded however many readers are open.
struct Cache {
    /// Most recently used first.
    blocks: Vec<(Key, Block)>,
    /// Blocks being decoded. The cell is set when the decode ends, to
    /// `None` when it failed.
    pending: Vec<(Key, Arc<Pending>)>,
}

impl Cache {
    fn get(&mut self, key: Key) -> Option<Block> {
        let i = self.blocks.iter().position(|(k, _)| *k == key)?;
        self.blocks[..=i].rotate_right(1);
        Some(Arc::clone(&self.blocks[0].1))
    }

    fn put(&mut self, key: Key, data: Block) {
        let mut bytes: usize = self.blocks.iter().map(|(_, d)| d.len()).sum();
        while self.blocks.len() >= CACHE_BLOCKS
            || !self.blocks.is_empty() && bytes + data.len() > CACHE_BYTES
        {
            if let Some((_, d)) = self.blocks.pop() {
                bytes -= d.len();
            }
        }
        self.blocks.insert(0, (key, data));
    }
}

/// Owner of a pending decode. Dropping it without a result (the decode
/// panicked) still clears the entry and wakes the waiters, which then
/// decode the block themselves.
struct PendingGuard {
    key: Key,
    cell: Arc<Pending>,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.cell.set(None).is_ok() {
            cache().pending.retain(|(k, _)| *k != self.key);
        }
    }
}

fn cache() -> std::sync::MutexGuard<'static, Cache> {
    static CACHE: Mutex<Cache> = Mutex::new(Cache {
        blocks: Vec::new(),
        pending: Vec::new(),
    });
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub use crate::testutil::Rng;

    pub struct TestSection {
        pub offset: usize,
        pub size: usize,
        pub key: Option<([u8; 16], [u8; 16])>,
    }

    /// `n` bytes mixing compressible runs and random data, so some blocks
    /// end up zstd compressed and others stored raw.
    pub fn plain_nca(rng: &mut Rng, n: usize) -> Vec<u8> {
        (0..n)
            .map(|j| {
                if (j / 0x6000) % 3 == 1 {
                    rng.next() as u8
                } else {
                    (j / 64) as u8
                }
            })
            .collect()
    }

    /// Compress the plaintext NCA `plain` the way nsz does. Returns the
    /// NCZ and the NCA it must decompress to.
    pub fn build_ncz(
        plain: &[u8],
        secs: &[TestSection],
        exp: u8,
        solid: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let hs = NCA_HEADER_SIZE as usize;
        let mut want = plain.to_vec();
        let mut out = plain[..hs].to_vec();
        out.extend_from_slice(b"NCZSECTN");
        out.extend_from_slice(&(secs.len() as u64).to_le_bytes());
        for s in secs {
            let mut ct = 1u64;
            let (key, ctr) = s.key.unwrap_or_default();
            if s.key.is_some() {
                ct = 3;
                let part = &mut want[s.offset..s.offset + s.size];
                CtrKey::new(&key, array_at(&ctr, 0).unwrap()).apply(s.offset as u64, part);
            }
            for v in [s.offset as u64, s.size as u64, ct, 0] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&key);
            out.extend_from_slice(&ctr);
        }
        // The raw header holds the original (encrypted) bytes when a
        // section starts inside it.
        out[..hs].copy_from_slice(&want[..hs]);
        let stream = &plain[hs..];
        if solid {
            out.extend_from_slice(&zstd::bulk::compress(stream, 3).unwrap());
            return (out, want);
        }
        let blocks: Vec<Vec<u8>> = stream
            .chunks(1 << exp)
            .map(|chunk| {
                let c = zstd::bulk::compress(chunk, 3).unwrap();
                if c.len() >= chunk.len() {
                    chunk.to_vec()
                } else {
                    c
                }
            })
            .collect();
        out.extend_from_slice(b"NCZBLOCK");
        out.extend_from_slice(&[2, 1, 0, exp]);
        out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        out.extend_from_slice(&(stream.len() as u64).to_le_bytes());
        for b in &blocks {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        }
        for b in &blocks {
            out.extend_from_slice(b);
        }
        (out, want)
    }

    /// An NCA with a gap before the first section (served as a plaintext
    /// section), an encrypted section not aligned to blocks and a partial
    /// last block.
    pub fn test_ncz(seed: u64) -> (Vec<u8>, Vec<u8>) {
        layout_ncz(seed, false)
    }

    /// [`test_ncz`] layout, solid compressed.
    pub fn solid_test_ncz() -> (Vec<u8>, Vec<u8>) {
        layout_ncz(11, true)
    }

    fn layout_ncz(seed: u64, solid: bool) -> (Vec<u8>, Vec<u8>) {
        let mut rng = Rng(seed * 0x9e37_79b9 + 1);
        let size = NCA_HEADER_SIZE as usize + 6 * 0x4000 + 1234;
        let plain = plain_nca(&mut rng, size);
        let secs = [
            TestSection {
                offset: 0x5000,
                size: 0x9010,
                key: Some((rng.bytes(), rng.bytes())),
            },
            TestSection {
                offset: 0xe010,
                size: size - 0xe010,
                key: None,
            },
        ];
        build_ncz(&plain, &secs, 14, solid)
    }

    /// Check random reads of `r` against `want`. Small reads hit unaligned
    /// AES-CTR and block boundaries.
    pub fn check_random_reads<R: ReadAt + ?Sized>(r: &R, want: &[u8]) {
        let mut rng = Rng(5);
        for i in 0..500 {
            let off = rng.below(want.len());
            let mut len = 1 + rng.below(0x20000);
            if i % 4 == 0 {
                len = 1 + rng.below(33);
            }
            let len = len.min(want.len() - off);
            let mut p = vec![0u8; len];
            r.read_at(off as u64, &mut p).unwrap();
            assert!(p == want[off..off + len], "read {len}@{off:#x} mismatch");
        }
        let mut p = [0u8; 2];
        assert!(r.read_at(want.len() as u64 - 1, &mut p).is_err());
    }

    fn blocks<S>(r: &NczReader<S>) -> &Blocks {
        match &r.body {
            Body::Block(b) => b,
            Body::Solid(_) => panic!("solid NCZ"),
        }
    }

    #[test]
    fn read_at() {
        let (ncz, want) = test_ncz(1);
        let r = NczReader::open(&ncz).unwrap();
        assert!(!r.is_solid());
        assert_eq!(r.size().unwrap(), want.len() as u64);
        let b = blocks(&r);
        let raw = b
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, &(_, l))| {
                l as u64 >= b.block_size
                    || i == b.blocks.len() - 1 && l as u64 >= b.decompressed_size % b.block_size
            })
            .count();
        assert!(
            raw > 0 && raw < b.blocks.len(),
            "{raw}/{} raw blocks",
            b.blocks.len()
        );
        let mut got = vec![0u8; want.len()];
        r.read_at(0, &mut got).unwrap();
        assert!(got == want, "full read mismatch");
        check_random_reads(&r, &want);
    }

    /// Small NCAs whose first section starts inside the raw header end at
    /// the last section end.
    #[test]
    fn section_in_header() {
        let mut rng = Rng(4);
        let size = NCA_HEADER_SIZE as usize + 0x5000;
        let secs = [TestSection {
            offset: 0xc00,
            size: size - 0xc00,
            key: Some((rng.bytes(), rng.bytes())),
        }];
        let (ncz, want) = build_ncz(&plain_nca(&mut rng, size), &secs, 14, false);
        let r = NczReader::open(&ncz).unwrap();
        assert_eq!(r.size().unwrap(), want.len() as u64);
        let mut got = vec![0u8; want.len()];
        r.read_at(0, &mut got).unwrap();
        assert!(got == want);
    }

    #[test]
    fn solid_read_at() {
        let (ncz, want) = solid_test_ncz();
        let r = NczReader::open(&ncz).unwrap();
        assert!(r.is_solid());
        assert_eq!(r.size().unwrap(), want.len() as u64);
        let mut got = vec![0u8; want.len()];
        r.read_at(0, &mut got).unwrap();
        assert!(got == want, "full read mismatch");
        // Sequential reads in small pieces continue the stream.
        let mut seq = Vec::new();
        for c in want.chunks(0x1234) {
            let mut p = vec![0u8; c.len()];
            r.read_at(seq.len() as u64, &mut p).unwrap();
            seq.extend_from_slice(&p);
        }
        assert!(seq == want, "sequential read mismatch");
        check_random_reads(&r, &want);
    }

    /// A solid stream that ends early is an error every time it is read.
    #[test]
    fn truncated_solid() {
        let (ncz, want) = solid_test_ncz();
        let r = NczReader::open(&ncz[..ncz.len() - 100]).unwrap();
        let mut got = vec![0u8; want.len()];
        for _ in 0..2 {
            let res = r.read_at(0, &mut got);
            assert!(matches!(res, Err(Error::InvalidData(_))), "{res:?}");
        }
    }

    /// A zstd block that ends early is an error, not a short read.
    #[test]
    fn truncated_block() {
        let (mut ncz, _) = test_ncz(1);
        let r = NczReader::open(&ncz).unwrap();
        let (_, len) = blocks(&r).blocks[0];
        assert!((len as u64) < blocks(&r).block_size, "block 0 stored raw");
        let i = ncz.windows(8).position(|w| w == b"NCZBLOCK").unwrap() + 24;
        ncz[i..i + 4].copy_from_slice(&(len - 1).to_le_bytes());
        let r = NczReader::open(&ncz).unwrap();
        let mut b = [0u8; 0x10];
        let res = r.read_at(NCA_HEADER_SIZE, &mut b);
        assert!(matches!(res, Err(Error::InvalidData(_))), "{res:?}");
    }

    #[test]
    fn bad_block_count() {
        let (mut ncz, _) = test_ncz(4);
        let i = ncz.windows(8).position(|w| w == b"NCZBLOCK").unwrap();
        let n = 0xffff_ffffu64;
        ncz[i + 12..i + 16].copy_from_slice(&(n as u32).to_le_bytes());
        ncz[i + 16..i + 24].copy_from_slice(&(n << 14).to_le_bytes());
        assert!(NczReader::open(&ncz).is_err());
    }

    #[test]
    fn concurrent_reads() {
        let (ncz, want) = test_ncz(7);
        let r = NczReader::open(&ncz).unwrap();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    let mut got = vec![0u8; want.len()];
                    r.read_at(0, &mut got).unwrap();
                    assert!(got == want);
                });
            }
        });
    }
}
