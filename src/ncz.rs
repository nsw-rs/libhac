// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NCZ: an NCA with its sections decrypted and zstd compressed, as written
//! by nsz. [`NczReader`] serves the original NCA, decompressed and
//! re-encrypted on the fly; [`NczWriter`] makes a block one.
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
use crate::error::{Result, fail};
use crate::nca::{EncryptionType, Nca, SectionIndex, TitleKeys};
use crate::storage::{ReadAt, check_range};
use crate::zstd::{self, Decoder, Encoder};
use std::collections::VecDeque;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};

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

/// Decoding state of a solid stream.
struct Solid {
    dec: Decoder,
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
            dec: Decoder::new()?,
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
        self.next_in = self.start;
        self.used = 0;
        self.filled = 0;
        self.pos = 0;
        self.dec.reset()
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
            let (consumed, produced, _) = self
                .dec
                .run(&self.input[self.used..self.filled], &mut out[done..])
                .map_err(|e| e.prefixed("NCZ"))?;
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
        let (sections, size) = parse_sections(&raw)?;

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
}

/// Parse the `NCZSECTN` entries in `raw` (0x40 bytes each, at least one).
/// Returns the sections, with a plaintext gap section in front when the
/// first one starts past the raw header, and the size of the NCA.
fn parse_sections(raw: &[u8]) -> Result<(Vec<Section>, u64)> {
    let mut sections = Vec::with_capacity(raw.len() / 0x40 + 1);
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
    Ok((sections, size))
}

/// Apply AES-CTR to the parts of `buf` (at NCA offset `off`) that fall in
/// encrypted sections past the raw header. Decrypts what it encrypts, so
/// the writer and the reader share it.
fn crypt(sections: &[Section], buf: &mut [u8], off: u64) {
    let end = off + buf.len() as u64;
    for s in sections {
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
        let alloc = |n: u64| -> Result<Vec<u8>> {
            let mut v = Vec::new();
            if v.try_reserve_exact(n as usize).is_err() {
                fail!(InvalidData, "NCZ block {id}: cannot allocate {n} bytes");
            }
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
        let data = zstd::decompress(&comp, size as usize)
            .map_err(|e| e.prefixed(&format!("NCZ block {id}")))?;
        if data.len() as u64 != size {
            fail!(
                InvalidData,
                "NCZ block {id}: got {} bytes, want {size}",
                data.len()
            );
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
        crypt(&self.sections, buf, off);
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

/// Block size exponent of the block NCZs written: 1 MiB blocks, the nsz
/// default.
pub const BLOCK_SIZE_EXP: u8 = 20;
const BLOCK_SIZE: u64 = 1 << BLOCK_SIZE_EXP;

/// Most compression threads [`NczWriter::write`] uses.
pub const MAX_THREADS: usize = 256;

/// Writes an NCA as NCZ, the way nsz does: the sections decrypted, then
/// compressed with zstd. The zstd frames are the ones RomVault writes:
/// level 19, multithreaded framing, and an empty last block. A block frame
/// also has its size in the header, as nsz needs it to decode the block.
///
/// The output depends only on the NCA and the pinned libzstd, not on the
/// thread count, so the same NCA always gives the same bytes.
pub struct NczWriter<'a, S> {
    src: &'a S,
    size: u64,
    /// `NCZSECTN` and its entries.
    table: Vec<u8>,
    sections: Vec<Section>,
}

impl<'a, S: ReadAt> NczWriter<'a, S> {
    /// Plan the NCZ of `nca`. `None` when nsz would store it as it is: its
    /// sections do not run back to back to the end of the NCA, or one uses
    /// an encryption NCZ cannot describe (AES-XTS, the skip layer hash
    /// types).
    pub fn new(nca: &'a Nca<S>, title_keys: &TitleKeys) -> Result<Option<Self>> {
        let src = nca.storage();
        let size = src.size()?;
        let mut secs: Vec<_> = SectionIndex::all()
            .filter(|&i| nca.is_section_enabled(i))
            .map(|i| (nca.section_bounds(i), i))
            .collect();
        secs.sort_by_key(|s| s.0.0);
        // nsz `isNcaPacked`.
        let mut next = secs.first().map(|s| s.0.0);
        for &((start, end), _) in &secs {
            if Some(start) != next || end < start {
                return Ok(None);
            }
            next = Some(end);
        }
        if size <= NCA_HEADER_SIZE || next != Some(size) {
            return Ok(None);
        }

        // nsz stores the section key in every entry, plaintext ones too.
        // Those do not need it, so it is left zero when it is missing.
        let key = nca.section_key(title_keys).ok();
        let mut entries = Vec::new();
        for ((start, end), i) in secs {
            let fsh = nca.fs_header(i);
            let upper = fsh.upper_counter();
            let et = fsh.encryption_type();
            if et == EncryptionType::NONE {
                entries.push((start, end - start, 1, key.unwrap_or_default(), upper));
                continue;
            }
            if et != EncryptionType::AES_CTR && et != EncryptionType::AES_CTR_EX {
                return Ok(None);
            }
            let k = match key {
                Some(k) => k,
                // Fails with the reason the key is missing.
                None => nca.section_key(title_keys)?,
            };
            if et == EncryptionType::AES_CTR {
                entries.push((start, end - start, 3, k, upper));
                continue;
            }
            // AesCtrEx: each counter range becomes a plain AES-CTR entry
            // (type 3), as nsz writes them.
            for (off, len, u) in nca.aes_ctr_ex_ranges(i, &k)? {
                entries.push((off, len, 3, k, u));
            }
        }

        let mut table = b"NCZSECTN".to_vec();
        table.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (offset, size, ct, key, upper) in entries {
            for v in [offset, size, ct, 0] {
                table.extend_from_slice(&v.to_le_bytes());
            }
            table.extend_from_slice(&key);
            table.extend_from_slice(&upper);
            table.extend_from_slice(&[0; 8]);
        }
        let (sections, _) = parse_sections(&table[16..])?;
        Ok(Some(NczWriter {
            src,
            size,
            table,
            sections,
        }))
    }

    /// Read the plain NCA bytes at `pos`, pass them to `on_read`, and
    /// decrypt them.
    fn read_plain(&self, pos: u64, len: u64, on_read: &mut dyn FnMut(&[u8])) -> Result<Vec<u8>> {
        let mut buf = self.src.read_vec(pos, len as usize)?;
        on_read(&buf);
        crypt(&self.sections, &mut buf, pos);
        Ok(buf)
    }

    /// Read the blocks from `pos` on, hand them to the compression threads
    /// through `jobs`, and write their data to `out` in order, while the
    /// next blocks are read. At most `2 * threads` blocks are in flight.
    /// Returns the table of block sizes.
    fn pipe_blocks<W: Write>(
        &self,
        out: &mut W,
        mut pos: u64,
        jobs: mpsc::SyncSender<BlockJob>,
        threads: usize,
        on_read: &mut dyn FnMut(&[u8]),
    ) -> Result<Vec<u8>> {
        let mut lens = Vec::new();
        let mut pending = VecDeque::with_capacity(2 * threads);
        let mut put = |rx: mpsc::Receiver<Result<Vec<u8>>>| -> Result<()> {
            // A closed channel means the thread panicked, which the caller
            // raises again after the join.
            let Ok(data) = rx.recv() else {
                fail!(InvalidData, "compression thread died");
            };
            let data = data?;
            out.write_all(&data)?;
            lens.extend_from_slice(&(data.len() as u32).to_le_bytes());
            Ok(())
        };
        while pos < self.size {
            if pending.len() == 2 * threads {
                put(pending.pop_front().unwrap())?;
            }
            let len = BLOCK_SIZE.min(self.size - pos);
            let raw = self.read_plain(pos, len, on_read)?;
            pos += len;
            let (tx, rx) = mpsc::sync_channel(1);
            if jobs.send((raw, tx)).is_err() {
                fail!(InvalidData, "compression thread died");
            }
            pending.push_back(rx);
        }
        // No more jobs: the threads end once the queue is empty.
        drop(jobs);
        for rx in pending {
            put(rx)?;
        }
        Ok(lens)
    }

    /// Write the NCZ to `out` at its current position, with `threads`
    /// compression threads (0 counts as 1, at most [`MAX_THREADS`] are
    /// used). `on_read` gets every byte of the NCA once, in order, as it is
    /// read. Returns the NCZ size.
    pub fn write<W: Write + Seek>(
        &self,
        out: &mut W,
        threads: usize,
        on_read: &mut dyn FnMut(&[u8]),
    ) -> Result<u64> {
        let threads = threads.clamp(1, MAX_THREADS);
        let start = out.stream_position()?;
        let head = self.src.read_vec(0, NCA_HEADER_SIZE as usize)?;
        on_read(&head);
        out.write_all(&head)?;
        out.write_all(&self.table)?;
        let body = self.size - NCA_HEADER_SIZE;
        let pos = NCA_HEADER_SIZE;
        let Ok(n) = u32::try_from(body.div_ceil(BLOCK_SIZE)) else {
            fail!(Unsupported, "NCA too large for NCZ");
        };
        out.write_all(b"NCZBLOCK")?;
        out.write_all(&[2, 1, 0, BLOCK_SIZE_EXP])?;
        out.write_all(&n.to_le_bytes())?;
        out.write_all(&body.to_le_bytes())?;
        let table_pos = out.stream_position()?;
        out.write_all(&vec![0; 4 * n as usize])?;
        let encoders = (0..threads)
            .map(|_| Encoder::new())
            .collect::<Result<Vec<_>>>()?;
        let (job_tx, job_rx) = mpsc::sync_channel::<BlockJob>(threads);
        // Owned by the threads only, so that if they all die, the
        // queued jobs are dropped and the reader sees it.
        let job_rx = Arc::new(Mutex::new(job_rx));
        let lens = std::thread::scope(|s| {
            let workers: Vec<_> = encoders
                .into_iter()
                .map(|mut enc| {
                    let job_rx = Arc::clone(&job_rx);
                    s.spawn(move || {
                        loop {
                            let job = job_rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                            let Ok((raw, done)) = job else { return };
                            let r = enc
                                .compress(&raw)
                                .map(|p| if p.len() < raw.len() { p } else { raw });
                            // The reader is gone only after an error.
                            let _ = done.send(r);
                        }
                    })
                })
                .collect();
            drop(job_rx);
            let res = self.pipe_blocks(out, pos, job_tx, threads, on_read);
            for w in workers {
                if let Err(p) = w.join() {
                    std::panic::resume_unwind(p);
                }
            }
            res
        })?;
        let end = out.stream_position()?;
        out.seek(SeekFrom::Start(table_pos))?;
        out.write_all(&lens)?;
        out.seek(SeekFrom::Start(end))?;
        Ok(out.stream_position()? - start)
    }
}

/// A plain block for a compression thread, and where its NCZ data goes:
/// the zstd frame, or the block itself when that is not smaller.
type BlockJob = (Vec<u8>, mpsc::SyncSender<Result<Vec<u8>>>);

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
    use crate::error::Error;

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
            out.extend_from_slice(&zstd::compress(stream));
            return (out, want);
        }
        let blocks: Vec<Vec<u8>> = stream
            .chunks(1 << exp)
            .map(|chunk| {
                let c = zstd::compress(chunk);
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

    /// Decompressed size of block `i`. The last one is a full block when
    /// the stream is an exact multiple of the block size.
    fn block_len(b: &Blocks, i: usize) -> u64 {
        let rem = b.decompressed_size % b.block_size;
        if i == b.blocks.len() - 1 && rem > 0 {
            rem
        } else {
            b.block_size
        }
    }

    #[test]
    fn read_at() {
        let (ncz, want) = test_ncz(1);
        let r = NczReader::open(&ncz).unwrap();
        assert!(!r.is_solid());
        assert_eq!(r.size().unwrap(), want.len() as u64);
        let b = blocks(&r);
        let raw = (0..b.blocks.len())
            .filter(|&i| b.blocks[i].1 as u64 >= block_len(b, i))
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

    /// A stream that is an exact multiple of the block size ends with a
    /// full block, here a compressed one. Reading it as a partial block of
    /// `size % block_size` (0) bytes would take it as raw. It is not zeros,
    /// which is what an empty block reads back as.
    #[test]
    fn exact_multiple_last_block() {
        let mut rng = Rng(9);
        let hs = NCA_HEADER_SIZE as usize;
        let size = hs + 4 * 0x4000;
        let mut plain = plain_nca(&mut rng, size);
        plain[size - 0x4000..].fill(0x5a);
        let secs = [TestSection {
            offset: hs,
            size: size - hs,
            key: None,
        }];
        let (ncz, want) = build_ncz(&plain, &secs, 14, false);
        let r = NczReader::open(&ncz).unwrap();
        let b = blocks(&r);
        assert_eq!(b.decompressed_size % b.block_size, 0);
        let last = b.blocks.len() - 1;
        assert!(
            (b.blocks[last].1 as u64) < block_len(b, last),
            "last block raw"
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

    /// A plain NCA image and the NCA made from it: an AES-CTR section
    /// starting inside the raw header, a plaintext section of several
    /// blocks, and an AesCtrEx section with two counter generations and its
    /// bucket tree. Returns the plain image, the NCA, its decrypted header
    /// and its key.
    fn writer_nca(rng: &mut Rng) -> (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 16]) {
        let ex_start = 0x9000 + 0x22_0000;
        let size = ex_start + 0xE000;
        let mut plain = plain_nca(rng, size);
        // Bucket tree past the AesCtrEx data: L1 node, then one entry set.
        let tree = ex_start + 0x6000;
        plain[tree..size].fill(0);
        let mut put = |at: usize, v: &[u8]| plain[at..at + v.len()].copy_from_slice(v);
        put(tree + 4, &1u32.to_le_bytes());
        put(tree + 8, &0x6000u64.to_le_bytes());
        let set = tree + 0x4000;
        put(set + 4, &2u32.to_le_bytes());
        put(set + 8, &0x6000u64.to_le_bytes());
        for (k, (off, generation)) in [(0u64, 5u32), (0x3000, 7)].into_iter().enumerate() {
            let e = set + 0x10 + k * 0x10;
            put(e, &off.to_le_bytes());
            put(e + 0xC, &generation.to_le_bytes());
        }

        let key: [u8; 16] = rng.bytes();
        let mut header = vec![0u8; 0xC00];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        let secs = [
            (0xC00, 0x9000, 3u8),
            (0x9000, ex_start, 1),
            (ex_start, size, 4),
        ];
        let mut nca = plain.clone();
        for (i, &(start, end, et)) in secs.iter().enumerate() {
            let t = 0x240 + i * 0x10;
            header[t..t + 4].copy_from_slice(&(start as u32 / 0x200).to_le_bytes());
            header[t + 4..t + 8].copy_from_slice(&(end as u32 / 0x200).to_le_bytes());
            let fsh = 0x400 + i * 0x200;
            header[fsh + 4] = et;
            let upper: [u8; 8] = rng.bytes();
            header[fsh + 0x140..fsh + 0x148].copy_from_slice(&upper);
            let upper = u64::from_le_bytes(upper).to_be_bytes();
            let ctr = |u: [u8; 8]| CtrKey::new(&key, u);
            match et {
                3 => ctr(upper).apply(start as u64, &mut nca[start..end]),
                4 => {
                    let info = fsh + 0x120;
                    header[info..info + 8].copy_from_slice(&0x6000u64.to_le_bytes());
                    header[info + 8..info + 16].copy_from_slice(&0x8000u64.to_le_bytes());
                    header[info + 16..info + 20].copy_from_slice(b"BKTR");
                    header[info + 24..info + 28].copy_from_slice(&2u32.to_le_bytes());
                    for (lo, hi, generation) in [(0, 0x3000, 5u32), (0x3000, 0x6000, 7)] {
                        let mut u = upper;
                        u[4..].copy_from_slice(&generation.to_be_bytes());
                        let (lo, hi) = (start + lo, start + hi);
                        ctr(u).apply(lo as u64, &mut nca[lo..hi]);
                    }
                    ctr(upper).apply(tree as u64, &mut nca[tree..end]);
                }
                _ => {}
            }
        }
        // The raw header is stored as it is.
        plain[..NCA_HEADER_SIZE as usize].copy_from_slice(&nca[..NCA_HEADER_SIZE as usize]);
        (plain, nca, header, key)
    }

    fn write_ncz(w: &NczWriter<'_, Vec<u8>>, threads: usize) -> Vec<u8> {
        let mut out = std::io::Cursor::new(b"pad".to_vec());
        out.set_position(3);
        let mut seen = Vec::new();
        let n = w.write(&mut out, threads, &mut |b| seen.extend_from_slice(b));
        let out = out.into_inner();
        assert_eq!(n.unwrap(), out.len() as u64 - 3);
        assert!(seen == *w.src, "on_read did not see the NCA in order");
        out[3..].to_vec()
    }

    #[test]
    fn writer_round_trip() {
        let mut rng = Rng(21);
        let (plain, nca, header, key) = writer_nca(&mut rng);
        let nca = Nca::with_plain_header(nca, header, key);
        let w = NczWriter::new(&nca, &TitleKeys::new()).unwrap().unwrap();
        let want = nca.storage();

        let ncz = write_ncz(&w, 2);
        let r = NczReader::open(&ncz).unwrap();
        assert!(!r.is_solid());
        // The stream is the plaintext: every section was decrypted with
        // the right counter.
        let hs = NCA_HEADER_SIZE as usize;
        let mut body = vec![0u8; plain.len() - hs];
        blocks(&r).read(&ncz, 0, &mut body).unwrap();
        assert!(body == plain[hs..], "body is not the plaintext");
        assert_eq!(blocks(&r).blocks.len(), body.len().div_ceil(1 << 20));
        check_random_reads(&r, want);
        // The thread count does not change the bytes.
        assert!(write_ncz(&w, 1) == ncz);
        assert!(write_ncz(&w, 5) == ncz);
    }

    /// A body that is an exact multiple of the block size: the last block
    /// is written compressed and reads back as a full block.
    #[test]
    fn writer_exact_multiple() {
        let mut rng = Rng(23);
        let size = (NCA_HEADER_SIZE + 2 * BLOCK_SIZE) as usize;
        let mut nca = plain_nca(&mut rng, size);
        nca[size - BLOCK_SIZE as usize..].fill(0x5a);
        let mut header = vec![0u8; 0xC00];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        header[0x240..0x244].copy_from_slice(&(0xC00u32 / 0x200).to_le_bytes());
        header[0x244..0x248].copy_from_slice(&(size as u32 / 0x200).to_le_bytes());
        header[0x404] = 1;
        let nca = Nca::with_plain_header(nca, header, rng.bytes());
        let w = NczWriter::new(&nca, &TitleKeys::new()).unwrap().unwrap();
        let want = nca.storage();

        let ncz = write_ncz(&w, 2);
        let r = NczReader::open(&ncz).unwrap();
        let b = blocks(&r);
        assert_eq!(b.blocks.len(), 2);
        assert!((b.blocks[1].1 as u64) < BLOCK_SIZE, "last block raw");
        let mut got = vec![0u8; want.len()];
        r.read_at(0, &mut got).unwrap();
        assert!(got == *want, "round trip mismatch");
    }

    /// NCAs nsz stores as they are.
    #[test]
    fn writer_declines() {
        let mut rng = Rng(22);
        let (_, storage, header, key) = writer_nca(&mut rng);
        let with = |f: &dyn Fn(&mut Vec<u8>, &mut Vec<u8>)| {
            let (mut s, mut h) = (storage.clone(), header.clone());
            f(&mut s, &mut h);
            let nca = Nca::with_plain_header(s, h, key);
            NczWriter::new(&nca, &TitleKeys::new()).unwrap().is_none()
        };
        assert!(!with(&|_, _| {}));
        // Trailing bytes past the last section.
        assert!(with(&|s, _| s.extend_from_slice(&[0; 0x200])));
        // A hole between sections.
        assert!(with(
            &|_, h| h[0x250..0x254].copy_from_slice(&0x50u32.to_le_bytes())
        ));
        // AES-XTS.
        assert!(with(&|_, h| h[0x404] = 2));
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
