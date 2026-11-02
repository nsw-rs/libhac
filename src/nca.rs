// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NCA reader: header decryption and signatures, key area, title key,
//! AES-CTR sections and hash-tree verified reads (mirrors LibHac
//! `IntegrityCheckLevel.ErrorOnInvalid` for the blocks that are touched).

use crate::bytes::{array_at, open_enum, u16_le, u32_le, u64_le};
use crate::crypto::{CtrKey, aes_ecb_decrypt, aes_xts_decrypt, verify_rsa_pss};
use crate::error::{Error, Result, fail};
use crate::keys::Keys;
use crate::storage::{ReadAt, check_range, in_range};
use crate::types::{KeyGeneration, RightsId, TitleId};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

open_enum! {
    /// NCA header content type.
    pub struct ContentType(u8) {
        PROGRAM = 0 => "Program",
        META = 1 => "Meta",
        CONTROL = 2 => "Control",
        MANUAL = 3 => "Manual",
        DATA = 4 => "Data",
        PUBLIC_DATA = 5 => "PublicData",
    }
}

open_enum! {
    /// File-system type of an NCA section.
    pub struct FsType(u8) {
        ROMFS = 0 => "RomFs",
        PFS0 = 1 => "PartitionFs",
    }
}

open_enum! {
    /// Hash tree type of an NCA section (`NcaHashType`).
    pub struct HashType(u8) {
        /// Picked from the file-system type.
        AUTO = 0 => "Auto",
        NONE = 1 => "None",
        /// Hierarchical SHA-256 (PFS0 sections).
        SHA256 = 2 => "Sha256",
        /// IVFC (RomFS sections).
        IVFC = 3 => "Ivfc",
    }
}

open_enum! {
    /// Encryption of an NCA section (`NcaEncryptionType`).
    pub struct EncryptionType(u8) {
        AUTO = 0 => "Auto",
        NONE = 1 => "None",
        AES_XTS = 2 => "AesXts",
        AES_CTR = 3 => "AesCtr",
        AES_CTR_EX = 4 => "AesCtrEx",
        AES_CTR_SKIP_LAYER_HASH = 5 => "AesCtrSkipLayerHash",
        AES_CTR_EX_SKIP_LAYER_HASH = 6 => "AesCtrExSkipLayerHash",
    }
}

open_enum! {
    /// How an NCA was distributed (`DistributionType`).
    pub struct DistributionType(u8) {
        DOWNLOAD = 0 => "Download",
        GAME_CARD = 1 => "GameCard",
    }
}

open_enum! {
    /// Which key area key decrypts the key area of an NCA
    /// (`NcaKeyAreaEncryptionKeyIndex`).
    pub struct KeyAreaKeyIndex(u8) {
        APPLICATION = 0 => "Application",
        OCEAN = 1 => "Ocean",
        SYSTEM = 2 => "System",
    }
}

/// Index of one of the 4 sections of an NCA. Shown as a decimal number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SectionIndex(u8);

impl SectionIndex {
    /// Number of section entries in an NCA header.
    pub const COUNT: usize = 4;

    /// `None` when `i` is not below [`SectionIndex::COUNT`].
    pub fn new(i: usize) -> Option<Self> {
        (i < Self::COUNT).then_some(SectionIndex(i as u8))
    }

    /// The index as a `usize` (0 to 3).
    pub fn get(self) -> usize {
        self.0 as usize
    }

    /// All section indices, in order.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..Self::COUNT as u8).map(SectionIndex)
    }
}

impl TryFrom<usize> for SectionIndex {
    type Error = Error;

    fn try_from(i: usize) -> Result<Self> {
        match Self::new(i) {
            Some(s) => Ok(s),
            None => fail!(OutOfRange, "NCA section index {i} out of range"),
        }
    }
}

impl fmt::Display for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Decode a hex string at compile time.
const fn hex_bytes<const N: usize>(s: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 2 * N, "bad hex length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Prod NCA header fixed-key RSA-2048 moduli (LibHac 0.19.0), indexed by
/// the header's signature key generation.
const NCA_HEADER_MODULI: [[u8; 256]; 2] = [
    hex_bytes(
        "bfbe406cf4a780e9f07d0c99611d772f96bc4b9e58381b03abb175499f2b4d5834b005a37522be1a3f0373ac7068d116b904465eb707912f078b26def60007b2b451f80d0a5e58adebbc9ad649b964efa782b5cf6d7013b00f85f6a908aa4d676687fa89ff7590181e6b3de98a68c92604d980ce3f5e92ce01ff063bf2c1a90cce026f16bc92420a4164cd52b6344daec02edea4df27683cc1a060ad43f3fc86c13e6c46f77c299ffafdf0e3ce64e735f2f656566f6df1e242b08340a5c3202bcc9aaecaed4d7030a8701c70fd1363290279ead2a7af3528321c7be62f1aaa407e328c2742fe8278ec0debe6834b6d8104401a9e9a67f67229fa04f09de4f403",
    ),
    hex_bytes(
        "ade3e1fa0435e5b6dd49ea8929b1ffb643dfca96a04a13df43d9949796436548705833a27d357b96745e0b5c32181424c258b36c227aa1b7cb90a7a3f97d4516a5c8ed8fad395e9e4b51687df80c35c63f91ae44a592300d46f840ffd0ff06d21c7f9618dcb71d663ed173bc158a2f94f300c183f1cdd78188abdf8cef97dd1b175f58f69ae9e8c22f3815f52107f837905d2e024024150d25b7265d09cc4cf4f21b94705a9eeeed7777d45199f5dc761ee36c8cd112d457d1b683e4e4fedae9b43b33e5378adfb57f89f19b9eb015b23afeea61845b7d4b23120b8312f2226bb922964b260b635e965752a3676422cad0563e74b5981f0df8b334e698685aad",
    ),
];

/// Decrypted view of an NCA section.
struct SectionStorage<'a, S> {
    nca: &'a S,
    /// Section start within the NCA.
    start: u64,
    size: u64,
    ctr: Option<CtrKey>,
}

impl<S: ReadAt> ReadAt for SectionStorage<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        let abs = self.start + offset;
        self.nca.read_at(abs, buf)?;
        if let Some(key) = &self.ctr {
            key.apply(abs, buf);
        }
        Ok(())
    }
    fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

struct HashLevel {
    offset: u64,
    size: u64,
    block_size: u64,
}

/// Verified blocks: every block of the hash levels by level and index, and
/// only the last block read of the data level, since caching all of those
/// would keep every byte ever read in memory.
#[derive(Default)]
struct BlockCache {
    hash: HashMap<(usize, u64), Rc<[u8]>>,
    data: Option<(u64, Rc<[u8]>)>,
}

/// Data level of a hash tree; every block read is checked up to the master hash.
struct VerifiedStorage<'a, S> {
    base: SectionStorage<'a, S>,
    levels: Vec<HashLevel>,
    master_hash: [u8; 32],
    /// How a partial last block is hashed: IVFC hashes it zero-padded to the
    /// block size, a hierarchical SHA256 tree hashes only the bytes present.
    zero_pad: bool,
    cache: RefCell<BlockCache>,
}

impl<S: ReadAt> VerifiedStorage<'_, S> {
    fn block(&self, level: usize, index: u64) -> Result<Rc<[u8]>> {
        let is_data = level + 1 == self.levels.len();
        {
            let cache = self.cache.borrow();
            let hit = if is_data {
                cache.data.as_ref().filter(|d| d.0 == index).map(|d| &d.1)
            } else {
                cache.hash.get(&(level, index))
            };
            if let Some(b) = hit {
                return Ok(Rc::clone(b));
            }
        }
        let l = &self.levels[level];
        let start = index * l.block_size;
        if start >= l.size {
            fail!(OutOfRange, "hash block out of range");
        }
        let len = l.block_size.min(l.size - start) as usize;
        // Read straight into the shared buffer. The level was checked to lie
        // inside the section when it was opened, so `len` is bounded.
        let mut data: Rc<[u8]> = std::iter::repeat_n(0, len).collect();
        self.base
            .read_at(l.offset + start, Rc::get_mut(&mut data).unwrap())?;

        let expected = if level == 0 {
            if index != 0 {
                fail!(InvalidData, "master hash covers only one block");
            }
            self.master_hash
        } else {
            let mut h = [0u8; 32];
            self.read_level(level - 1, index * 32, &mut h)?;
            h
        };

        let mut h = Sha256::new();
        h.update(&*data);
        if self.zero_pad {
            // The padding is hashed in small chunks, since the block size
            // comes from the file.
            let zeros = [0u8; 0x1000];
            let mut left = l.block_size - data.len() as u64;
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                h.update(&zeros[..n]);
                left -= n as u64;
            }
        }
        if h.finalize().as_slice() != expected {
            return Err(Error::HashMismatch {
                level,
                block: index,
            });
        }
        let mut cache = self.cache.borrow_mut();
        if is_data {
            cache.data = Some((index, Rc::clone(&data)));
        } else {
            cache.hash.insert((level, index), Rc::clone(&data));
        }
        Ok(data)
    }

    fn read_level(&self, level: usize, offset: u64, out: &mut [u8]) -> Result<()> {
        let bs = self.levels[level].block_size;
        let mut pos = offset;
        let end = offset + out.len() as u64;
        while pos < end {
            let block = self.block(level, pos / bs)?;
            let in_block = (pos % bs) as usize;
            // A short last block can end before `pos`.
            let take = ((end - pos) as usize).min(block.len().saturating_sub(in_block));
            if take == 0 {
                fail!(OutOfRange, "read past end of hash level");
            }
            let done = (pos - offset) as usize;
            out[done..done + take].copy_from_slice(&block[in_block..in_block + take]);
            pos += take as u64;
        }
        Ok(())
    }
}

impl<S: ReadAt> ReadAt for VerifiedStorage<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let data_level = self.levels.len() - 1;
        check_range(offset, buf.len(), self.size()?)?;
        self.read_level(data_level, offset, buf)
    }
    fn size(&self) -> Result<u64> {
        Ok(self.levels.last().unwrap().size)
    }
}

// ---------------------------------------------------------------- compression

/// Bucket tree node size used by `CompressedStorage`.
const BKTR_NODE_SIZE: usize = 0x4000;
/// Size of a bucket tree node header: index (s32), count (s32), end offset (s64).
const BKTR_NODE_HEADER: usize = 0x10;
const COMPRESSED_ENTRY_SIZE: usize = 0x18;

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_ZEROS: u8 = 1;
const COMPRESSION_LZ4: u8 = 3;

/// One `CompressedStorage` entry: a virtual range backed by `phys_size`
/// bytes at `phys` in the verified data level.
struct CompressedEntry {
    virt: u64,
    phys: u64,
    kind: u8,
    phys_size: u32,
}

/// LibHac `CompressedStorage`: the decompressed view of a verified data
/// level, described by a bucket tree stored inside that level.
struct CompressedStorage<'a, S> {
    base: VerifiedStorage<'a, S>,
    entries: Vec<CompressedEntry>,
    size: u64,
    /// Index and output of the last LZ4 entry decompressed, so small reads
    /// inside one entry do not decompress it again each time.
    lz4: RefCell<Option<(usize, Vec<u8>)>>,
}

impl<'a, S: ReadAt> CompressedStorage<'a, S> {
    /// `info` is the FS header `CompressionInfo`: table offset and size,
    /// then the bucket tree header.
    fn open(base: VerifiedStorage<'a, S>, info: &[u8]) -> Result<Self> {
        let table_offset = u64_le(info, 0);
        let table_size = u64_le(info, 8);
        if &info[0x10..0x14] != b"BKTR" {
            fail!(InvalidMagic, "Invalid compression table header");
        }
        let count = u32_le(info, 0x18) as usize;

        // Layout from `BucketTree.QueryNodeStorageSize`/`QueryEntryStorageSize`:
        // the L1 node, optional L2 nodes, then the entry sets.
        let per_set = (BKTR_NODE_SIZE - BKTR_NODE_HEADER) / COMPRESSED_ENTRY_SIZE;
        let offsets_per_node = (BKTR_NODE_SIZE - BKTR_NODE_HEADER) / 8;
        let sets = count.div_ceil(per_set);
        let l2_nodes = if sets <= offsets_per_node {
            0
        } else {
            let n = sets.div_ceil(offsets_per_node);
            // LibHac aborts here; past this point the subtraction underflows.
            if n > offsets_per_node {
                fail!(InvalidData, "Invalid compression table");
            }
            (sets - (offsets_per_node - (n - 1))).div_ceil(offsets_per_node)
        };
        let node_size = BKTR_NODE_SIZE as u64;
        let node_storage = node_size * (l2_nodes as u64 + 1);
        // The table must lie inside the data level before `count` entries
        // are allocated, since `count` comes from the file.
        let base_size = base.size()?;
        if node_storage + sets as u64 * node_size > table_size
            || !in_range(table_offset, table_size, base_size)
        {
            fail!(OutOfRange, "Compression table out of range");
        }

        let l1 = base.read_vec(table_offset, BKTR_NODE_SIZE)?;
        let size = u64_le(&l1, 8);
        let mut entries = Vec::with_capacity(count);
        for set in 0..sets {
            let node = base.read_vec(
                table_offset + node_storage + set as u64 * node_size,
                BKTR_NODE_SIZE,
            )?;
            let n = (u32_le(&node, 4) as usize).min(per_set);
            for k in 0..n {
                let e = &node[BKTR_NODE_HEADER + k * COMPRESSED_ENTRY_SIZE..];
                entries.push(CompressedEntry {
                    virt: u64_le(e, 0),
                    phys: u64_le(e, 8),
                    kind: e[0x10],
                    phys_size: u32_le(e, 0x14),
                });
            }
        }
        // A non-empty storage needs a first entry at offset 0.
        if entries.len() != count
            || entries.first().map_or(size != 0, |e| e.virt != 0)
            || !entries.windows(2).all(|w| w[0].virt < w[1].virt)
            || entries.last().is_some_and(|e| e.virt >= size)
        {
            fail!(InvalidData, "Invalid compression table");
        }
        Ok(CompressedStorage {
            base,
            entries,
            size,
            lz4: RefCell::new(None),
        })
    }

    /// Decompressed bytes of LZ4 entry `e`, which is `len` bytes long.
    fn decompress_lz4(&self, e: &CompressedEntry, len: u64) -> Result<Vec<u8>> {
        // An LZ4 block expands at most about 255 times (one 0xFF length
        // byte per 255 output bytes), so a larger length is corrupt. Check
        // before allocating, since `len` comes from the file.
        if len > (e.phys_size as u64 + 1) * 255 {
            fail!(
                InvalidData,
                "LZ4 entry of {} bytes cannot decompress to {len} bytes",
                e.phys_size
            );
        }
        let Ok(len) = usize::try_from(len) else {
            fail!(
                InvalidData,
                "LZ4 entry of {len} bytes does not fit in memory"
            );
        };
        let packed = self.base.read_vec(e.phys, e.phys_size as usize)?;
        let mut out = vec![0; len];
        let n = lz4_flex::block::decompress_into(&packed, &mut out)
            .map_err(|e| Error::InvalidData(e.to_string()))?;
        if n != len {
            fail!(
                InvalidData,
                "LZ4 entry decompressed to {n} bytes, expected {len}"
            );
        }
        Ok(out)
    }
}

impl<S: ReadAt> ReadAt for CompressedStorage<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let i = self.entries.partition_point(|e| e.virt <= pos) - 1;
            let e = &self.entries[i];
            let end = self.entries.get(i + 1).map_or(self.size, |n| n.virt);
            let skip = pos - e.virt;
            let take = (end - pos).min((buf.len() - done) as u64) as usize;
            let out = &mut buf[done..done + take];
            // Plain and zero entries can be large: touch only the bytes asked for.
            match e.kind {
                COMPRESSION_NONE => {
                    let Some(phys) = e.phys.checked_add(skip) else {
                        fail!(OutOfRange, "Compressed entry out of range");
                    };
                    self.base.read_at(phys, out)?;
                }
                COMPRESSION_ZEROS => out.fill(0),
                COMPRESSION_LZ4 => {
                    let mut lz4 = self.lz4.borrow_mut();
                    if lz4.as_ref().is_none_or(|c| c.0 != i) {
                        *lz4 = Some((i, self.decompress_lz4(e, end - e.virt)?));
                    }
                    let data = &lz4.as_ref().unwrap().1;
                    let skip = skip as usize;
                    out.copy_from_slice(&data[skip..skip + take]);
                }
                t => fail!(Unsupported, "Unsupported compression type {t}"),
            }
            done += take;
        }
        Ok(())
    }
    fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

// ---------------------------------------------------------------- FS header

/// NCA section (file-system) header.
pub struct FsHeader<'h> {
    raw: &'h [u8],
}

impl FsHeader<'_> {
    /// File system type.
    pub fn fs_type(&self) -> FsType {
        FsType(self.raw[2])
    }
    /// Hash tree type.
    pub fn hash_type(&self) -> HashType {
        HashType(self.raw[3])
    }
    /// Encryption type.
    pub fn encryption_type(&self) -> EncryptionType {
        EncryptionType(self.raw[4])
    }
    /// LibHac `NcaFsHeader.IsPatchSection`: relocation (indirect) tree size != 0.
    pub fn is_patch_section(&self) -> bool {
        u64_le(self.raw, 0x108) != 0
    }
    /// Sparse layer present (SparseInfo.Generation != 0).
    pub fn has_sparse_layer(&self) -> bool {
        u16_le(self.raw, 0x170) != 0
    }
    /// LibHac `NcaFsHeader.ExistsCompressionLayer`.
    fn compression_info(&self) -> Option<&[u8]> {
        let info = &self.raw[0x178..0x1A0];
        (u64_le(info, 0) != 0 && u64_le(info, 8) != 0).then_some(info)
    }
    fn upper_counter(&self) -> [u8; 8] {
        u64_le(self.raw, 0x140).to_be_bytes()
    }
}

// ---------------------------------------------------------------- NCA

/// An NCA with a decrypted header, read from storage `S`.
pub struct Nca<S> {
    storage: S,
    header: Vec<u8>,
    rights_id: RightsId,
    /// Decrypted AES-CTR key of the key area (entry 2), the only one used.
    key_area_ctr: Option<[u8; 16]>,
    titlekek: Option<[u8; 16]>,
}

/// Encrypted title keys imported from tickets, by rights ID.
#[derive(Clone, Default)]
pub struct TitleKeys(HashMap<RightsId, [u8; 16]>);

impl TitleKeys {
    /// An empty key map.
    pub fn new() -> Self {
        Self::default()
    }

    /// The encrypted title key of `rights_id`.
    pub fn get(&self, rights_id: &RightsId) -> Option<&[u8; 16]> {
        self.0.get(rights_id)
    }

    /// Add or replace the key of `rights_id`, returning the old one.
    pub fn insert(&mut self, rights_id: RightsId, key: [u8; 16]) -> Option<[u8; 16]> {
        self.0.insert(rights_id, key)
    }

    /// True when a key for `rights_id` is present.
    pub fn contains(&self, rights_id: &RightsId) -> bool {
        self.0.contains_key(rights_id)
    }
}

/// Lists the rights IDs only, not the keys.
impl fmt::Debug for TitleKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl<S: ReadAt> Nca<S> {
    /// Decrypt and parse the header, and decrypt the key area when its key
    /// is in `keys`.
    pub fn open(keys: &Keys, storage: S) -> Result<Self> {
        if storage.size()? < 0xC00 {
            fail!(InvalidData, "NCA too small");
        }
        let mut header = storage.read_vec(0, 0xC00)?;
        aes_xts_decrypt(&keys.header_key, &mut header[..0x400], 0x200, 0);
        match &header[0x200..0x204] {
            b"NCA3" => aes_xts_decrypt(&keys.header_key, &mut header[0x400..], 0x200, 2),
            b"NCA2" => {
                for i in 0..4 {
                    let s = 0x400 + i * 0x200;
                    aes_xts_decrypt(&keys.header_key, &mut header[s..s + 0x200], 0x200, 0);
                }
            }
            _ => fail!(
                InvalidData,
                "Unable to decrypt NCA header. The file is not a valid NCA file or the header key is incorrect."
            ),
        }

        let mut nca = Nca {
            storage,
            rights_id: RightsId(array_at(&header, 0x230)?),
            header,
            key_area_ctr: None,
            titlekek: None,
        };
        let rev = nca.key_generation().master_key_revision();
        if let Some(kak) = keys.key_area_key(rev, nca.key_area_key_index()) {
            let mut key: [u8; 16] = array_at(&nca.header, 0x320)?;
            aes_ecb_decrypt(kak, &mut key);
            nca.key_area_ctr = Some(key);
        }
        nca.titlekek = keys.titlekek(rev).copied();
        Ok(nca)
    }

    /// Download or game card.
    pub fn distribution_type(&self) -> DistributionType {
        DistributionType(self.header[0x204])
    }
    /// The storage the NCA is read from.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Content type from the header.
    pub fn content_type(&self) -> ContentType {
        ContentType(self.header[0x205])
    }
    /// Which key area key family encrypts the key area.
    pub fn key_area_key_index(&self) -> KeyAreaKeyIndex {
        KeyAreaKeyIndex(self.header[0x207])
    }
    /// Program (title) ID from the header.
    pub fn program_id(&self) -> TitleId {
        TitleId(u64_le(&self.header, 0x210))
    }
    /// LibHac `NcaHeader.KeyGeneration`: max of the old and new fields.
    pub fn key_generation(&self) -> KeyGeneration {
        KeyGeneration(self.header[0x206].max(self.header[0x220]))
    }
    fn signature_key_generation(&self) -> u8 {
        self.header[0x221]
    }
    /// Zero when the NCA does not use title key crypto.
    pub fn rights_id(&self) -> RightsId {
        self.rights_id
    }
    /// Section index LibHac uses for `NcaSectionType.Data`.
    pub fn data_section_index(&self) -> SectionIndex {
        SectionIndex(u8::from(self.content_type() == ContentType::PROGRAM))
    }

    /// Check signature 1 of the header against Nintendo's fixed NCA header key.
    pub fn verify_header_signature(&self) -> bool {
        let Some(m) = NCA_HEADER_MODULI.get(self.signature_key_generation() as usize) else {
            return false;
        };
        verify_rsa_pss(m, &self.header[0x200..0x400], &self.header[..0x100])
    }

    /// Check signature 2 of the header against `modulus`, the ACID modulus
    /// of the program's `main.npdm` (see [`crate::npdm::acid_modulus`]).
    pub fn verify_signature2(&self, modulus: &[u8]) -> bool {
        verify_rsa_pss(
            modulus,
            &self.header[0x200..0x400],
            &self.header[0x100..0x200],
        )
    }

    fn section_bounds(&self, i: SectionIndex) -> (u64, u64) {
        let o = 0x240 + i.get() * 0x10;
        (
            u32_le(&self.header, o) as u64 * 0x200,
            u32_le(&self.header, o + 4) as u64 * 0x200,
        )
    }

    /// True when section `i` has a non-empty entry in the section table.
    pub fn is_section_enabled(&self, i: SectionIndex) -> bool {
        let (start, end) = self.section_bounds(i);
        start != 0 || end != start
    }

    /// The FS header of section `i`.
    pub fn fs_header(&self, i: SectionIndex) -> FsHeader<'_> {
        let o = 0x400 + i.get() * 0x200;
        FsHeader {
            raw: &self.header[o..o + 0x200],
        }
    }

    /// Decrypted title key (LibHac `Nca.GetDecryptedTitleKey`). The error
    /// is [`Error::MissingTitleKey`] with the missing key name, mirroring
    /// `MissingKeyException.Name`: the rights ID for a missing title key,
    /// `titlekek_XX` for a missing kek.
    pub fn decrypted_title_key(&self, title_keys: &TitleKeys) -> Result<[u8; 16]> {
        let mut key = *title_keys
            .get(&self.rights_id)
            .ok_or_else(|| Error::MissingTitleKey(self.rights_id.to_string()))?;
        let kek = self.titlekek.ok_or_else(|| {
            Error::MissingTitleKey(format!(
                "titlekek_{:02x}",
                self.key_generation().master_key_revision()
            ))
        })?;
        aes_ecb_decrypt(&kek, &mut key);
        Ok(key)
    }

    /// LibHac `Nca.CanOpenSection`.
    pub fn can_open_section(&self, i: SectionIndex, title_keys: &TitleKeys) -> bool {
        if !self.is_section_enabled(i) {
            return false;
        }
        if self.fs_header(i).encryption_type() == EncryptionType::NONE {
            return true;
        }
        if !self.rights_id.is_zero() {
            title_keys.contains(&self.rights_id) && self.titlekek.is_some()
        } else {
            self.key_area_ctr.is_some()
        }
    }

    fn section_key(&self, title_keys: &TitleKeys) -> Result<[u8; 16]> {
        if !self.rights_id.is_zero() {
            self.decrypted_title_key(title_keys)
        } else {
            self.key_area_ctr
                .ok_or_else(|| Error::MissingKey("Missing key area key".into()))
        }
    }

    /// Open the hash-verified data level of section `i`, decompressed when
    /// the section has a compression layer (LibHac `OpenStorage(i, ErrorOnInvalid)`).
    pub fn open_section(
        &self,
        i: SectionIndex,
        title_keys: &TitleKeys,
    ) -> Result<SectionReader<'_, S>> {
        if !self.is_section_enabled(i) {
            fail!(InvalidData, "Section {i} is empty");
        }
        let fsh = self.fs_header(i);
        // LibHac `NcaHeader.GetFsHeader`: the signed header holds a SHA256 of each FS header.
        let h = 0x280 + i.get() * 0x20;
        if Sha256::digest(fsh.raw).as_slice() != &self.header[h..h + 0x20] {
            fail!(InvalidData, "FS header hash is invalid.");
        }
        if fsh.is_patch_section() {
            fail!(Unsupported, "Patch sections are not supported");
        }
        if fsh.has_sparse_layer() {
            fail!(Unsupported, "Sparse sections are not supported");
        }
        let (start, end) = self.section_bounds(i);
        if end < start || end > self.storage.size()? {
            fail!(OutOfRange, "Section {i} is out of range");
        }
        let ctr = match fsh.encryption_type() {
            EncryptionType::NONE => None,
            // AesCtrSkipLayerHash leaves the hash layers unencrypted, which
            // needs a region switch storage.
            EncryptionType::AES_CTR => Some(CtrKey::new(
                &self.section_key(title_keys)?,
                fsh.upper_counter(),
            )),
            t => fail!(Unsupported, "Unsupported section encryption type {}", t.0),
        };
        let base = SectionStorage {
            nca: &self.storage,
            start,
            size: end - start,
            ctr,
        };

        let raw = fsh.raw;
        let hash_type = match (fsh.hash_type(), fsh.fs_type()) {
            (HashType::AUTO, FsType::PFS0) => HashType::SHA256,
            (HashType::AUTO, FsType::ROMFS) => HashType::IVFC,
            (t, _) => t,
        };
        let (levels, master_hash, zero_pad) = match hash_type {
            HashType::SHA256 => {
                let master: [u8; 32] = array_at(raw, 0x08)?;
                let block_size = u32_le(raw, 0x28) as u64;
                let count = u32_le(raw, 0x2C) as usize;
                if !(2..=5).contains(&count) || block_size == 0 {
                    fail!(InvalidData, "Invalid hierarchical SHA256 header");
                }
                let levels = (0..count)
                    .map(|l| {
                        let o = 0x30 + l * 0x10;
                        let size = u64_le(raw, o + 8);
                        HashLevel {
                            offset: u64_le(raw, o),
                            size,
                            block_size: if l == 0 { size.max(1) } else { block_size },
                        }
                    })
                    .collect::<Vec<_>>();
                (levels, master, false)
            }
            HashType::IVFC => {
                if &raw[0x08..0x0C] != b"IVFC" {
                    fail!(InvalidMagic, "Invalid IVFC header");
                }
                let count = u32_le(raw, 0x14) as usize;
                if !(2..=7).contains(&count) {
                    fail!(InvalidData, "Invalid IVFC level count");
                }
                let levels = (0..count - 1)
                    .map(|l| {
                        let o = 0x18 + l * 0x18;
                        HashLevel {
                            offset: u64_le(raw, o),
                            size: u64_le(raw, o + 8),
                            block_size: 1u64 << u32_le(raw, o + 0x10).min(31),
                        }
                    })
                    .collect::<Vec<_>>();
                (levels, array_at(raw, 0xC8)?, true)
            }
            t => fail!(Unsupported, "Unsupported hash type {}", t.0),
        };
        for l in &levels {
            if !in_range(l.offset, l.size, base.size) {
                fail!(OutOfRange, "Hash level out of range");
            }
        }
        let verified = VerifiedStorage {
            base,
            levels,
            master_hash,
            zero_pad,
            cache: Default::default(),
        };
        Ok(SectionReader(match fsh.compression_info() {
            Some(info) => Layer::Compressed(CompressedStorage::open(verified, info)?),
            None => Layer::Verified(verified),
        }))
    }
}

/// The hash-verified data of an NCA section, decompressed when the section
/// has a compression layer. Returned by [`Nca::open_section`].
pub struct SectionReader<'a, S>(Layer<'a, S>);

enum Layer<'a, S> {
    Verified(VerifiedStorage<'a, S>),
    Compressed(CompressedStorage<'a, S>),
}

impl<S: ReadAt> ReadAt for SectionReader<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match &self.0 {
            Layer::Verified(v) => v.read_at(offset, buf),
            Layer::Compressed(c) => c.read_at(offset, buf),
        }
    }
    fn size(&self) -> Result<u64> {
        match &self.0 {
            Layer::Verified(v) => v.size(),
            Layer::Compressed(c) => c.size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two level SHA256 tree over `data`: its hash at 0, then the data.
    fn tree(data: &[u8]) -> Vec<u8> {
        let mut v = Sha256::digest(data).to_vec();
        v.extend_from_slice(data);
        v
    }

    fn verified(backing: &Vec<u8>) -> VerifiedStorage<'_, Vec<u8>> {
        let data_len = backing.len() as u64 - 32;
        VerifiedStorage {
            base: SectionStorage {
                nca: backing,
                start: 0,
                size: backing.len() as u64,
                ctr: None,
            },
            levels: vec![
                HashLevel {
                    offset: 0,
                    size: 32,
                    block_size: 32,
                },
                HashLevel {
                    offset: 32,
                    size: data_len,
                    block_size: data_len.max(1),
                },
            ],
            master_hash: Sha256::digest(&backing[..32]).into(),
            zero_pad: false,
            cache: Default::default(),
        }
    }

    /// CompressionInfo for a table at offset 0.
    fn info(table_size: u64, count: u32) -> Vec<u8> {
        let mut i = vec![0u8; 0x28];
        i[8..16].copy_from_slice(&table_size.to_le_bytes());
        i[0x10..0x14].copy_from_slice(b"BKTR");
        i[0x18..0x1C].copy_from_slice(&count.to_le_bytes());
        i
    }

    #[test]
    fn short_hash_level_is_an_error() {
        // Level 0 holds 0x30 bytes but block 2 of level 1 needs the hash at 0x40.
        let level0: Vec<u8> = (0..0x30).collect();
        let mut backing = level0.clone();
        backing.resize(0x40 + 0x30, 0);
        let mut padded = level0;
        padded.resize(0x4000, 0);
        let v = VerifiedStorage {
            base: SectionStorage {
                nca: &backing,
                start: 0,
                size: backing.len() as u64,
                ctr: None,
            },
            levels: vec![
                HashLevel {
                    offset: 0,
                    size: 0x30,
                    block_size: 0x4000,
                },
                HashLevel {
                    offset: 0x40,
                    size: 0x30,
                    block_size: 0x10,
                },
            ],
            master_hash: Sha256::digest(&padded).into(),
            zero_pad: true,
            cache: Default::default(),
        };
        assert!(matches!(v.read_vec(0x20, 0x10), Err(Error::OutOfRange(_))));
    }

    #[test]
    fn bad_compression_tables_are_errors() {
        let backing = tree(&vec![0u8; 0x4000]);
        let huge = CompressedStorage::open(verified(&backing), &info(u64::MAX, u32::MAX));
        assert!(huge.is_err());

        let mut l1 = vec![0u8; 0x4000];
        l1[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        let backing = tree(&l1);
        let empty = CompressedStorage::open(verified(&backing), &info(0x4000, 0));
        assert!(matches!(empty, Err(Error::InvalidData(_))));
    }

    #[test]
    fn compressed_reads_span_entries() {
        let mut data = vec![0u8; 0x8000];
        data[8..16].copy_from_slice(&0x20u64.to_le_bytes());
        let set = &mut data[0x4000..];
        set[4..8].copy_from_slice(&2u32.to_le_bytes());
        let e = &mut set[BKTR_NODE_HEADER..];
        e[8..16].copy_from_slice(&0x8000u64.to_le_bytes());
        e[0x10] = COMPRESSION_NONE;
        let e = &mut e[COMPRESSED_ENTRY_SIZE..];
        e[..8].copy_from_slice(&0x10u64.to_le_bytes());
        e[0x10] = COMPRESSION_ZEROS;
        data.extend(1..=16u8);
        let backing = tree(&data);
        let c = CompressedStorage::open(verified(&backing), &info(0x8000, 2)).unwrap();
        let mut want: Vec<u8> = (9..=16).collect();
        want.extend([0; 8]);
        assert_eq!(c.read_vec(8, 16).unwrap(), want);
        assert!(c.read_vec(0x18, 9).is_err());
    }

    #[test]
    fn oversized_lz4_entry_is_an_error() {
        // One LZ4 entry of 0x10 packed bytes claiming 1 TiB of output.
        let mut data = vec![0u8; 0x8000];
        data[8..16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        let set = &mut data[0x4000..];
        set[4..8].copy_from_slice(&1u32.to_le_bytes());
        let e = &mut set[BKTR_NODE_HEADER..];
        e[8..16].copy_from_slice(&0x8000u64.to_le_bytes());
        e[0x10] = COMPRESSION_LZ4;
        e[0x14..0x18].copy_from_slice(&0x10u32.to_le_bytes());
        data.extend([0; 0x10]);
        let backing = tree(&data);
        let c = CompressedStorage::open(verified(&backing), &info(0x8000, 1)).unwrap();
        assert!(matches!(c.read_vec(0, 1), Err(Error::InvalidData(_))));
    }

    #[test]
    fn section_index_past_the_header() {
        assert!(SectionIndex::new(3).is_some());
        assert!(SectionIndex::new(4).is_none());
        assert!(matches!(
            SectionIndex::try_from(4),
            Err(Error::OutOfRange(_))
        ));
        assert_eq!(SectionIndex::all().count(), SectionIndex::COUNT);
    }

    #[test]
    fn header_moduli_decode() {
        assert_eq!(NCA_HEADER_MODULI[0][..2], [0xbf, 0xbe]);
        assert_eq!(NCA_HEADER_MODULI[1][255], 0xad);
    }
}
