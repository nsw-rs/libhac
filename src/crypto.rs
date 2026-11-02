// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AES-128 modes and RSA signature checks used by the Switch formats.

use aes::Aes128;
use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rsa::{BigUint, Pss, RsaPublicKey};
use sha2::{Digest, Sha256};

fn aes(key: &[u8; 16]) -> Aes128 {
    Aes128::new(&(*key).into())
}

/// AES-128-ECB decryption in place. A trailing partial block is left as is.
pub fn aes_ecb_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let c = aes(key);
    for chunk in data.as_chunks_mut::<16>().0 {
        let mut b = Block::<Aes128>::from(*chunk);
        c.decrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }
}

/// AES-XTS decryption with Nintendo's big-endian sector number tweak.
///
/// # Panics
/// When `sector_size` is 0.
pub fn aes_xts_decrypt(key: &[u8; 32], data: &mut [u8], sector_size: usize, first_sector: u128) {
    assert!(sector_size > 0, "AES-XTS sector size is 0");
    let (halves, _) = key.as_chunks::<16>();
    let data_cipher = aes(&halves[0]);
    let tweak_cipher = aes(&halves[1]);
    for (i, sector) in data.chunks_mut(sector_size).enumerate() {
        let mut t = Block::<Aes128>::from((first_sector + i as u128).to_be_bytes());
        tweak_cipher.encrypt_block(&mut t);
        let mut tweak: [u8; 16] = t.into();
        for chunk in sector.as_chunks_mut::<16>().0 {
            let mut blk = Block::<Aes128>::from(std::array::from_fn(|k| chunk[k] ^ tweak[k]));
            data_cipher.decrypt_block(&mut blk);
            for k in 0..16 {
                chunk[k] = blk[k] ^ tweak[k];
            }
            // Multiply the tweak by x in GF(2^128), little-endian convention.
            let carry = tweak[15] >> 7;
            for k in (1..16).rev() {
                tweak[k] = (tweak[k] << 1) | (tweak[k - 1] >> 7);
            }
            tweak[0] = (tweak[0] << 1) ^ (carry * 0x87);
        }
    }
}

/// An AES-128-CTR key and the high half of its counter, with the key
/// schedule expanded once.
#[derive(Clone)]
pub struct CtrKey {
    cipher: Aes128,
    upper: [u8; 8],
}

impl std::fmt::Debug for CtrKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrKey(..)")
    }
}

impl CtrKey {
    /// Expand `key`; `upper` is the high half of every counter block.
    pub fn new(key: &[u8; 16], upper: [u8; 8]) -> Self {
        CtrKey {
            cipher: aes(key),
            upper,
        }
    }

    /// AES-CTR over `data`, which starts at stream offset `offset`.
    /// The counter is `upper` followed by the big-endian block index. An
    /// unaligned `offset` skips the first `offset % 16` keystream bytes.
    pub fn apply(&self, offset: u64, data: &mut [u8]) {
        // Keystream blocks encrypted per call, so the cipher can use its
        // parallel (pipelined) path.
        const BATCH: usize = 32;
        let mut ks: [Block<Aes128>; BATCH] = std::array::from_fn(|_| Block::<Aes128>::default());
        let mut skip = (offset % 16) as usize;
        let mut data = data;
        let mut counter = offset / 16;
        while !data.is_empty() {
            let blocks = (skip + data.len()).div_ceil(16).min(BATCH);
            for b in &mut ks[..blocks] {
                b[..8].copy_from_slice(&self.upper);
                b[8..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);
            }
            self.cipher.encrypt_blocks(&mut ks[..blocks]);
            let n = data.len().min(blocks * 16 - skip);
            let (chunk, rest) = data.split_at_mut(n);
            let stream = ks[..blocks].iter().flat_map(|b| b.iter()).skip(skip);
            for (d, k) in chunk.iter_mut().zip(stream) {
                *d ^= k;
            }
            data = rest;
            skip = 0;
        }
    }
}

/// RSA-PSS SHA256 verification with public exponent 65537.
pub fn verify_rsa_pss(modulus: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(modulus), BigUint::from(65537u32))
    else {
        return false;
    };
    let hash = Sha256::digest(message);
    key.verify(Pss::new::<Sha256>(), &hash, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_is_an_involution_at_any_aligned_offset() {
        let key = [7u8; 16];
        let upper = [1u8; 8];
        let plain: Vec<u8> = (0..64).collect();
        let mut whole = plain.clone();
        CtrKey::new(&key, upper).apply(0x100, &mut whole);
        // Decrypting the second half alone must use the right counter.
        let mut half = whole[32..].to_vec();
        CtrKey::new(&key, upper).apply(0x120, &mut half);
        assert_eq!(half, plain[32..]);
        // So must an unaligned start.
        let mut odd = whole[13..50].to_vec();
        CtrKey::new(&key, upper).apply(0x10d, &mut odd);
        assert_eq!(odd, plain[13..50]);
    }

    #[test]
    fn ctr_batches_match_single_blocks() {
        let key = [3u8; 16];
        let upper = [9u8; 8];
        // Unaligned and longer than one keystream batch.
        let mut whole = vec![0u8; 0x1234];
        CtrKey::new(&key, upper).apply(0x75, &mut whole);
        for (i, chunk) in whole.chunks(7).enumerate() {
            let mut part = vec![0u8; chunk.len()];
            CtrKey::new(&key, upper).apply(0x75 + i as u64 * 7, &mut part);
            assert_eq!(part, chunk);
        }
    }
}
