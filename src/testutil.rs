// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers shared by the unit tests.

/// xorshift64*, enough for test data.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    #[cfg_attr(not(feature = "ncz"), allow(dead_code))]
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
}

/// Run `parse` on every prefix of the valid `sample` and on seeded random
/// corruptions of it (a few bytes replaced, or a 32-bit field set to an
/// extreme value). A parser that panics fails the calling test; one that
/// tries a huge allocation aborts it.
pub fn fuzz(sample: &[u8], seed: u64, mut parse: impl FnMut(&[u8])) {
    for n in 0..sample.len() {
        parse(&sample[..n]);
    }
    let mut rng = Rng(seed | 1);
    let mut b = sample.to_vec();
    for _ in 0..3000 {
        b.copy_from_slice(sample);
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(b.len());
            if rng.below(4) == 0 && i + 4 <= b.len() {
                let v: u32 = [0, 1, 0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000][rng.below(5)];
                b[i..i + 4].copy_from_slice(&v.to_le_bytes());
            } else {
                b[i] = rng.next() as u8;
            }
        }
        parse(&b);
    }
}
