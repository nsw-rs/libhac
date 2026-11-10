// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers shared by the unit tests.

/// Modulus of a throwaway RSA-2048 key made for these tests (public
/// exponent 65537).
pub const RSA_N: &str = "bbb04636df8afa0ab709eca78d45ebd7fce0b0f8fde4c58af3de1d266b34fe47a2f03472f16fda84b47832c03cd4997ac8f751d176a8d3e90b3d3c7e9f5e2ebebef2276fe5649784b75e7b1b9d9a9191dcb33ad5c1f2eff34e55021f04ed0a52a2236891b382f85e88a130faa2bc49a1f9e3dab2092cff1e7e58fe7ba180b9fa285bb85141e2e175a8da12a8bd2da809f51b168dbda20f49f49349a36680efbd9e0faec142555e08b335b7be8ffc390772142134bf82972e335c3e9b1375491902405f7c35c2adbd21999c9c8e85b6176ef755b3c18ec3a719a72281aa4b025a6b34f7419d23bb5fb4a2fdf89db71222ddc46ec2854a0112178868a1bbcfb6f9";

/// Private exponent of that key.
pub const RSA_D: &str = "25f5de0da522cfb5b11591c6c59cf9b9628cf35e38c3b76c862c4b4b04eddfec0f3973f23780befa8e21ad6a122391b332c84ac509b1d5c251a29e04a229035d52f359249989c1d776dae61d4cc0016735f30e1843b4e5f118cbbab51962f3ee889a8ec0c144e10505af4c5fb4e04e2833897127071211bb52249fbbd38b5c91b238d720144025b569c0b4bc959dabe65ce064c229ea33a2a472856b1f8dd7a6db989aa3c4eb442c4802bb771ba96c0c34d73a0045d738e537ab4cdde688fc8cd16f25c0c3dd6133f85157cda553e5167c5de6f9ebf83ef910b5ea5f08c8c4492bba77245e799007dd6ef583a2de2412ee01be3f1bfc0ba16ec98b792c35f1bd";

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

/// Read 0x40 bytes at the start, middle and end of `r`, ignoring errors.
/// For a fuzzed input that opened: its reads must not panic either.
#[cfg(feature = "ncz")]
pub fn probe_reads(r: &impl crate::storage::ReadAt) {
    let size = r.size().unwrap();
    for at in [0, size / 2, size.saturating_sub(0x40)] {
        let mut b = [0u8; 0x40];
        let n = (size - at).min(0x40) as usize;
        let _ = r.read_at(at, &mut b[..n]);
    }
}
