// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! eTicket parsing and serialization, matching LibHac `Tools.Es.Ticket`.

use crate::bytes::{array_at, c_str, open_enum, u16_le, u32_le, u64_le};
use crate::error::{Result, fail};
use crate::keys::Keys;
use crate::types::{KeyGeneration, RightsId};
use rsa::{BigUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;

open_enum! {
    /// Ticket signature type (`TicketSigType`).
    pub struct SignatureType(u32) {
        RSA4096_SHA1 = 0x10000 => "Rsa4096Sha1",
        RSA2048_SHA1 = 0x10001 => "Rsa2048Sha1",
        ECDSA_SHA1 = 0x10002 => "EcdsaSha1",
        RSA4096_SHA256 = 0x10003 => "Rsa4096Sha256",
        RSA2048_SHA256 = 0x10004 => "Rsa2048Sha256",
        ECDSA_SHA256 = 0x10005 => "EcdsaSha256",
    }
}

open_enum! {
    /// How the title key is stored in the ticket.
    pub struct TitleKeyType(u8) {
        COMMON = 0 => "Common",
        PERSONALIZED = 1 => "Personalized",
    }
}

open_enum! {
    /// Ticket license type.
    pub struct LicenseType(u8) {
        PERMANENT = 0 => "Permanent",
        DEMO = 1 => "Demo",
        TRIAL = 2 => "Trial",
        RENTAL = 3 => "Rental",
        SUBSCRIPTION = 4 => "Subscription",
        SERVICE = 5 => "Service",
    }
}

impl SignatureType {
    /// Signature size in bytes, `None` for an unknown type.
    pub fn signature_len(self) -> Option<usize> {
        match self.0 {
            0x10000 | 0x10003 => Some(0x200),
            0x10001 | 0x10004 => Some(0x100),
            0x10002 | 0x10005 => Some(0x3C),
            _ => None,
        }
    }
}

/// Offset of the ticket body for a signature of `sig_len` bytes. LibHac
/// skips 0x3C bytes after an RSA signature and 0x40 after an ECDSA one, so
/// the body starts at 0x80 for ECDSA, not 0x40.
fn body_offset(sig_len: usize) -> usize {
    4 + sig_len + if sig_len == 0x3C { 0x40 } else { 0x3C }
}

/// An eTicket.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ticket {
    /// Signature type.
    pub signature_type: SignatureType,
    /// Signature over the ticket body.
    pub signature: Vec<u8>,
    /// Issuer, like `Root-CA00000003-XS00000020`, without the NUL padding.
    pub issuer: Vec<u8>,
    /// Title key: 16 bytes for a common ticket, an RSA-OAEP block of
    /// 0x100 bytes for a personalized one.
    pub title_key_block: Vec<u8>,
    /// Ticket format version.
    pub format_version: u8,
    /// Common or personalized title key.
    pub title_key_type: TitleKeyType,
    /// Ticket version.
    pub ticket_version: u16,
    /// License type.
    pub license_type: LicenseType,
    /// Key generation of the title key.
    pub crypto_type: KeyGeneration,
    /// Property flags (pre-install, shared title, all contents, ...).
    pub property_mask: u32,
    /// Ticket ID.
    pub ticket_id: u64,
    /// Console device ID of a personalized ticket.
    pub device_id: u64,
    /// Rights ID the title key belongs to.
    pub rights_id: RightsId,
    /// Account ID of a personalized ticket.
    pub account_id: u32,
    /// Total size of the section records.
    pub sect_total_size: u32,
    /// Offset of the section records (the ticket size without them).
    pub sect_header_offset: u32,
    /// Number of section records.
    pub sect_num: u16,
    /// Size of one section record.
    pub sect_entry_size: u16,
    /// LibHac `Ticket.File`: the first `sect_header_offset` bytes of the ticket.
    pub file: Vec<u8>,
}

/// Shows what identifies the ticket. The title key block is left out, and
/// so are the signature and the raw bytes, which hold the key too.
impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("signature_type", &self.signature_type)
            .field("issuer", &String::from_utf8_lossy(&self.issuer))
            .field("format_version", &self.format_version)
            .field("title_key_type", &self.title_key_type)
            .field("ticket_version", &self.ticket_version)
            .field("license_type", &self.license_type)
            .field("crypto_type", &self.crypto_type)
            .field("property_mask", &self.property_mask)
            .field("ticket_id", &self.ticket_id)
            .field("device_id", &self.device_id)
            .field("rights_id", &self.rights_id)
            .field("account_id", &self.account_id)
            .field("sect_total_size", &self.sect_total_size)
            .field("sect_header_offset", &self.sect_header_offset)
            .field("sect_num", &self.sect_num)
            .field("sect_entry_size", &self.sect_entry_size)
            .finish_non_exhaustive()
    }
}

impl Ticket {
    /// Parse a ticket file.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 4 {
            fail!(InvalidData, "ticket too small");
        }
        let signature_type = SignatureType(u32_le(b, 0));
        let Some(sig_len) = signature_type.signature_len() else {
            fail!(
                Unsupported,
                "unknown ticket signature type {:#x}",
                signature_type.0
            );
        };
        let body = body_offset(sig_len);
        if b.len() < body + 0x180 {
            fail!(InvalidData, "ticket too small");
        }
        let d = &b[body..];
        let sect_header_offset = u32_le(d, 0x178);
        let file_len = (sect_header_offset as usize).min(b.len());
        Ok(Ticket {
            signature_type,
            signature: b[4..4 + sig_len].to_vec(),
            issuer: c_str(&d[..0x40]).to_vec(),
            title_key_block: d[0x40..0x140].to_vec(),
            format_version: d[0x140],
            title_key_type: TitleKeyType(d[0x141]),
            ticket_version: u16_le(d, 0x142),
            license_type: LicenseType(d[0x144]),
            crypto_type: KeyGeneration(d[0x145]),
            property_mask: u32_le(d, 0x146),
            ticket_id: u64_le(d, 0x150),
            device_id: u64_le(d, 0x158),
            rights_id: RightsId(array_at(d, 0x160)?),
            account_id: u32_le(d, 0x170),
            sect_total_size: u32_le(d, 0x174),
            sect_header_offset,
            sect_num: u16_le(d, 0x17C),
            sect_entry_size: u16_le(d, 0x17E),
            file: b[..file_len].to_vec(),
        })
    }

    /// A normalised common ticket, as NSFW writes into Standard NSPs (port
    /// of `NsfwUtilities.CreateTicket`).
    pub fn create(
        master_key_revision: u8,
        rights_id: RightsId,
        title_key_enc: &[u8],
        signature: Vec<u8>,
    ) -> Self {
        // Key generation is revision + 1, but 0 below 3 and for revision
        // 255, which would wrap.
        let key_gen = match master_key_revision {
            2..=254 => master_key_revision + 1,
            _ => 0,
        };
        Ticket {
            signature_type: SignatureType::RSA2048_SHA256,
            signature,
            issuer: b"Root-CA00000003-XS00000020".to_vec(),
            title_key_block: title_key_enc.to_vec(),
            format_version: 2,
            title_key_type: TitleKeyType::COMMON,
            ticket_version: 0,
            license_type: LicenseType::PERMANENT,
            crypto_type: KeyGeneration(key_gen),
            property_mask: 0,
            ticket_id: 0,
            device_id: 0,
            rights_id,
            account_id: 0,
            sect_total_size: 0,
            sect_header_offset: 0x2C0,
            sect_num: 0,
            sect_entry_size: 0,
            file: Vec::new(),
        }
    }

    /// Port of LibHac `Ticket.GetBytes`, except that ECDSA tickets put the
    /// body at 0x80 as [`Ticket::parse`] expects; LibHac writes it at 0x40.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_len = self.signature_type.signature_len().unwrap_or(0);
        let body = body_offset(sig_len);
        let mut out = vec![0u8; body + 0x180];
        out[..4].copy_from_slice(&self.signature_type.0.to_le_bytes());
        if self.signature.len() == sig_len {
            out[4..4 + sig_len].copy_from_slice(&self.signature);
        }
        let d = &mut out[body..];
        let n = self.issuer.len().min(0x40);
        d[..n].copy_from_slice(&self.issuer[..n]);
        let n = self.title_key_block.len().min(0x100);
        d[0x40..0x40 + n].copy_from_slice(&self.title_key_block[..n]);
        d[0x140] = self.format_version;
        d[0x141] = self.title_key_type.0;
        d[0x142..0x144].copy_from_slice(&self.ticket_version.to_le_bytes());
        d[0x144] = self.license_type.0;
        d[0x145] = self.crypto_type.0;
        d[0x146..0x14A].copy_from_slice(&self.property_mask.to_le_bytes());
        d[0x150..0x158].copy_from_slice(&self.ticket_id.to_le_bytes());
        d[0x158..0x160].copy_from_slice(&self.device_id.to_le_bytes());
        d[0x160..0x170].copy_from_slice(&self.rights_id.0);
        d[0x170..0x174].copy_from_slice(&self.account_id.to_le_bytes());
        d[0x174..0x178].copy_from_slice(&self.sect_total_size.to_le_bytes());
        d[0x178..0x17C].copy_from_slice(&self.sect_header_offset.to_le_bytes());
        d[0x17C..0x17E].copy_from_slice(&self.sect_num.to_le_bytes());
        d[0x17E..0x180].copy_from_slice(&self.sect_entry_size.to_le_bytes());
        out
    }

    /// Encrypted title key (LibHac `Ticket.GetTitleKey`): common tickets hold
    /// it directly, personalized ones need the eTicket RSA key (OAEP-SHA256).
    pub fn title_key(&self, keys: &Keys) -> Option<[u8; 16]> {
        if self.title_key_type == TitleKeyType::COMMON {
            return array_at(&self.title_key_block, 0).ok();
        }
        let kp = keys.eticket_rsa_keypair.as_ref()?;
        if kp.len() < 0x204 {
            return None;
        }
        let d = BigUint::from_bytes_be(&kp[..0x100]);
        let n = BigUint::from_bytes_be(&kp[0x100..0x200]);
        let e = BigUint::from_bytes_be(&kp[0x200..0x204]);
        let key = RsaPrivateKey::from_components(n, e, d, vec![]).ok()?;
        let dec = key
            .decrypt(Oaep::new::<Sha256>(), &self.title_key_block)
            .ok()?;
        array_at(&dec, 0).ok()
    }

    /// Port of `NsfwUtilities.ValidateTicket`: RSA-PKCS#1 v1.5 SHA256 over
    /// the ticket body, using the key at offset 1480 of the common cert.
    ///
    /// The body is taken at 0x140 of the bytes given to [`Ticket::parse`]
    /// ([`Ticket::file`]), whatever the signature type says. So only a
    /// ticket with an RSA-2048 signature can pass, a change to the public
    /// fields after the parse is not seen, and a ticket from
    /// [`Ticket::create`], which has no such bytes, never passes.
    pub fn verify_signature(&self, cert: &[u8]) -> bool {
        let (Some(m), Some(e)) = (cert.get(1480..1480 + 256), cert.get(1736..1740)) else {
            return false;
        };
        let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(m), BigUint::from_bytes_be(e))
        else {
            return false;
        };
        let Some(message) = self.file.get(0x140..) else {
            return false;
        };
        let hash = Sha256::digest(message);
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &self.signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{RSA_D, RSA_N};

    #[test]
    fn create_layout() {
        let t = Ticket::create(9, RightsId([0xAB; 16]), &[0x11; 16], vec![0xFF; 0x100]);
        let b = t.to_bytes();
        assert_eq!(b.len(), 0x2C0);
        assert_eq!(&b[..4], &[4, 0, 1, 0]);
        assert!(b[4..0x104].iter().all(|&x| x == 0xFF));
        assert_eq!(&b[0x140..0x15A], b"Root-CA00000003-XS00000020");
        assert_eq!(&b[0x180..0x190], &[0x11; 16]);
        assert_eq!(b[0x280], 2);
        assert_eq!(b[0x285], 10);
        assert_eq!(&b[0x2A0..0x2B0], &[0xAB; 16]);
        assert_eq!(&b[0x2B8..0x2BC], &[0xC0, 2, 0, 0]);
        let p = Ticket::parse(&b).unwrap();
        assert_eq!(p.to_bytes(), b);
    }

    #[test]
    fn ecdsa_round_trip() {
        let mut b = vec![0u8; 0x80 + 0x180];
        b[..4].copy_from_slice(&0x10005u32.to_le_bytes());
        b[4..0x40].fill(0x5A);
        b[0x80..0x8F].copy_from_slice(b"Root-CA00000003");
        b[0x80 + 0x160..0x80 + 0x170].copy_from_slice(&[0xCD; 16]);
        let t = Ticket::parse(&b).unwrap();
        assert_eq!(t.rights_id, RightsId([0xCD; 16]));
        assert_eq!(t.to_bytes(), b);
    }

    /// A signature and an OAEP block made by another implementation with
    /// the test key.
    #[test]
    fn signature() {
        let mut cert = vec![0u8; 1740];
        cert[1480..1736].copy_from_slice(&hex::decode(RSA_N).unwrap());
        cert[1736..].copy_from_slice(&[0, 1, 0, 1]);
        let sig = hex::decode("92585d030f75f4e2e3bc88f2e97d2fc6b21c123e254a99fb949bd6fd94da9e34cb1378ff3d010db2ea632b3979159d302c0a1be6f970758c7515ce5b277cd1268a50ee0a7dad25abb7db46d6ae6f2b297c3186691d4e2a148dbee02756a20eec02f782962116b5ca24613bc4ee8e984cf73420ebed0a52b1211d054298ce73b2ea83a06cd1e6fc56812ba088bda263a1c112b6ff77cff849a27cb9b32eafa4d07036605d727368834ad0f5a62140dbcb62f849a519f7b7c6c3271809ff39496200dc7390f05ebe920b88557d9af3f5be110be24ad1b04b08bb2f7f00dea4ab5a23a36319ee4e63e7aa5968910b75fc1ca20107cf4b09ed7cb12fc5929b1a1755").unwrap();
        let made = Ticket::create(9, RightsId([0xAB; 16]), &[0x11; 16], sig);
        let b = made.to_bytes();
        let t = Ticket::parse(&b).unwrap();
        assert!(t.verify_signature(&cert));
        assert!(!t.verify_signature(&cert[..1739]));
        // Not parsed: no bytes to check.
        assert!(!made.verify_signature(&cert));
        for at in [4, 0x140, 0x2A0] {
            let mut bad = b.clone();
            bad[at] ^= 1;
            let t = Ticket::parse(&bad).unwrap();
            assert!(!t.verify_signature(&cert), "byte {at:#x}");
        }
    }

    #[test]
    fn title_keys() {
        let mut keys = Keys::with_header_key([0; 32]);
        let mut t = Ticket::create(9, RightsId([0xAB; 16]), &[0x11; 16], vec![0; 0x100]);
        assert_eq!(t.title_key(&keys), Some([0x11; 16]));

        t.title_key_type = TitleKeyType::PERSONALIZED;
        t.title_key_block = hex::decode("56bccf7268fc52b5549d0e2f5a1e89cfe0b813f862fa64d387c5a9195612f857201e7015718dfb098d124f1c300a6ae85da95707d0920a701737396e0d3a3130bd0d3a817502f3318484f3aab6ad0f16ed0ffe74cec52f461743ad5e42fe893637244aa9ebcefee9a6976978ddce303b6acacc9c49ec92199280835ea8847c02562557f281a06e70371bc9bff8f88538df5b87609455f25cdc432a41e77f4d7976c351397b9b2a415dd32d4c956d624fec5e9f089790cfbf257f5513808d92ce63bd369c1c6ff57bbd1ee04e21208415588a226825ea4b890a0c404196c518613553d7593242773dd026547b91d21e43c0e4323d57c19775b47921e75673f662").unwrap();
        assert_eq!(t.title_key(&keys), None);
        let pair = [RSA_D, RSA_N, "00010001"].concat();
        keys.eticket_rsa_keypair = Some(hex::decode(pair).unwrap());
        let want: [u8; 16] = std::array::from_fn(|i| 0x20 + i as u8);
        assert_eq!(t.title_key(&keys), Some(want));
        t.title_key_block[5] ^= 1;
        assert_eq!(t.title_key(&keys), None);
    }

    #[test]
    fn debug_hides_the_title_key() {
        let b = Ticket::create(9, RightsId([0xAB; 16]), &[0x11; 16], vec![0x22; 0x100]).to_bytes();
        let shown = format!("{:?}", Ticket::parse(&b).unwrap());
        assert!(shown.contains("rights_id") && shown.contains("XS00000020"));
        assert!(
            !shown.contains("17, 17") && !shown.contains("34, 34"),
            "{shown}"
        );
    }

    #[test]
    fn fuzz_no_panic() {
        let t = Ticket::create(9, RightsId([0xAB; 16]), &[0x11; 16], vec![0xFF; 0x100]);
        crate::testutil::fuzz(&t.to_bytes(), 17, |b| {
            if let Ok(t) = Ticket::parse(b) {
                let _ = t.to_bytes();
            }
        });
    }
}
