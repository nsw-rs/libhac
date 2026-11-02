// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key set loaded from a `prod.keys` file.

use crate::error::{Error, Result, fail};
use crate::nca::KeyAreaKeyIndex;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Derived keys read from a `prod.keys` file. Only the keys needed for
/// NCA and ticket decryption are kept.
pub struct Keys {
    /// `header_key`: AES-XTS key of NCA headers.
    pub header_key: [u8; 32],
    /// key_area_key_{application,ocean,system}_XX, indexed [revision][kaek index].
    key_area_keys: HashMap<(u8, u8), [u8; 16]>,
    titlekeks: HashMap<u8, [u8; 16]>,
    /// eticket_rsa_keypair: private exponent (0x100), modulus (0x100), public exponent (4).
    pub eticket_rsa_keypair: Option<Vec<u8>>,
    skipped: Vec<Error>,
}

fn parse_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|e| Error::InvalidKey(format!("invalid hex for key {name}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidKey(format!("key {name} has wrong length")))
}

fn suffix_index(name: &str, prefix: &str) -> Option<u8> {
    let rest = name.strip_prefix(prefix)?;
    u8::from_str_radix(rest, 16).ok()
}

impl Keys {
    /// Load a keys file (`name = hex` lines). Lines that cannot be parsed
    /// are skipped like LibHac does and listed by [`Keys::skipped`].
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::ReadKeys {
            path: path.to_owned(),
            source,
        })?;
        let mut header_key = None;
        let mut key_area_keys = HashMap::new();
        let mut titlekeks = HashMap::new();
        let mut eticket_rsa_keypair = None;
        let mut skipped = Vec::new();

        // A leading UTF-8 BOM would otherwise become part of the first key name.
        for line in text.trim_start_matches('\u{feff}').lines() {
            let Some((name, value)) = line.split_once(['=', ',']) else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            // Like LibHac, skip a key that cannot be parsed instead of
            // rejecting the whole file.
            let parsed = (|| -> Result<()> {
                if name == "header_key" {
                    header_key = Some(parse_hex::<32>(&name, value)?);
                } else if name == "eticket_rsa_keypair" {
                    eticket_rsa_keypair = Some(hex::decode(value).map_err(|e| {
                        Error::InvalidKey(format!("invalid eticket_rsa_keypair: {e}"))
                    })?);
                } else if let Some(i) = suffix_index(&name, "titlekek_") {
                    titlekeks.insert(i, parse_hex::<16>(&name, value)?);
                } else {
                    for (kind, prefix) in [
                        (0u8, "key_area_key_application_"),
                        (1, "key_area_key_ocean_"),
                        (2, "key_area_key_system_"),
                    ] {
                        if let Some(i) = suffix_index(&name, prefix) {
                            key_area_keys.insert((i, kind), parse_hex::<16>(&name, value)?);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(e) = parsed {
                skipped.push(e);
            }
        }

        let Some(header_key) = header_key else {
            fail!(MissingKey, "header_key missing from {}", path.display());
        };
        Ok(Keys {
            header_key,
            key_area_keys,
            titlekeks,
            eticket_rsa_keypair,
            skipped,
        })
    }

    /// Why each skipped line of the keys file was rejected, in file order.
    pub fn skipped(&self) -> &[Error] {
        &self.skipped
    }

    /// Key area key for a master key revision and key area key index.
    pub fn key_area_key(&self, revision: u8, index: KeyAreaKeyIndex) -> Option<&[u8; 16]> {
        self.key_area_keys.get(&(revision, index.0))
    }

    /// Title key encryption key for a master key revision.
    pub fn titlekek(&self, revision: u8) -> Option<&[u8; 16]> {
        self.titlekeks.get(&revision)
    }
}

/// Shows which keys are present, never their values.
impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("key_area_keys", &self.key_area_keys.len())
            .field("titlekeks", &self.titlekeks.len())
            .field("eticket_rsa_keypair", &self.eticket_rsa_keypair.is_some())
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_skips_bad_lines() {
        let dir = std::env::temp_dir().join(format!("libhac-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("prod.keys");
        let text = format!(
            "\u{feff}header_key = {}\ntitlekek_0a = {}\nkey_area_key_ocean_01 = 0g\n",
            "11".repeat(32),
            "22".repeat(16)
        );
        std::fs::write(&path, text).unwrap();
        let keys = Keys::load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(keys.header_key, [0x11; 32]);
        assert_eq!(keys.titlekek(10), Some(&[0x22; 16]));
        assert_eq!(keys.key_area_key(1, KeyAreaKeyIndex::OCEAN), None);
        assert_eq!(keys.skipped().len(), 1);
        assert!(
            keys.skipped()[0]
                .to_string()
                .starts_with("invalid hex for key key_area_key_ocean_01: ")
        );
    }
}
