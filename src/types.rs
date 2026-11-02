// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identifiers shared by several formats.

use std::fmt;

/// A title (program, patch, add-on content, ...) ID. Shown as 16
/// upper-case hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TitleId(pub u64);

impl fmt::Display for TitleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}

impl fmt::Debug for TitleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TitleId({self})")
    }
}

/// The rights ID of an NCA or a ticket, which names its title key. All
/// zero when the NCA does not use title key crypto. Shown as upper-case
/// hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RightsId(pub [u8; 16]);

impl RightsId {
    /// True for the all-zero ID of NCAs without title key crypto.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }

    /// The key generation stored in the last byte.
    pub fn key_generation(&self) -> KeyGeneration {
        KeyGeneration(self.0[15])
    }
}

impl fmt::Display for RightsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode_upper(self.0))
    }
}

impl fmt::Debug for RightsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RightsId({self})")
    }
}

/// The ID of an NCA, the first half of its SHA-256. Shown as lower-case
/// hex, like NCA file names.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct NcaId(pub [u8; 16]);

impl fmt::Display for NcaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NcaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NcaId({self})")
    }
}

/// A key generation, as stored in NCA headers and tickets. Shown as a
/// decimal number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Debug)]
pub struct KeyGeneration(pub u8);

impl KeyGeneration {
    /// The master key revision used by this generation (LibHac
    /// `Utilities.GetMasterKeyRevision`): generations 0 and 1 both use
    /// revision 0.
    pub fn master_key_revision(self) -> u8 {
        self.0.saturating_sub(1)
    }
}

impl fmt::Display for KeyGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        let mut id = [0u8; 16];
        id[0] = 0xab;
        id[15] = 0x0a;
        assert_eq!(RightsId(id).to_string(), "AB00000000000000000000000000000A");
        assert_eq!(NcaId(id).to_string(), "ab00000000000000000000000000000a");
        assert_eq!(RightsId(id).key_generation(), KeyGeneration(10));
        assert!(!RightsId(id).is_zero() && RightsId::default().is_zero());
        assert_eq!(
            TitleId(0x0100_0000_0000_0800).to_string(),
            "0100000000000800"
        );
        assert_eq!(KeyGeneration(0).master_key_revision(), 0);
        assert_eq!(KeyGeneration(11).master_key_revision(), 10);
    }
}
