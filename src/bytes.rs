// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Little-endian field readers and C string decoding shared by the parsers.
//! The `*_le` readers panic on a short slice, so they are only used where
//! the length was checked first; the `*_at` readers fail instead.

use crate::error::{Result, fail};

pub fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

pub fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub fn u64_le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// The `N` bytes at `o`, failing with [`crate::Error::OutOfRange`] on a
/// short slice.
pub fn array_at<const N: usize>(b: &[u8], o: usize) -> Result<[u8; N]> {
    match o.checked_add(N).and_then(|end| b.get(o..end)) {
        Some(s) => Ok(s.try_into().unwrap()),
        None => fail!(OutOfRange, "field at {o:#x} out of range"),
    }
}

pub fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    array_at(b, o).map(u32::from_le_bytes)
}

pub fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    array_at(b, o).map(u64::from_le_bytes)
}

/// Bytes up to the first NUL (or the whole slice).
pub fn c_str(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

/// Text up to the first NUL (or the whole slice), decoded lossily.
pub fn c_string(b: &[u8]) -> String {
    String::from_utf8_lossy(c_str(b)).into_owned()
}

/// Define a `#[repr(transparent)]` newtype over an on-disk integer field
/// with named associated constants. Unknown values are kept as they are.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        pub struct $name:ident($repr:ty) {
            $( $(#[$cmeta:meta])* $konst:ident = $value:expr => $text:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            $(
                $(#[$cmeta])*
                #[doc = concat!("`", $text, "`.")]
                pub const $konst: Self = Self($value);
            )*

            /// Name of a known value.
            pub fn name(self) -> Option<&'static str> {
                match self {
                    $( Self::$konst => Some($text), )*
                    _ => None,
                }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.name() {
                    Some(n) => f.write_str(n),
                    None => write!(f, concat!(stringify!($name), "({:#x})"), self.0),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.name() {
                    Some(n) => f.write_str(n),
                    None => write!(f, "{:#x}", self.0),
                }
            }
        }

        impl From<$repr> for $name {
            fn from(v: $repr) -> Self {
                Self(v)
            }
        }

        impl From<$name> for $repr {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}
pub(crate) use open_enum;
