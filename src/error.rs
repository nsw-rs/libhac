// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error type shared by every module.

use std::path::PathBuf;

/// Errors returned by the parsers and storages. The message of each variant
/// is the full human readable description.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    /// An I/O error of the underlying storage.
    Io(#[from] std::io::Error),
    /// The keys file could not be read.
    #[error("failed to read keys file {}", path.display())]
    ReadKeys {
        /// Path of the keys file.
        path: PathBuf,
        #[source]
        /// Why it could not be read.
        source: std::io::Error,
    },
    /// A read or a table entry points outside its source.
    #[error("{0}")]
    OutOfRange(String),
    /// A header does not start with the expected magic.
    #[error("{0}")]
    InvalidMagic(String),
    /// A structure is malformed.
    #[error("{0}")]
    InvalidData(String),
    /// A valid structure uses a feature that is not implemented.
    #[error("{0}")]
    Unsupported(String),
    /// A key line of a keys file could not be parsed.
    #[error("{0}")]
    InvalidKey(String),
    /// A required key is missing from the key set.
    #[error("{0}")]
    MissingKey(String),
    /// The title key named by the value (a rights ID in upper-case hex, or
    /// `titlekek_XX` for a missing title KEK) is not available, like
    /// LibHac `MissingKeyException.Name`.
    #[error("Missing title key {0}")]
    MissingTitleKey(String),
    /// A hash tree block does not match its parent hash.
    #[error("hash mismatch in level {level} block {block}")]
    HashMismatch {
        /// Hash tree level, 0 for the top.
        level: usize,
        /// Block index within the level.
        block: u64,
    },
}

impl Error {
    /// The same error with `prefix: ` in front of its message. I/O errors
    /// are kept as they are, so callers can still tell them apart.
    pub fn prefixed(self, prefix: &str) -> Self {
        let p = |m: String| format!("{prefix}: {m}");
        match self {
            Error::OutOfRange(m) => Error::OutOfRange(p(m)),
            Error::InvalidMagic(m) => Error::InvalidMagic(p(m)),
            Error::InvalidData(m) => Error::InvalidData(p(m)),
            Error::Unsupported(m) => Error::Unsupported(p(m)),
            e => e,
        }
    }
}

/// `Result` with [`Error`] as the default error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `return Err(Error::$kind(format!(...)))`.
macro_rules! fail {
    ($kind:ident, $($arg:tt)*) => {
        return Err($crate::Error::$kind(format!($($arg)*)))
    };
}
pub(crate) use fail;
