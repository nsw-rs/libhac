// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Readers for Nintendo Switch file formats, ported from LibHac.
//!
//! The entry point is usually [`nca::Nca`]: open it on any [`ReadAt`]
//! storage (a [`std::fs::File`], a byte slice, or a [`SubStorage`] range of
//! a PFS0 such as an NSP), with keys from [`Keys::load`].

#![warn(missing_docs)]

mod bytes;
pub mod cnmt;
pub mod crypto;
mod error;
#[cfg(feature = "ncz")]
pub mod image;
pub mod keys;
pub mod nacp;
pub mod nca;
#[cfg(feature = "ncz")]
pub mod ncz;
pub mod npdm;
pub mod partition;
pub mod pfs0;
pub mod romfs;
pub mod storage;
#[cfg(test)]
mod testutil;
pub mod ticket;
mod types;
pub mod xci;

pub use error::{Error, Result};
pub use keys::Keys;
pub use storage::{ReadAt, SubStorage};
pub use types::{KeyGeneration, NcaId, RightsId, TitleId};
