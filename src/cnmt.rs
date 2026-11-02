// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packaged content meta (`*.cnmt`) parser, matching LibHac `Cnmt`.

use crate::bytes::{array_at, open_enum, u16_le, u32_le, u64_le};
use crate::error::{Result, fail};
use crate::types::{NcaId, TitleId};
use std::fmt;
use std::ops::BitOr;

open_enum! {
    /// Content meta type (`ContentMetaType`).
    pub struct MetaType(u8) {
        SYSTEM_PROGRAM = 0x01 => "SystemProgram",
        SYSTEM_DATA = 0x02 => "SystemData",
        SYSTEM_UPDATE = 0x03 => "SystemUpdate",
        BOOT_IMAGE_PACKAGE = 0x04 => "BootImagePackage",
        BOOT_IMAGE_PACKAGE_SAFE = 0x05 => "BootImagePackageSafe",
        APPLICATION = 0x80 => "Application",
        PATCH = 0x81 => "Patch",
        ADD_ON_CONTENT = 0x82 => "AddOnContent",
        DELTA = 0x83 => "Delta",
        DATA_PATCH = 0x84 => "DataPatch",
    }
}

open_enum! {
    /// Type of a content entry (`ContentType` in content meta, not the NCA
    /// header content type).
    pub struct ContentEntryType(u8) {
        META = 0 => "Meta",
        PROGRAM = 1 => "Program",
        DATA = 2 => "Data",
        CONTROL = 3 => "Control",
        HTML_DOCUMENT = 4 => "HtmlDocument",
        LEGAL_INFORMATION = 5 => "LegalInformation",
        DELTA_FRAGMENT = 6 => "DeltaFragment",
    }
}

/// Content meta attribute flags (`ContentMetaAttribute`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct ContentAttributes(pub u8);

impl ContentAttributes {
    /// The system update includes the exFAT driver.
    pub const INCLUDES_EX_FAT_DRIVER: Self = Self(1);
    /// The system update can be installed without a reboot.
    pub const REBOOTLESS: Self = Self(2);
    /// The content is compacted.
    pub const COMPACTED: Self = Self(4);

    const NAMES: [(Self, &str); 3] = [
        (Self::INCLUDES_EX_FAT_DRIVER, "IncludesExFatDriver"),
        (Self::REBOOTLESS, "Rebootless"),
        (Self::COMPACTED, "Compacted"),
    ];

    /// True when every flag of `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for ContentAttributes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The names of the set flags joined by `|`, unknown bits in hex.
impl fmt::Debug for ContentAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        let mut sep = "";
        for (flag, name) in Self::NAMES {
            if self.contains(flag) {
                write!(f, "{sep}{name}")?;
                rest &= !flag.0;
                sep = " | ";
            }
        }
        if rest != 0 || sep.is_empty() {
            write!(f, "{sep}{rest:#x}")?;
        }
        Ok(())
    }
}

/// One content (NCA) listed by the content meta.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContentEntry {
    /// SHA-256 of the whole NCA.
    pub hash: [u8; 32],
    /// NCA ID, the first half of `hash` for unmodified NCAs.
    pub nca_id: NcaId,
    /// NCA size in bytes (48-bit on disk).
    pub size: u64,
    /// What the NCA holds.
    pub content_type: ContentEntryType,
    /// Index of the program within a multi-program application.
    pub id_offset: u8,
}

/// A content meta referenced by this one (`ContentMetaInfo`), as listed by
/// system updates.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContentMetaEntry {
    /// Title ID of the referenced content meta.
    pub title_id: TitleId,
    /// Version of the referenced content meta.
    pub version: u32,
    /// Type of the referenced content meta.
    pub meta_type: MetaType,
    /// Attributes of the referenced content meta.
    pub attributes: ContentAttributes,
}

/// The type specific header that follows the fixed CNMT header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtendedHeader {
    /// `ApplicationMetaExtendedHeader`.
    Application {
        /// Title ID of the patch for this application.
        patch_id: TitleId,
        /// Minimum system version needed to run it.
        required_system_version: u32,
        /// Minimum application version (for multi-program titles).
        required_application_version: u32,
    },
    /// `PatchMetaExtendedHeader`.
    Patch {
        /// Title ID of the patched application.
        application_id: TitleId,
        /// Minimum system version needed to run it.
        required_system_version: u32,
        /// Size of the extended data that follows the content meta entries.
        extended_data_size: u32,
    },
    /// `AddOnContentMetaExtendedHeader`.
    AddOnContent {
        /// Title ID of the application this content belongs to.
        application_id: TitleId,
        /// Minimum application version needed to use it.
        required_application_version: u32,
        /// Title ID of the data patch, present in the 0x18 byte header of
        /// newer add-on contents.
        data_patch_id: Option<TitleId>,
    },
    /// `DeltaMetaExtendedHeader`.
    Delta {
        /// Title ID of the application.
        application_id: TitleId,
        /// Size of the extended data that follows the content meta entries.
        extended_data_size: u32,
    },
    /// `DataPatchMetaExtendedHeader`.
    DataPatch {
        /// Title ID of the patched add-on content.
        data_id: TitleId,
        /// Title ID of the application.
        application_id: TitleId,
        /// Minimum application version needed to use it.
        required_application_version: u32,
        /// Size of the extended data that follows the content meta entries.
        extended_data_size: u32,
    },
    /// `SystemUpdateMetaExtendedHeader`.
    SystemUpdate {
        /// Size of the extended data that follows the content meta entries.
        extended_data_size: u32,
    },
    /// No extended header: the meta type has none, or the stored header is
    /// shorter than the layout of its type.
    None,
}

impl ExtendedHeader {
    /// Parse the extended header `h` of a content meta of type `t`.
    fn parse(t: MetaType, h: &[u8]) -> Self {
        let id = |o| TitleId(u64_le(h, o));
        let n = h.len();
        match t {
            MetaType::APPLICATION if n >= 0x10 => Self::Application {
                patch_id: id(0),
                required_system_version: u32_le(h, 8),
                required_application_version: u32_le(h, 0xC),
            },
            MetaType::PATCH if n >= 0x10 => Self::Patch {
                application_id: id(0),
                required_system_version: u32_le(h, 8),
                extended_data_size: u32_le(h, 0xC),
            },
            MetaType::ADD_ON_CONTENT if n >= 0x10 => Self::AddOnContent {
                application_id: id(0),
                required_application_version: u32_le(h, 8),
                data_patch_id: (n >= 0x18).then(|| id(0x10)),
            },
            MetaType::DELTA if n >= 0x10 => Self::Delta {
                application_id: id(0),
                extended_data_size: u32_le(h, 8),
            },
            MetaType::DATA_PATCH if n >= 0x18 => Self::DataPatch {
                data_id: id(0),
                application_id: id(8),
                required_application_version: u32_le(h, 0x10),
                extended_data_size: u32_le(h, 0x14),
            },
            MetaType::SYSTEM_UPDATE if n >= 4 => Self::SystemUpdate {
                extended_data_size: u32_le(h, 0),
            },
            _ => Self::None,
        }
    }

    /// Size of the extended data stored between the content meta entries
    /// and the digest (0 for the types that have none).
    pub fn extended_data_size(&self) -> u32 {
        match *self {
            Self::Patch {
                extended_data_size, ..
            }
            | Self::Delta {
                extended_data_size, ..
            }
            | Self::DataPatch {
                extended_data_size, ..
            }
            | Self::SystemUpdate { extended_data_size } => extended_data_size,
            _ => 0,
        }
    }
}

/// Packaged content meta.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cnmt {
    /// Title ID of this content meta.
    pub title_id: TitleId,
    /// Title version.
    pub title_version: u32,
    /// Content meta type.
    pub meta_type: MetaType,
    /// Content meta attributes.
    pub attributes: ContentAttributes,
    /// Minimum system version needed to download the title.
    pub required_download_system_version: u32,
    /// Type specific header.
    pub extended_header: ExtendedHeader,
    /// The NCAs of the title.
    pub content_entries: Vec<ContentEntry>,
    /// Other content metas referenced by this one.
    pub content_meta_entries: Vec<ContentMetaEntry>,
    /// SHA-256 digest stored at the end, `None` when the file ends before
    /// it.
    pub digest: Option<[u8; 32]>,
    application_title_id: TitleId,
}

/// `start + count * size`, or an error when it overflows or passes `len`.
fn table_end(start: usize, count: usize, size: usize, len: usize, what: &str) -> Result<usize> {
    match count
        .checked_mul(size)
        .and_then(|n| n.checked_add(start))
        .filter(|&end| end <= len)
    {
        Some(end) => Ok(end),
        None => fail!(OutOfRange, "CNMT {what} out of range"),
    }
}

impl Cnmt {
    /// Parse a `*.cnmt` file.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 0x20 {
            fail!(InvalidData, "CNMT too small");
        }
        let title_id = u64_le(b, 0);
        let title_version = u32_le(b, 8);
        let meta_type = MetaType(b[0x0C]);
        let table_offset = u16_le(b, 0x0E) as usize;
        let count = u16_le(b, 0x10) as usize;
        let meta_count = u16_le(b, 0x12) as usize;
        let attributes = ContentAttributes(b[0x14]);
        let required_download_system_version = u32_le(b, 0x18);

        // Like LibHac, read the application ID of patches and add-on
        // contents even when the declared extended header is shorter.
        let application_title_id = TitleId(match meta_type {
            MetaType::APPLICATION => title_id,
            MetaType::PATCH | MetaType::ADD_ON_CONTENT if b.len() >= 0x28 => u64_le(b, 0x20),
            _ => 0,
        });

        let start = 0x20 + table_offset;
        let meta_start = table_end(start, count, 0x38, b.len(), "content entries")?;
        let extended_header = ExtendedHeader::parse(meta_type, &b[0x20..start]);
        let content_entries = b[start..meta_start]
            .as_chunks::<0x38>()
            .0
            .iter()
            .map(|e| ContentEntry {
                hash: e[..0x20].try_into().unwrap(),
                nca_id: NcaId(e[0x20..0x30].try_into().unwrap()),
                // 48-bit size.
                size: u64_le(e, 0x30) & 0xFFFF_FFFF_FFFF,
                content_type: ContentEntryType(e[0x36]),
                id_offset: e[0x37],
            })
            .collect();
        let meta_end = table_end(
            meta_start,
            meta_count,
            0x10,
            b.len(),
            "content meta entries",
        )?;
        let content_meta_entries = b[meta_start..meta_end]
            .as_chunks::<0x10>()
            .0
            .iter()
            .map(|e| ContentMetaEntry {
                title_id: TitleId(u64_le(e, 0)),
                version: u32_le(e, 8),
                meta_type: MetaType(e[0xC]),
                attributes: ContentAttributes(e[0xD]),
            })
            .collect();
        let digest = meta_end
            .checked_add(extended_header.extended_data_size() as usize)
            .and_then(|o| array_at(b, o).ok());

        Ok(Cnmt {
            title_id: TitleId(title_id),
            title_version,
            meta_type,
            attributes,
            required_download_system_version,
            extended_header,
            content_entries,
            content_meta_entries,
            digest,
            application_title_id,
        })
    }

    /// Title ID of the application: the title itself for an application,
    /// the application ID of the extended header for a patch or an add-on
    /// content, 0 otherwise.
    pub fn application_title_id(&self) -> TitleId {
        self.application_title_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fuzz;

    /// A patch with a 0x18 byte extended header, two contents, one content
    /// meta entry, 0x10 bytes of extended data and the digest.
    fn patch_sample() -> Vec<u8> {
        let mut b = vec![0u8; 0x20];
        b[..8].copy_from_slice(&0x0100_0000_0000_0800u64.to_le_bytes());
        b[8..12].copy_from_slice(&0x20000u32.to_le_bytes());
        b[0x0C] = 0x81;
        b[0x0E] = 0x18;
        b[0x10] = 2;
        b[0x12] = 1;
        b[0x18..0x1C].copy_from_slice(&0x1234u32.to_le_bytes());
        b.extend_from_slice(&0x0100_0000_0000_0000u64.to_le_bytes());
        b.extend_from_slice(&0x0C00_0000u32.to_le_bytes());
        b.extend_from_slice(&0x10u32.to_le_bytes());
        b.extend_from_slice(&[0; 8]);
        for (id, ty) in [(0x11, 1), (0x22, 3)] {
            let mut e = [0u8; 0x38];
            e[..0x20].fill(id);
            e[0x20..0x30].fill(id);
            e[0x30] = id;
            e[0x36] = ty;
            e[0x37] = 1;
            b.extend_from_slice(&e);
        }
        b.extend_from_slice(&0x0100_0000_0000_0000u64.to_le_bytes());
        b.extend_from_slice(&0x10000u32.to_le_bytes());
        b.extend_from_slice(&[0x80, 0, 0, 0]);
        b.extend_from_slice(&[0xEE; 0x10]);
        b.extend_from_slice(&[0xDD; 0x20]);
        b
    }

    #[test]
    fn parse_full() {
        let b = patch_sample();
        let c = Cnmt::parse(&b).unwrap();
        assert_eq!(c.required_download_system_version, 0x1234);
        assert_eq!(
            c.extended_header,
            ExtendedHeader::Patch {
                application_id: TitleId(0x0100_0000_0000_0000),
                required_system_version: 0x0C00_0000,
                extended_data_size: 0x10,
            }
        );
        assert_eq!(c.application_title_id(), TitleId(0x0100_0000_0000_0000));
        assert_eq!(c.content_entries.len(), 2);
        assert_eq!(c.content_entries[1].nca_id, NcaId([0x22; 16]));
        assert_eq!(c.content_entries[1].size, 0x22);
        assert_eq!(c.content_entries[1].id_offset, 1);
        assert_eq!(
            c.content_meta_entries,
            [ContentMetaEntry {
                title_id: TitleId(0x0100_0000_0000_0000),
                version: 0x10000,
                meta_type: MetaType::APPLICATION,
                attributes: ContentAttributes(0),
            }]
        );
        assert_eq!(c.digest, Some([0xDD; 0x20]));
        // Without the digest the rest still parses.
        let c = Cnmt::parse(&b[..b.len() - 1]).unwrap();
        assert_eq!(c.digest, None);
        // Missing content meta entries fail.
        assert!(Cnmt::parse(&b[..0x20 + 0x18 + 2 * 0x38 + 8]).is_err());
    }

    #[test]
    fn extended_headers() {
        let h: Vec<u8> = (1..=0x18).collect();
        let id = |o: usize| TitleId(u64::from_le_bytes(h[o..o + 8].try_into().unwrap()));
        let w = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
        assert_eq!(
            ExtendedHeader::parse(MetaType::ADD_ON_CONTENT, &h),
            ExtendedHeader::AddOnContent {
                application_id: id(0),
                required_application_version: w(8),
                data_patch_id: Some(id(0x10)),
            }
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::ADD_ON_CONTENT, &h[..0x10]),
            ExtendedHeader::AddOnContent {
                application_id: id(0),
                required_application_version: w(8),
                data_patch_id: None,
            }
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::DATA_PATCH, &h).extended_data_size(),
            w(0x14)
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::DELTA, &h).extended_data_size(),
            w(8)
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::SYSTEM_UPDATE, &h[..4]),
            ExtendedHeader::SystemUpdate {
                extended_data_size: w(0)
            }
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::APPLICATION, &h[..0xF]),
            ExtendedHeader::None
        );
        assert_eq!(
            ExtendedHeader::parse(MetaType::SYSTEM_PROGRAM, &h),
            ExtendedHeader::None
        );
    }

    #[test]
    fn fuzz_no_panic() {
        fuzz(&patch_sample(), 7, |b| {
            let _ = Cnmt::parse(b);
        });
    }

    #[test]
    fn parse_patch() {
        let mut b = vec![0u8; 0x30 + 0x38];
        b[..8].copy_from_slice(&0x0100_0000_0000_0800u64.to_le_bytes());
        b[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
        b[0x0C] = 0x81;
        b[0x0E] = 0x10;
        b[0x10] = 1;
        b[0x14] = 4;
        b[0x20..0x28].copy_from_slice(&0x0100_0000_0000_0000u64.to_le_bytes());
        let e = &mut b[0x30..];
        e[0x20..0x30].copy_from_slice(&[0xAA; 16]);
        e[0x30..0x36].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        e[0x36] = 6;
        let c = Cnmt::parse(&b).unwrap();
        assert_eq!(c.meta_type, MetaType::PATCH);
        assert_eq!(c.title_version, 0x10000);
        assert_eq!(c.application_title_id(), TitleId(0x0100_0000_0000_0000));
        assert!(c.attributes.contains(ContentAttributes::COMPACTED));
        assert_eq!(c.content_entries.len(), 1);
        assert_eq!(c.content_entries[0].nca_id, NcaId([0xAA; 16]));
        assert_eq!(c.content_entries[0].size, 0x0605_0403_0201);
        assert_eq!(
            c.content_entries[0].content_type,
            ContentEntryType::DELTA_FRAGMENT
        );
        let a = ContentAttributes::REBOOTLESS | ContentAttributes::COMPACTED;
        assert!(a.contains(ContentAttributes::COMPACTED));
        assert_eq!(format!("{a:?}"), "Rebootless | Compacted");
        assert_eq!(
            format!("{:?}", ContentAttributes(0x81)),
            "IncludesExFatDriver | 0x80"
        );
        assert_eq!(format!("{:?}", ContentAttributes(0)), "0x0");
        assert_eq!(format!("{}", MetaType(0x42)), "0x42");
        assert!(Cnmt::parse(&b[..0x40]).is_err());
    }
}
