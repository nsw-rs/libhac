// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application control property (`control.nacp`, LibHac
//! `ApplicationControlProperty`).

use crate::bytes::{c_string, open_enum, u16_le, u32_le, u64_le};
use crate::types::TitleId;

/// Size of the application control property.
pub const NACP_SIZE: usize = 0x4000;

const ATTRIBUTE_DEMO: u32 = 1;
const ATTRIBUTE_RETAIL_INTERACTIVE_DISPLAY: u32 = 2;

/// Application control property, zero-padded to [`NACP_SIZE`] bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Nacp {
    raw: Vec<u8>,
}

impl Nacp {
    /// An all-zero NACP, like LibHac's default `ApplicationControlProperty`.
    pub fn empty() -> Self {
        Self::from_bytes(&[])
    }

    /// Copy of `b`, truncated or zero-padded to [`NACP_SIZE`] bytes.
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut raw = b[..b.len().min(NACP_SIZE)].to_vec();
        raw.resize(NACP_SIZE, 0);
        Nacp { raw }
    }

    /// Title names for the 16 language slots; `None` when the name is empty.
    pub fn titles(&self) -> Vec<Option<String>> {
        (0..16)
            .map(|i| {
                let name = &self.raw[i * 0x300..i * 0x300 + 0x200];
                (name[0] != 0).then(|| c_string(name))
            })
            .collect()
    }

    /// Title name and publisher in language `lang`, `None` when both are
    /// empty.
    pub fn title(&self, lang: Language) -> Option<Title> {
        let t = &self.raw[lang as usize * 0x300..][..0x300];
        (t[0] != 0 || t[0x200] != 0).then(|| Title {
            name: c_string(&t[..0x200]),
            publisher: c_string(&t[0x200..]),
        })
    }

    /// Application version shown to the user, like `1.0.2`.
    pub fn display_version(&self) -> String {
        c_string(&self.raw[0x3060..0x3070])
    }

    /// Attribute flags (bit 0 demo, bit 1 retail interactive display).
    pub fn attribute_flag(&self) -> u32 {
        u32_le(&self.raw, 0x3028)
    }

    /// True for a demo.
    pub fn is_demo(&self) -> bool {
        self.attribute_flag() & ATTRIBUTE_DEMO != 0
    }

    /// True for a retail interactive display (kiosk) build.
    pub fn is_retail_display(&self) -> bool {
        self.attribute_flag() & ATTRIBUTE_RETAIL_INTERACTIVE_DISPLAY != 0
    }

    fn u8_at(&self, o: usize) -> u8 {
        self.raw[o]
    }

    fn u64_at(&self, o: usize) -> u64 {
        u64_le(&self.raw, o)
    }

    /// ISBN, for applications that have one.
    pub fn isbn(&self) -> String {
        c_string(&self.raw[0x3000..0x3025])
    }

    /// Whether a user account must be selected at startup.
    pub fn startup_user_account(&self) -> StartupUserAccount {
        StartupUserAccount(self.u8_at(0x3025))
    }

    /// Supported languages, bit `n` for [`Language`] `n`.
    pub fn supported_language_flag(&self) -> u32 {
        u32_le(&self.raw, 0x302C)
    }

    /// True when the bit of `lang` is set in
    /// [`supported_language_flag`](Self::supported_language_flag).
    pub fn supports_language(&self, lang: Language) -> bool {
        self.supported_language_flag() & (1 << lang as u32) != 0
    }

    /// Parental control flags (bit 0: free communication).
    pub fn parental_control(&self) -> u32 {
        u32_le(&self.raw, 0x3030)
    }

    /// Presence group ID.
    pub fn presence_group_id(&self) -> TitleId {
        TitleId(self.u64_at(0x3038))
    }

    /// Minimum age for each rating organization (CERO, GRAC, GSRMR, ESRB,
    /// ClassInd, USK, PEGI, PEGI Portugal, PEGI BBFC, Russian, ACB, OFLC,
    /// IARC Generic, then reserved); -1 when not rated.
    pub fn rating_age(&self) -> [i8; 32] {
        std::array::from_fn(|i| self.raw[0x3040 + i] as i8)
    }

    /// Base title ID of the add-on contents.
    pub fn add_on_content_base_id(&self) -> TitleId {
        TitleId(self.u64_at(0x3070))
    }

    /// Owner ID of the save data.
    pub fn save_data_owner_id(&self) -> TitleId {
        TitleId(self.u64_at(0x3078))
    }

    /// Size of the user account save data.
    pub fn user_account_save_data_size(&self) -> u64 {
        self.u64_at(0x3080)
    }

    /// Journal size of the user account save data.
    pub fn user_account_save_data_journal_size(&self) -> u64 {
        self.u64_at(0x3088)
    }

    /// Size of the device save data.
    pub fn device_save_data_size(&self) -> u64 {
        self.u64_at(0x3090)
    }

    /// Journal size of the device save data.
    pub fn device_save_data_journal_size(&self) -> u64 {
        self.u64_at(0x3098)
    }

    /// Size of the BCAT delivery cache storage.
    pub fn bcat_delivery_cache_storage_size(&self) -> u64 {
        self.u64_at(0x30A0)
    }

    /// Error code category shown in application error codes.
    pub fn application_error_code_category(&self) -> String {
        c_string(&self.raw[0x30A8..0x30B0])
    }

    /// Local communication (local wireless) IDs.
    pub fn local_communication_ids(&self) -> [u64; 8] {
        std::array::from_fn(|i| self.u64_at(0x30B0 + i * 8))
    }

    /// Kind of logo shown at startup.
    pub fn logo_type(&self) -> LogoType {
        LogoType(self.u8_at(0x30F0))
    }

    /// Whether the application hides the startup logo itself.
    pub fn logo_handling(&self) -> LogoHandling {
        LogoHandling(self.u8_at(0x30F1))
    }

    /// Seed for the pseudo device ID.
    pub fn seed_for_pseudo_device_id(&self) -> u64 {
        self.u64_at(0x30F8)
    }

    /// BCAT passphrase.
    pub fn bcat_passphrase(&self) -> String {
        c_string(&self.raw[0x3100..0x3141])
    }

    /// Size of the cache storage.
    pub fn cache_storage_size(&self) -> u64 {
        self.u64_at(0x3170)
    }

    /// Journal size of the cache storage.
    pub fn cache_storage_journal_size(&self) -> u64 {
        self.u64_at(0x3178)
    }

    /// Largest data plus journal size of a cache storage.
    pub fn cache_storage_data_and_journal_size_max(&self) -> u64 {
        self.u64_at(0x3180)
    }

    /// Largest cache storage index.
    pub fn cache_storage_index_max(&self) -> u16 {
        u16_le(&self.raw, 0x3188)
    }

    /// Program index within a multi-program application.
    pub fn program_index(&self) -> u8 {
        self.u8_at(0x3212)
    }

    /// The raw [`NACP_SIZE`] bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Title name and publisher of one language slot.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Title {
    /// Application name.
    pub name: String,
    /// Publisher name.
    pub publisher: String,
}

/// The 16 language slots of the title table, in slot order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Language {
    AmericanEnglish = 0,
    BritishEnglish = 1,
    Japanese = 2,
    French = 3,
    German = 4,
    LatinAmericanSpanish = 5,
    Spanish = 6,
    Italian = 7,
    Dutch = 8,
    CanadianFrench = 9,
    Portuguese = 10,
    Russian = 11,
    Korean = 12,
    TraditionalChinese = 13,
    SimplifiedChinese = 14,
    BrazilianPortuguese = 15,
}

impl Language {
    /// Every language, in slot order.
    pub const ALL: [Language; 16] = [
        Self::AmericanEnglish,
        Self::BritishEnglish,
        Self::Japanese,
        Self::French,
        Self::German,
        Self::LatinAmericanSpanish,
        Self::Spanish,
        Self::Italian,
        Self::Dutch,
        Self::CanadianFrench,
        Self::Portuguese,
        Self::Russian,
        Self::Korean,
        Self::TraditionalChinese,
        Self::SimplifiedChinese,
        Self::BrazilianPortuguese,
    ];
}

open_enum! {
    /// Whether a user account must be selected at startup.
    pub struct StartupUserAccount(u8) {
        NONE = 0 => "None",
        REQUIRED = 1 => "Required",
        REQUIRED_WITH_NETWORK_SERVICE_ACCOUNT_AVAILABLE = 2 => "RequiredWithNetworkServiceAccountAvailable",
    }
}

open_enum! {
    /// Kind of logo shown at startup.
    pub struct LogoType(u8) {
        LICENSED_BY_NINTENDO = 0 => "LicensedByNintendo",
        DISTRIBUTED_BY_NINTENDO = 1 => "DistributedByNintendo",
        NINTENDO = 2 => "Nintendo",
    }
}

open_enum! {
    /// Whether the system or the application hides the startup logo.
    pub struct LogoHandling(u8) {
        AUTO = 0 => "Auto",
        MANUAL = 1 => "Manual",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields() {
        let mut b = vec![0u8; 0x3300];
        b[0x300..0x305].copy_from_slice(b"Name1");
        b[0x500..0x503].copy_from_slice(b"Pub");
        b[4 * 0x300 + 0x200..][..2].copy_from_slice(b"P2");
        b[0x3000..0x3004].copy_from_slice(b"isbn");
        b[0x3025] = 1;
        b[0x302C..0x3030].copy_from_slice(&0b11u32.to_le_bytes());
        b[0x3040] = 0xFF;
        b[0x3041] = 12;
        b[0x3060..0x3065].copy_from_slice(b"1.2.3");
        b[0x3078..0x3080].copy_from_slice(&0x0100_0000_0000_1000u64.to_le_bytes());
        b[0x3080..0x3088].copy_from_slice(&0x40_0000u64.to_le_bytes());
        b[0x30B8..0x30C0].copy_from_slice(&0xABCDu64.to_le_bytes());
        b[0x30F0] = 2;
        b[0x3188..0x318A].copy_from_slice(&5u16.to_le_bytes());
        b[0x3212] = 3;
        let n = Nacp::from_bytes(&b);
        assert_eq!(n.title(Language::AmericanEnglish), None);
        assert_eq!(
            n.title(Language::BritishEnglish),
            Some(Title {
                name: "Name1".into(),
                publisher: "Pub".into()
            })
        );
        // A publisher without a name still counts as a title.
        assert_eq!(
            n.title(Language::German).map(|t| t.publisher),
            Some("P2".into())
        );
        assert_eq!(n.titles()[1].as_deref(), Some("Name1"));
        assert_eq!(n.titles()[4], None);
        assert_eq!(n.isbn(), "isbn");
        assert_eq!(n.startup_user_account(), StartupUserAccount::REQUIRED);
        assert!(n.supports_language(Language::BritishEnglish));
        assert!(!n.supports_language(Language::Japanese));
        assert_eq!(n.rating_age()[..3], [-1, 12, 0]);
        assert_eq!(n.display_version(), "1.2.3");
        assert_eq!(n.save_data_owner_id(), TitleId(0x0100_0000_0000_1000));
        assert_eq!(n.user_account_save_data_size(), 0x40_0000);
        assert_eq!(n.local_communication_ids()[1], 0xABCD);
        assert_eq!(n.logo_type(), LogoType::NINTENDO);
        assert_eq!(n.cache_storage_index_max(), 5);
        assert_eq!(n.program_index(), 3);
        assert_eq!(n.as_bytes().len(), NACP_SIZE);
        assert_eq!(Language::ALL[15], Language::BrazilianPortuguese);
    }

    #[test]
    fn fuzz_no_panic() {
        let mut b = vec![0x41u8; NACP_SIZE];
        b[0x3000..].fill(0xFF);
        crate::testutil::fuzz(&b[..0x3300], 3, |b| {
            let n = Nacp::from_bytes(b);
            for l in Language::ALL {
                let _ = n.title(l);
            }
            let _ = (
                n.titles(),
                n.isbn(),
                n.display_version(),
                n.bcat_passphrase(),
            );
            let _ = n.application_error_code_category();
        });
    }
}
