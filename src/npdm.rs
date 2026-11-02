// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Program metadata (`main.npdm`): the `META` header, the `ACI0` access
//! control info and the signed `ACID` access control descriptor.

use crate::bytes::{self, c_string, u64_le};
use crate::error::{Error, Result, fail};
use crate::types::TitleId;

fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    bytes::u32_at(b, o).map_err(|_| Error::OutOfRange("NPDM truncated".into()))
}

/// The `size` bytes at `off` of `b`, failing with a message naming `what`.
fn region<'a>(b: &'a [u8], off: u32, size: u32, what: &str) -> Result<&'a [u8]> {
    let off = off as usize;
    match off
        .checked_add(size as usize)
        .and_then(|end| b.get(off..end))
    {
        Some(r) => Ok(r),
        None => fail!(OutOfRange, "NPDM {what} out of range"),
    }
}

/// The checks of LibHac's NPDM reader that NCA signature verification
/// depends on, returning the `META` header, the `ACI0` section and the
/// `ACID` section (each running to the end of `b`).
fn locate(b: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    if b.get(..4) != Some(b"META") {
        fail!(InvalidMagic, "NPDM Stream doesn't contain NPDM file!");
    }
    if b.len() < 0x80 {
        fail!(OutOfRange, "NPDM truncated");
    }
    if b[0x0E] > 0x3F {
        fail!(InvalidData, "MainThreadPriority is out of range!");
    }
    let aci0 = u32_at(b, 0x70)? as usize;
    let acid = u32_at(b, 0x78)? as usize;

    let Some(aci) = b.get(aci0..).filter(|s| s.starts_with(b"ACI0")) else {
        fail!(InvalidMagic, "ACI0 Stream doesn't contain ACI0 section!");
    };
    let fs_off = u32_at(aci, 0x20)? as usize;
    let fs_size = u32_at(aci, 0x24)?;
    if fs_size > 0 && u32_at(aci.get(fs_off..).unwrap_or_default(), 0x0C)? != 0x1C {
        fail!(InvalidData, "FsAccessHeader is corrupted!");
    }

    let Some(acid) = b
        .get(acid..)
        .filter(|s| s.get(0x200..0x204) == Some(b"ACID"))
    else {
        fail!(InvalidMagic, "ACID Stream doesn't contain ACID section!");
    };
    Ok((&b[..0x80], aci, acid))
}

/// The ACID RSA-2048 modulus that signs the NCA header (signature 2) of the
/// program NCA holding this `main.npdm`.
pub fn acid_modulus(b: &[u8]) -> Result<Vec<u8>> {
    let (_, _, acid) = locate(b)?;
    Ok(acid[0x100..0x200].to_vec())
}

/// File system permissions of an `ACI0` (`FsAccessHeader`) or an `ACID`
/// (`FsAccessControlDescriptor`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FsAccessControl {
    /// Structure version.
    pub version: u8,
    /// Permission bits (`FsAccessFlag`).
    pub permissions: u64,
}

impl FsAccessControl {
    fn parse(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Ok(Self::default());
        }
        if b.len() < 0x0C {
            fail!(OutOfRange, "NPDM FS access control truncated");
        }
        Ok(Self {
            version: b[0],
            permissions: u64_le(b, 4),
        })
    }
}

/// An entry of a service access control list.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceAccess {
    /// Service name, possibly with a trailing `*` wildcard.
    pub name: String,
    /// True when the program may host (register) the service, false when
    /// it may only connect to it.
    pub is_server: bool,
}

/// Parse a service access control list: each entry is a control byte
/// (bits 0-2 name length minus one, bit 7 server) and the name.
fn parse_services(mut b: &[u8]) -> Result<Vec<ServiceAccess>> {
    let mut out = Vec::new();
    while let Some((&ctrl, rest)) = b.split_first() {
        // A zero control byte ends the list (padding).
        if ctrl == 0 {
            break;
        }
        let len = (ctrl & 7) as usize + 1;
        let Some(name) = rest.get(..len) else {
            fail!(OutOfRange, "NPDM service access entry truncated");
        };
        out.push(ServiceAccess {
            name: c_string(name),
            is_server: ctrl & 0x80 != 0,
        });
        b = &rest[len..];
    }
    Ok(out)
}

/// Kernel capability descriptors, one 32-bit word each.
fn parse_kernel_caps(b: &[u8]) -> Result<Vec<u32>> {
    if !b.len().is_multiple_of(4) {
        fail!(
            InvalidData,
            "NPDM kernel capabilities size not a multiple of 4"
        );
    }
    Ok(b.as_chunks::<4>()
        .0
        .iter()
        .map(|&w| u32::from_le_bytes(w))
        .collect())
}

/// The access control lists shared by `ACI0` and `ACID`, at the offsets
/// stored at `at` of section `s`.
fn parse_lists(s: &[u8], at: usize) -> Result<(FsAccessControl, Vec<ServiceAccess>, Vec<u32>)> {
    let entry = |i: usize, what| {
        let off = u32_at(s, at + i * 8)?;
        let size = u32_at(s, at + i * 8 + 4)?;
        region(s, off, size, what)
    };
    Ok((
        FsAccessControl::parse(entry(0, "FS access control")?)?,
        parse_services(entry(1, "service access control")?)?,
        parse_kernel_caps(entry(2, "kernel capabilities")?)?,
    ))
}

/// The `ACI0` access control info: what the program is granted.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Aci0 {
    /// Program ID.
    pub program_id: TitleId,
    /// File system permissions.
    pub fs_access_control: FsAccessControl,
    /// Services the program may use or host.
    pub services: Vec<ServiceAccess>,
    /// Kernel capability descriptors.
    pub kernel_capabilities: Vec<u32>,
}

/// The `ACID` access control descriptor: the limits of what an `ACI0` may
/// grant, signed by Nintendo.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Acid {
    /// RSA-2048 PSS signature over the descriptor.
    pub signature: Vec<u8>,
    /// RSA-2048 modulus that signs the program NCA header (signature 2).
    pub modulus: Vec<u8>,
    /// Flags (bit 0 production, bit 1 unqualified approval, bits 2-5
    /// memory region).
    pub flags: u32,
    /// Lowest program ID the descriptor allows.
    pub program_id_min: TitleId,
    /// Highest program ID the descriptor allows.
    pub program_id_max: TitleId,
    /// File system permissions.
    pub fs_access_control: FsAccessControl,
    /// Services the program may use or host.
    pub services: Vec<ServiceAccess>,
    /// Kernel capability descriptors.
    pub kernel_capabilities: Vec<u32>,
}

/// A parsed `main.npdm`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Npdm {
    /// Program name.
    pub name: String,
    /// Product code.
    pub product_code: String,
    /// Index of the key that signs the `ACID`.
    pub signature_key_generation: u32,
    /// Flags (bit 0 64-bit instructions, bits 1-3 address space type).
    pub flags: u8,
    /// Priority of the main thread (0 to 63).
    pub main_thread_priority: u8,
    /// CPU core of the main thread.
    pub main_thread_core: u8,
    /// Stack size of the main thread.
    pub main_thread_stack_size: u32,
    /// Program version.
    pub version: u32,
    /// Size of the system resource.
    pub system_resource_size: u32,
    /// Access control info.
    pub aci0: Aci0,
    /// Access control descriptor.
    pub acid: Acid,
}

impl Npdm {
    /// Parse a `main.npdm`. It fails on the same files as [`acid_modulus`]
    /// with the same errors, and also on access control lists that do not
    /// fit their section.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let (meta, aci, acid) = locate(b)?;
        let aci_size = u32_at(meta, 0x74)?;
        let acid_size = u32_at(meta, 0x7C)?;
        let aci = region(aci, 0, aci_size, "ACI0")?;
        if aci.len() < 0x40 {
            fail!(OutOfRange, "NPDM ACI0 truncated");
        }
        let acid = region(acid, 0, acid_size, "ACID")?;
        if acid.len() < 0x240 {
            fail!(OutOfRange, "NPDM ACID truncated");
        }

        let (fs, services, caps) = parse_lists(aci, 0x20)?;
        let aci0 = Aci0 {
            program_id: TitleId(u64_le(aci, 0x10)),
            fs_access_control: fs,
            services,
            kernel_capabilities: caps,
        };
        // ACID offsets count from the start of the section, signature
        // included.
        let (fs, services, caps) = parse_lists(acid, 0x220)?;
        let acid = Acid {
            signature: acid[..0x100].to_vec(),
            modulus: acid[0x100..0x200].to_vec(),
            flags: u32_at(acid, 0x20C)?,
            program_id_min: TitleId(u64_le(acid, 0x210)),
            program_id_max: TitleId(u64_le(acid, 0x218)),
            fs_access_control: fs,
            services,
            kernel_capabilities: caps,
        };
        Ok(Npdm {
            name: c_string(&meta[0x20..0x30]),
            product_code: c_string(&meta[0x30..0x40]),
            signature_key_generation: u32_at(meta, 4)?,
            flags: meta[0x0C],
            main_thread_priority: meta[0x0E],
            main_thread_core: meta[0x0F],
            main_thread_stack_size: u32_at(meta, 0x1C)?,
            version: u32_at(meta, 0x18)?,
            system_resource_size: u32_at(meta, 0x14)?,
            aci0,
            acid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fuzz;

    fn put(b: &mut [u8], o: usize, v: &[u8]) {
        b[o..o + v.len()].copy_from_slice(v);
    }

    /// Append an FS access control, a service list and kernel
    /// capabilities to section `sec`, writing their offset/size table at
    /// `table`.
    fn lists(sec: &mut Vec<u8>, table: usize, fs: &[u8]) {
        let services = b"\x06fsp-srv\x82sm:\x00";
        let caps: Vec<u8> = [0x0000_0007u32, 0x0200_003F]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        for (i, part) in [fs, &services[..], &caps].into_iter().enumerate() {
            let off = sec.len() as u32;
            sec.extend_from_slice(part);
            put(sec, table + i * 8, &off.to_le_bytes());
            put(sec, table + i * 8 + 4, &(part.len() as u32).to_le_bytes());
        }
    }

    fn sample() -> Vec<u8> {
        let mut aci = vec![0u8; 0x40];
        put(&mut aci, 0, b"ACI0");
        put(&mut aci, 0x10, &0x0100_0000_0000_1000u64.to_le_bytes());
        let mut fs = vec![0u8; 0x1C];
        fs[0] = 1;
        put(&mut fs, 4, &0x4000_0000_0000_0000u64.to_le_bytes());
        put(&mut fs, 0x0C, &0x1Cu32.to_le_bytes());
        put(&mut fs, 0x14, &0x1Cu32.to_le_bytes());
        lists(&mut aci, 0x20, &fs);
        aci.resize(aci.len().next_multiple_of(0x10), 0);

        let mut acid = vec![0u8; 0x240];
        acid[..0x100].fill(0x5A);
        acid[0x100..0x200].fill(0xAB);
        put(&mut acid, 0x200, b"ACID");
        put(&mut acid, 0x20C, &3u32.to_le_bytes());
        put(&mut acid, 0x210, &0x0100_0000_0000_0000u64.to_le_bytes());
        put(&mut acid, 0x218, &0x01FF_FFFF_FFFF_FFFFu64.to_le_bytes());
        let mut fs = vec![0u8; 0x2C];
        fs[0] = 1;
        put(&mut fs, 4, &0x4000_0000_0000_0000u64.to_le_bytes());
        lists(&mut acid, 0x220, &fs);
        let acid_size = acid.len() as u32;
        put(&mut acid, 0x204, &(acid_size - 0x100).to_le_bytes());

        let mut b = vec![0u8; 0x80];
        put(&mut b, 0, b"META");
        b[0x0C] = 1;
        b[0x0E] = 44;
        b[0x0F] = 0;
        put(&mut b, 0x14, &0x0100_0000u32.to_le_bytes());
        put(&mut b, 0x18, &7u32.to_le_bytes());
        put(&mut b, 0x1C, &0x10_0000u32.to_le_bytes());
        put(&mut b, 0x20, b"Application");
        let aci_off = b.len() as u32;
        let acid_off = aci_off + aci.len() as u32;
        put(&mut b, 0x70, &aci_off.to_le_bytes());
        put(&mut b, 0x74, &(aci.len() as u32).to_le_bytes());
        put(&mut b, 0x78, &acid_off.to_le_bytes());
        put(&mut b, 0x7C, &acid_size.to_le_bytes());
        b.extend_from_slice(&aci);
        b.extend_from_slice(&acid);
        b
    }

    #[test]
    fn parse_sample() {
        let b = sample();
        let n = Npdm::parse(&b).unwrap();
        assert_eq!(n.name, "Application");
        assert_eq!(n.flags, 1);
        assert_eq!(n.main_thread_priority, 44);
        assert_eq!(n.main_thread_stack_size, 0x10_0000);
        assert_eq!(n.system_resource_size, 0x0100_0000);
        assert_eq!(n.version, 7);
        assert_eq!(n.aci0.program_id, TitleId(0x0100_0000_0000_1000));
        assert_eq!(n.aci0.fs_access_control.version, 1);
        assert_eq!(n.aci0.fs_access_control.permissions, 1 << 62);
        let names: Vec<_> = n
            .aci0
            .services
            .iter()
            .map(|s| (s.name.as_str(), s.is_server))
            .collect();
        assert_eq!(names, [("fsp-srv", false), ("sm:", true)]);
        assert_eq!(n.aci0.kernel_capabilities, [7, 0x0200_003F]);
        assert_eq!(n.acid.flags, 3);
        assert_eq!(n.acid.program_id_max, TitleId(0x01FF_FFFF_FFFF_FFFF));
        assert_eq!(n.acid.modulus, [0xAB; 0x100]);
        assert_eq!(n.acid.signature, [0x5A; 0x100]);
        assert_eq!(n.acid.services, n.aci0.services);
        assert_eq!(acid_modulus(&b).unwrap(), n.acid.modulus);
    }

    #[test]
    fn acid_modulus_errors() {
        let b = sample();
        let msg = |b: &[u8]| acid_modulus(b).unwrap_err().to_string();
        assert_eq!(msg(&b[..3]), "NPDM Stream doesn't contain NPDM file!");
        assert_eq!(msg(&b[..0x40]), "NPDM truncated");
        let mut bad = b.clone();
        bad[0x0E] = 0x40;
        assert_eq!(msg(&bad), "MainThreadPriority is out of range!");
        let mut bad = b.clone();
        bad[0x80] = b'X';
        assert_eq!(msg(&bad), "ACI0 Stream doesn't contain ACI0 section!");
        // FsAccessHeader content owner offset.
        let mut bad = b.clone();
        let fs = 0x80 + u32::from_le_bytes(b[0xA0..0xA4].try_into().unwrap()) as usize;
        bad[fs + 0x0C] = 0;
        assert_eq!(msg(&bad), "FsAccessHeader is corrupted!");
        assert_eq!(
            msg(&b[..b.len() - 0x100]),
            "ACID Stream doesn't contain ACID section!"
        );
    }

    #[test]
    fn fuzz_no_panic() {
        fuzz(&sample(), 11, |b| {
            let modulus = acid_modulus(b);
            let full = Npdm::parse(b);
            // parse fails on every file acid_modulus rejects.
            if modulus.is_err() {
                assert!(full.is_err());
            }
        });
    }
}
