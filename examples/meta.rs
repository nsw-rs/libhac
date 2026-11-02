// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Print the content meta, control property and program metadata of the
//! NSPs given on the command line.
//!
//! Usage: `cargo run --example meta -- KEYS NSP...`

use libhac::cnmt::Cnmt;
use libhac::nacp::{Language, Nacp};
use libhac::nca::{ContentType, Nca, SectionIndex, TitleKeys};
use libhac::npdm::Npdm;
use libhac::partition::PartitionFs;
use libhac::romfs::RomFs;
use libhac::ticket::Ticket;
use libhac::{Keys, ReadAt, SubStorage};
use std::fs::File;
use std::path::Path;

/// The single file of the PFS0 in section `i` whose name passes `pick`.
fn pfs_file<S: ReadAt>(
    nca: &Nca<S>,
    i: SectionIndex,
    tk: &TitleKeys,
    pick: impl Fn(&str) -> bool,
) -> libhac::Result<Option<Vec<u8>>> {
    let section = nca.open_section(i, tk)?;
    let pfs = PartitionFs::parse_pfs0(&section)?;
    match pfs.entries().iter().find(|e| pick(&e.name)) {
        Some(e) => Ok(Some(section.read_vec(e.offset, e.size as usize)?)),
        None => Ok(None),
    }
}

fn dump(keys: &Keys, path: &Path) -> libhac::Result<()> {
    let nsp = File::open(path)?;
    let size = nsp.metadata()?.len();
    let pfs = PartitionFs::parse_pfs0(&SubStorage::new(&nsp, 0, size)?)?;
    let mut tk = TitleKeys::new();
    for e in pfs.entries().iter().filter(|e| e.name.ends_with(".tik")) {
        let t = Ticket::parse(&nsp.read_vec(e.offset, e.size as usize)?)?;
        if let Ok(key) = t.title_key_block[..16].try_into() {
            tk.insert(t.rights_id, key);
        }
    }
    for e in pfs.entries().iter().filter(|e| e.name.ends_with(".nca")) {
        let nca = Nca::open(keys, SubStorage::new(&nsp, e.offset, e.size)?)?;
        let data = nca.data_section_index();
        match nca.content_type() {
            ContentType::META => {
                if let Some(b) = pfs_file(&nca, data, &tk, |n| n.ends_with(".cnmt"))? {
                    println!("{:#?}", Cnmt::parse(&b)?);
                }
            }
            ContentType::CONTROL => {
                let section = nca.open_section(data, &tk)?;
                let romfs = RomFs::open(&section)?;
                if let Some(b) = romfs.read_root_file(&section, "control.nacp")? {
                    let n = Nacp::from_bytes(&b);
                    for lang in Language::ALL {
                        if let Some(t) = n.title(lang) {
                            println!("{lang:?}: {t:?}");
                        }
                    }
                    println!(
                        "version {} save owner {} user save {:#x}/{:#x} logo {}",
                        n.display_version(),
                        n.save_data_owner_id(),
                        n.user_account_save_data_size(),
                        n.user_account_save_data_journal_size(),
                        n.logo_type(),
                    );
                }
            }
            ContentType::PROGRAM => {
                let exefs = SectionIndex::new(0).unwrap();
                if let Ok(Some(b)) = pfs_file(&nca, exefs, &tk, |n| n == "main.npdm") {
                    println!("{:#?}", Npdm::parse(&b)?);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((keys, nsps)) = args.split_first() else {
        eprintln!("usage: meta KEYS NSP...");
        std::process::exit(2);
    };
    let keys = Keys::load(Path::new(keys)).expect("keys");
    for nsp in nsps {
        println!("== {nsp}");
        if let Err(e) = dump(&keys, Path::new(nsp)) {
            println!("error: {e}");
        }
    }
}
