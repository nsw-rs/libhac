<!--
SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# libhac

A Rust library for reading Nintendo Switch file formats. It is a port of
LibHac by Alex Barney, with an idiomatic Rust API rather than a copy of the
LibHac class layout. No .NET runtime is involved. The goal is to cover all of
LibHac; see [Status](#status) for what is ported so far.

It can validate NSP files and write Standard NSPs that are byte-identical
to those of NSFW.

> [!IMPORTANT]
> This library is designed to work with legal backup copies of your own
> games and with keys dumped from your own console.

## Example

```rust,no_run
use libhac::nca::{ContentType, Nca, TitleKeys};
use libhac::partition::PartitionFs;
use libhac::romfs::RomFs;
use libhac::{Keys, SubStorage};
use std::fs::File;
use std::path::Path;

fn main() -> libhac::Result<()> {
    let keys = Keys::load(Path::new("prod.keys"))?;
    let nsp = File::open("game.nsp")?;
    let size = nsp.metadata()?.len();
    let pfs = PartitionFs::parse_pfs0(&SubStorage::new(&nsp, 0, size)?)?;
    for e in pfs.entries().iter().filter(|e| e.name.ends_with(".nca")) {
        let nca = Nca::open(&keys, SubStorage::new(&nsp, e.offset, e.size)?)?;
        println!("{} {} {}", e.name, nca.content_type(), nca.program_id());
        // No signature is checked on open.
        if !nca.verify_header_signature() {
            println!("  header signature is invalid");
        }
        if nca.content_type() == ContentType::CONTROL {
            let section = nca.open_section(nca.data_section_index(), &TitleKeys::new())?;
            let romfs = RomFs::open(&section)?;
            let nacp = romfs.read_root_file(&section, "control.nacp")?;
            println!("  control.nacp: {} bytes", nacp.map_or(0, |n| n.len()));
        }
    }
    Ok(())
}
```

## Modules

| Module | Contents |
|---|---|
| `storage` | `ReadAt` positional read trait for files, byte slices and `SubStorage` ranges |
| `keys` | `prod.keys` loader |
| `crypto` | AES-ECB/CTR/XTS, RSA-PSS verification |
| `nca` | NCA header decryption and signatures, key area, title keys, hash-verified sections (hierarchical SHA256 and IVFC), compressed sections |
| `partition` | PFS0/HFS0 parser at any offset |
| `pfs0` | Standard NSP header builder |
| `xci` | XCI card header and root HFS0 partition table |
| `ncz` | Block compressed NCZ read as the original NCA (feature `ncz`) |
| `image` | Virtual NSP/XCI images of NSZ/XCZ containers, `NSZKEEP1` trailer restore (feature `ncz`) |
| `romfs` | RomFS tables, directory tree walk and path lookup |
| `ticket` | eTicket parsing, creation, serialization, title key and signature checks |
| `cnmt` | Packaged content meta: extended headers, contents, content meta entries, digest |
| `nacp` | Application control property: titles and publishers, version, save data sizes, ratings and the other fields |
| `npdm` | Program metadata: `META` header, `ACI0` and `ACID` (FS access, services, kernel capabilities), ACID modulus for NCA signature 2 checks |

## Status

| LibHac area | Status |
|---|---|
| NCA (header, key area, title keys, AES-CTR sections) | ported |
| Hash tree verification (SHA256, IVFC) | ported, read-only |
| Compressed storage (LZ4) | ported |
| PFS0 / NSP | ported, plus Standard NSP header writer |
| RomFS | ported, read-only |
| Tickets | ported |
| CNMT, NACP | ported |
| NPDM | ported; kernel capabilities kept as raw descriptors |
| Key derivation (`KeySet`) | not ported: derived keys are read from `prod.keys` |
| Patch (BKTR indirect/AES-CTR-EX) and sparse sections | not ported |
| Writable storage, `IFileSystem`/`IFile` abstractions | not ported |
| XCI | partial: card header, root and partition HFS0 |
| NCZ/XCZ (nsz) | NCZ reading (block and solid), block NCZ writing, NSZ/XCZ images of block NCZs (feature `ncz`) |
| NSO/NRO, save data | not ported |
| `hactoolnet`-like command line tool | not ported |

## Usage

Add it to a project with:

```
cargo add libhac
```

Use `cargo add libhac --features ncz` for NSZ/XCZ support.

## Building

Requires Rust 1.89 or newer.

```
cargo build
cargo test --all-features
```

The `ncz` feature adds zstd (libzstd, built from source) and serde_json.

## License

libhac is licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option. Code ported from LibHac
and NSFW keeps the copyright notices of their authors (both MIT upstream).

The repository is [REUSE](https://reuse.software/) compliant: every file
states its copyright and license.
