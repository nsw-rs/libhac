// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RomFS reader: walk the directory tree and read files.

use crate::bytes::{u32_at, u64_at};
use crate::error::{Result, fail};
use crate::storage::ReadAt;

const NONE: u32 = 0xFFFF_FFFF;

// Minimum entry sizes (fields before the name), used to bound table walks.
const DIR_ENTRY_SIZE: usize = 0x18;
const FILE_ENTRY_SIZE: usize = 0x20;

/// Longest path the console file system accepts. Longer paths only come
/// from crafted tables (e.g. a directory that is its own child), where
/// they would make [`RomFs::files`] use memory quadratic in the entries.
const MAX_PATH: usize = 0x300;

/// Entry name: a u32 length at `len_off`, the bytes right after it.
fn name_at(b: &[u8], o: usize, len_off: usize) -> Result<&[u8]> {
    let len = u32_at(b, o + len_off)? as usize;
    let start = o + len_off + 4;
    match start.checked_add(len).and_then(|end| b.get(start..end)) {
        Some(n) => Ok(n),
        None => fail!(OutOfRange, "RomFS name out of range"),
    }
}

/// `prefix/name`, failing past [`MAX_PATH`].
fn join(prefix: &str, name: &[u8]) -> Result<String> {
    let path = format!("{prefix}/{}", String::from_utf8_lossy(name));
    if path.len() > MAX_PATH {
        fail!(InvalidData, "RomFS path too long");
    }
    Ok(path)
}

/// A file in a RomFS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RomFsFile {
    /// Full path, starting with `/`.
    pub path: String,
    /// Offset of the file data in the RomFS storage.
    pub offset: u64,
    /// Size of the file data.
    pub size: u64,
}

/// Directory and file tables of a RomFS.
pub struct RomFs {
    dirs: Vec<u8>,
    files: Vec<u8>,
    data_off: u64,
}

impl RomFs {
    /// Read the header and metadata tables.
    pub fn open<R: ReadAt + ?Sized>(src: &R) -> Result<Self> {
        let header = src.read_vec(0, 0x50)?;
        let dir_meta_off = u64_at(&header, 0x18)?;
        let dir_meta_size = u64_at(&header, 0x20)?;
        let file_meta_off = u64_at(&header, 0x38)?;
        let file_meta_size = u64_at(&header, 0x40)?;
        let data_off = u64_at(&header, 0x48)?;
        if dir_meta_size > 0x1000_0000 || file_meta_size > 0x1000_0000 {
            fail!(Unsupported, "RomFS tables too large");
        }
        let dirs = src.read_vec(dir_meta_off, dir_meta_size as usize)?;
        let files = src.read_vec(file_meta_off, file_meta_size as usize)?;
        Ok(RomFs {
            dirs,
            files,
            data_off,
        })
    }

    /// List every file, depth first.
    pub fn files(&self) -> Result<Vec<RomFsFile>> {
        let mut out = Vec::new();
        let mut steps = 0;
        let mut stack = vec![(0u32, String::new())];
        while let Some((dir, prefix)) = stack.pop() {
            let mut f = u32_at(&self.dirs, dir as usize + 0x0C)?;
            while f != NONE {
                self.step(&mut steps)?;
                out.push(self.file(f, join(&prefix, self.file_name(f)?)?)?);
                f = u32_at(&self.files, f as usize + 0x04)?;
            }
            let mut d = u32_at(&self.dirs, dir as usize + 0x08)?;
            while d != NONE {
                self.step(&mut steps)?;
                stack.push((d, join(&prefix, self.dir_name(d)?)?));
                d = u32_at(&self.dirs, d as usize + 0x04)?;
            }
        }
        Ok(out)
    }

    /// Look up a file by path. Empty components are ignored, so
    /// `/a/b`, `a/b` and `a//b` are the same path.
    pub fn find(&self, path: &str) -> Result<Option<RomFsFile>> {
        let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let full = format!("/{}", parts.join("/"));
        let Some(file) = parts.pop() else {
            return Ok(None);
        };
        let mut steps = 0;
        let mut dir = 0u32;
        for part in parts {
            let first = u32_at(&self.dirs, dir as usize + 0x08)?;
            match self.find_sibling(first, part.as_bytes(), true, &mut steps)? {
                Some(d) => dir = d,
                None => return Ok(None),
            }
        }
        let first = u32_at(&self.dirs, dir as usize + 0x0C)?;
        match self.find_sibling(first, file.as_bytes(), false, &mut steps)? {
            Some(f) => Ok(Some(self.file(f, full)?)),
            None => Ok(None),
        }
    }

    /// Read the data of `file` from `src`, which must be the storage
    /// passed to [`RomFs::open`].
    pub fn read_file<R: ReadAt + ?Sized>(&self, src: &R, file: &RomFsFile) -> Result<Vec<u8>> {
        src.read_vec(file.offset, file.size as usize)
    }

    /// Read file `name` from the root directory of the RomFS in `src`,
    /// which must be the storage passed to [`RomFs::open`].
    pub fn read_root_file<R: ReadAt + ?Sized>(
        &self,
        src: &R,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let first = u32_at(&self.dirs, 0x0C)?;
        match self.find_sibling(first, name.as_bytes(), false, &mut 0)? {
            Some(f) => Ok(Some(
                self.read_file(src, &self.file(f, format!("/{name}"))?)?,
            )),
            None => Ok(None),
        }
    }

    /// Walk the sibling chain from `cur` looking for `name`.
    fn find_sibling(
        &self,
        mut cur: u32,
        name: &[u8],
        is_dir: bool,
        steps: &mut usize,
    ) -> Result<Option<u32>> {
        while cur != NONE {
            self.step(steps)?;
            let (entry_name, table) = if is_dir {
                (self.dir_name(cur)?, &self.dirs)
            } else {
                (self.file_name(cur)?, &self.files)
            };
            if entry_name == name {
                return Ok(Some(cur));
            }
            cur = u32_at(table, cur as usize + 0x04)?;
        }
        Ok(None)
    }

    /// Count one visited entry. A valid RomFS cannot have more entries
    /// than fit in its tables, so going past that means a loop.
    fn step(&self, steps: &mut usize) -> Result<()> {
        *steps += 1;
        if *steps > self.dirs.len() / DIR_ENTRY_SIZE + self.files.len() / FILE_ENTRY_SIZE {
            fail!(InvalidData, "RomFS entry loop");
        }
        Ok(())
    }

    fn dir_name(&self, o: u32) -> Result<&[u8]> {
        name_at(&self.dirs, o as usize, 0x14)
    }

    fn file_name(&self, o: u32) -> Result<&[u8]> {
        name_at(&self.files, o as usize, 0x1C)
    }

    fn file(&self, o: u32, path: String) -> Result<RomFsFile> {
        let o = o as usize;
        let off = u64_at(&self.files, o + 0x08)?;
        let size = u64_at(&self.files, o + 0x10)?;
        let Some(offset) = self.data_off.checked_add(off) else {
            fail!(OutOfRange, "RomFS file offset out of range");
        };
        Ok(RomFsFile { path, offset, size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn name_field(out: &mut Vec<u8>, name: &str) {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len().next_multiple_of(4), 0);
    }

    fn dir(parent: u32, sibling: u32, child_dir: u32, child_file: u32, name: &str) -> Vec<u8> {
        let mut e = Vec::new();
        for v in [parent, sibling, child_dir, child_file, NONE] {
            e.extend_from_slice(&v.to_le_bytes());
        }
        name_field(&mut e, name);
        e
    }

    fn file(parent: u32, sibling: u32, off: u64, size: u64, name: &str) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&parent.to_le_bytes());
        e.extend_from_slice(&sibling.to_le_bytes());
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&size.to_le_bytes());
        e.extend_from_slice(&NONE.to_le_bytes());
        name_field(&mut e, name);
        e
    }

    fn image(dirs: &[u8], files: &[u8], data: &[u8]) -> Vec<u8> {
        let dir_off = 0x50u64;
        let file_off = dir_off + dirs.len() as u64;
        let data_off = (file_off + files.len() as u64).next_multiple_of(0x10);
        let mut out = vec![0u8; 0x50];
        for (o, v) in [
            (0x00, 0x50),
            (0x18, dir_off),
            (0x20, dirs.len() as u64),
            (0x38, file_off),
            (0x40, files.len() as u64),
            (0x48, data_off),
        ] {
            out[o..o + 8].copy_from_slice(&u64::to_le_bytes(v));
        }
        out.extend_from_slice(dirs);
        out.extend_from_slice(files);
        out.resize(data_off as usize, 0);
        out.extend_from_slice(data);
        out
    }

    // Tree: /a.txt, /d/b.bin, /d/e/c.dat and the empty directory /x.
    // Dirs: root 0x00, d 0x18, e 0x34, x 0x50.
    // Files: a.txt 0x00, b.bin 0x28, c.dat 0x50.
    fn tables() -> (Vec<u8>, Vec<u8>) {
        let dirs = [
            dir(0, NONE, 0x18, 0x00, ""),
            dir(0, 0x50, 0x34, 0x28, "d"),
            dir(0x18, NONE, NONE, 0x50, "e"),
            dir(0, NONE, NONE, NONE, "x"),
        ]
        .concat();
        let files = [
            file(0, NONE, 0, 5, "a.txt"),
            file(0x18, NONE, 5, 3, "b.bin"),
            file(0x34, NONE, 8, 4, "c.dat"),
        ]
        .concat();
        (dirs, files)
    }

    const DATA: &[u8] = b"hello\x01\x02\x03\x09\x09\x09\x09";

    #[test]
    fn walk_and_find() {
        let (dirs, files) = tables();
        let img = image(&dirs, &files, DATA);
        let fs = RomFs::open(&img).unwrap();

        let mut all: Vec<_> = fs
            .files()
            .unwrap()
            .into_iter()
            .map(|f| (f.path, f.size))
            .collect();
        all.sort();
        assert_eq!(
            all,
            [
                ("/a.txt".to_string(), 5),
                ("/d/b.bin".to_string(), 3),
                ("/d/e/c.dat".to_string(), 4),
            ]
        );

        let c = fs.find("/d/e/c.dat").unwrap().unwrap();
        assert_eq!(fs.read_file(&img, &c).unwrap(), [9; 4]);
        let b = fs.find("d//b.bin").unwrap().unwrap();
        assert_eq!(b.path, "/d/b.bin");
        assert_eq!(fs.read_file(&img, &b).unwrap(), [1, 2, 3]);
        assert!(fs.find("/d/zz").unwrap().is_none());
        assert!(fs.find("/x/a.txt").unwrap().is_none());
        assert!(fs.find("/").unwrap().is_none());

        assert_eq!(fs.read_root_file(&img, "a.txt").unwrap().unwrap(), b"hello");
        assert!(fs.read_root_file(&img, "b.bin").unwrap().is_none());
    }

    #[test]
    fn sibling_loop() {
        let (dirs, mut files) = tables();
        // a.txt sibling points to itself.
        files[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        let img = image(&dirs, &files, DATA);
        let fs = RomFs::open(&img).unwrap();
        assert!(matches!(fs.files(), Err(Error::InvalidData(_))));
        assert!(matches!(fs.find("/zz"), Err(Error::InvalidData(_))));
    }

    #[test]
    fn bad_name_length() {
        let (dirs, mut files) = tables();
        files[0x1C..0x20].copy_from_slice(&0x1000u32.to_le_bytes());
        let img = image(&dirs, &files, DATA);
        let fs = RomFs::open(&img).unwrap();
        assert!(matches!(fs.files(), Err(Error::OutOfRange(_))));
    }

    #[test]
    fn dir_loop() {
        let (mut dirs, files) = tables();
        // e is its own child directory.
        dirs[0x34 + 0x08..0x34 + 0x0C].copy_from_slice(&0x34u32.to_le_bytes());
        let img = image(&dirs, &files, DATA);
        let fs = RomFs::open(&img).unwrap();
        assert!(matches!(fs.files(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn fuzz_no_panic() {
        let (dirs, files) = tables();
        let img = image(&dirs, &files, DATA);
        crate::testutil::fuzz(&img, 9, |b| {
            if let Ok(fs) = RomFs::open(&b) {
                let _ = fs.files();
                let _ = fs.find("/d/e/c.dat");
                let _ = fs.read_root_file(&b, "a.txt");
            }
        });
    }
}
