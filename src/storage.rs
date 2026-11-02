// SPDX-FileCopyrightText: 2024 mRg
// SPDX-FileCopyrightText: 2018-2022 Alex Barney
// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only random access storage.

use crate::error::{Result, fail};
#[cfg(any(unix, windows))]
use std::fs::File;
use std::sync::Arc;

/// Random-access byte source.
pub trait ReadAt {
    /// Fill `buf` with the bytes at `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
    /// Total size in bytes. Fails when the size cannot be queried, e.g.
    /// when `fstat` fails on a file.
    fn size(&self) -> Result<u64>;

    /// Read `len` bytes at `offset` into a new vector.
    fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        // Check before allocating: lengths come from file data.
        check_range(offset, len, self.size()?)?;
        let mut v = vec![0u8; len];
        self.read_at(offset, &mut v)?;
        Ok(v)
    }

    /// Read `size` bytes at `offset` in 1 MiB chunks, passing each to `f`.
    fn read_chunks(
        &self,
        offset: u64,
        size: u64,
        f: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if !in_range(offset, size, self.size()?) {
            fail!(OutOfRange, "read out of range");
        }
        let mut buf = vec![0u8; size.min(0x100000) as usize];
        let mut pos = 0u64;
        while pos < size {
            let n = (size - pos).min(buf.len() as u64) as usize;
            self.read_at(offset + pos, &mut buf[..n])?;
            f(&buf[..n])?;
            pos += n as u64;
        }
        Ok(())
    }
}

/// Fail unless the `len` bytes at `offset` lie within `size` bytes. The end
/// is computed without overflow, so a huge `offset` cannot wrap around the
/// check.
pub(crate) fn check_range(offset: u64, len: usize, size: u64) -> Result<()> {
    if !in_range(offset, len as u64, size) {
        fail!(OutOfRange, "read out of range");
    }
    Ok(())
}

/// Whether the `len` bytes at `offset` lie within `size` bytes, computed
/// without overflow.
pub(crate) fn in_range(offset: u64, len: u64, size: u64) -> bool {
    offset.checked_add(len).is_some_and(|end| end <= size)
}

/// The `N` bytes at `offset` of `src`, for fixed-size headers.
pub(crate) fn read_array<const N: usize, S: ReadAt + ?Sized>(
    src: &S,
    offset: u64,
) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    src.read_at(offset, &mut b)?;
    Ok(b)
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }
    fn size(&self) -> Result<u64> {
        (**self).size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }
    fn size(&self) -> Result<u64> {
        (**self).size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Arc<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }
    fn size(&self) -> Result<u64> {
        (**self).size()
    }
}

impl ReadAt for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let Some(src) = usize::try_from(offset)
            .ok()
            .and_then(|o| self.get(o..o.checked_add(buf.len())?))
        else {
            fail!(OutOfRange, "read out of range");
        };
        buf.copy_from_slice(src);
        Ok(())
    }
    fn size(&self) -> Result<u64> {
        Ok(self.len() as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.as_slice().read_at(offset, buf)
    }
    fn size(&self) -> Result<u64> {
        Ok(self.len() as u64)
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

/// Windows has no `read_exact_at`, and `seek_read` may return fewer bytes.
#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
        }
    }
    Ok(())
}

/// Positional reads that do not move the file cursor. The size is queried
/// from the file system on every call; wrap the file in a [`SubStorage`] to
/// fix it once.
#[cfg(any(unix, windows))]
impl ReadAt for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        read_exact_at(self, buf, offset)?;
        Ok(())
    }
    fn size(&self) -> Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// A byte range of another storage.
#[derive(Clone, Copy, Debug)]
pub struct SubStorage<S> {
    base: S,
    offset: u64,
    size: u64,
}

impl<S: ReadAt> SubStorage<S> {
    /// The `size` bytes of `base` starting at `offset`. Fails when the
    /// range does not lie inside `base`.
    pub fn new(base: S, offset: u64, size: u64) -> Result<Self> {
        if !in_range(offset, size, base.size()?) {
            fail!(OutOfRange, "sub-storage out of range");
        }
        Ok(SubStorage { base, offset, size })
    }

    /// Start of the range within the base storage.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The base storage.
    pub fn base(&self) -> &S {
        &self.base
    }
}

impl<S: ReadAt> ReadAt for SubStorage<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        // `new` checked that the range ends inside the base, so this cannot
        // overflow.
        self.base.read_at(self.offset + offset, buf)
    }
    fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn sub_storage_bounds() {
        let data: Vec<u8> = (0..32).collect();
        let sub = SubStorage::new(&data, 8, 8).unwrap();
        assert_eq!(sub.read_vec(0, 8).unwrap(), (8..16).collect::<Vec<u8>>());
        assert!(sub.read_vec(1, 8).is_err());
        assert!(data.read_vec(30, 4).is_err());
        let mut n = 0;
        sub.read_chunks(2, 6, &mut |c| {
            n += c.len();
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 6);
        // Checked before any chunk is read, so nothing reaches `f`.
        for (offset, size) in [(2, 7), (u64::MAX, 2)] {
            let r = sub.read_chunks(offset, size, &mut |_| panic!("chunk read"));
            assert!(matches!(r, Err(Error::OutOfRange(_))));
        }
    }

    #[test]
    fn huge_offset_does_not_wrap() {
        let data: Vec<u8> = (0..32).collect();
        let sub = SubStorage::new(&data, 8, 8).unwrap();
        let mut buf = [0u8; 16];
        assert!(sub.read_at(u64::MAX - 7, &mut buf).is_err());
        assert!(SubStorage::new(&data, u64::MAX, 8).is_err());
        assert!(SubStorage::new(&data, 30, 4).is_err());
    }
}
