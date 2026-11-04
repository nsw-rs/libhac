// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Thin libzstd bindings for NCZ.
//!
//! The encoder output must stay the same from one build to the next, so
//! libzstd is pinned (zstd-sys `=2.0.9`, libzstd 1.5.5) and every context
//! is set up the same way: level 19, multithreaded with one worker,
//! nothing else.

use crate::error::{Error, Result};
use std::ffi::CStr;
use std::io::{self, Read};
use std::os::raw::c_void;
use zstd_sys as z;

/// Compression level of every NCZ written.
const LEVEL: i32 = 19;

/// `ZSTD_versionNumber` of the pinned libzstd (1.5.5).
const LIBZSTD_VERSION: u32 = 10505;

fn check(code: usize) -> Result<usize> {
    // SAFETY: both functions only inspect the code; the name is a static
    // string.
    unsafe {
        if z::ZSTD_isError(code) != 0 {
            let msg = CStr::from_ptr(z::ZSTD_getErrorName(code));
            return Err(Error::InvalidData(format!(
                "zstd: {}",
                msg.to_string_lossy()
            )));
        }
    }
    Ok(code)
}

/// A compression context with the fixed NCZ parameters.
pub(crate) struct Encoder {
    cctx: *mut z::ZSTD_CCtx,
}

// SAFETY: the context is owned and only used through `&mut self`.
unsafe impl Send for Encoder {}

impl Encoder {
    /// A one-worker context: the worker gives the multithreaded framing
    /// RomVault writes.
    pub(crate) fn new() -> Result<Self> {
        // The pin can be bypassed by linking a system libzstd (zstd-sys
        // `ZSTD_SYS_USE_PKG_CONFIG`), which would change the output.
        // SAFETY: pure function.
        let version = unsafe { z::ZSTD_versionNumber() };
        if version != LIBZSTD_VERSION {
            return Err(Error::Unsupported(format!(
                "zstd: NCZ output needs libzstd {LIBZSTD_VERSION}, linked {version}"
            )));
        }
        // SAFETY: plain constructor; null is checked below.
        let cctx = unsafe { z::ZSTD_createCCtx() };
        if cctx.is_null() {
            return Err(Error::InvalidData("zstd: cannot create context".into()));
        }
        // Built first so that Drop frees the context if setup fails.
        let e = Encoder { cctx };
        // SAFETY: `cctx` is a valid context.
        unsafe {
            check(z::ZSTD_CCtx_setParameter(
                cctx,
                z::ZSTD_cParameter::ZSTD_c_compressionLevel,
                LEVEL,
            ))?;
            // zstd clamps out-of-range values instead of failing and
            // returns the value it set, so 0 means no multithread support.
            let r = z::ZSTD_CCtx_setParameter(cctx, z::ZSTD_cParameter::ZSTD_c_nbWorkers, 1);
            if z::ZSTD_isError(r) != 0 || r == 0 {
                return Err(Error::Unsupported(
                    "zstd: built without multithread support".into(),
                ));
            }
        }
        Ok(e)
    }

    /// Compress `src` as one frame, with its size in the frame header:
    /// nsz decodes NCZ blocks with a call that needs it.
    ///
    /// The frame is driven like RomVault's zstd stream: input with
    /// `ZSTD_e_continue`, then `ZSTD_e_flush` until done, then `ZSTD_e_end`
    /// until done. The flush makes the frame end with an empty last block
    /// (`01 00 00`). The context is then ready for the next frame.
    pub(crate) fn compress(&mut self, src: &[u8]) -> Result<Vec<u8>> {
        // SAFETY: `cctx` is a valid context, between frames.
        check(unsafe { z::ZSTD_CCtx_setPledgedSrcSize(self.cctx, src.len() as u64) })?;
        // SAFETY: pure function.
        let mut out = Vec::with_capacity(unsafe { z::ZSTD_compressBound(src.len()) });
        self.run(src, z::ZSTD_EndDirective::ZSTD_e_continue, &mut out)?;
        self.run(&[], z::ZSTD_EndDirective::ZSTD_e_flush, &mut out)?;
        self.run(&[], z::ZSTD_EndDirective::ZSTD_e_end, &mut out)?;
        Ok(out)
    }

    /// One `ZSTD_compressStream2` directive, until `src` is taken in
    /// (`ZSTD_e_continue`) or nothing is left to write (flush and end).
    fn run(&mut self, src: &[u8], op: z::ZSTD_EndDirective, out: &mut Vec<u8>) -> Result<()> {
        let mut input = z::ZSTD_inBuffer {
            src: src.as_ptr() as *const c_void,
            size: src.len(),
            pos: 0,
        };
        // SAFETY: pure function.
        let step = unsafe { z::ZSTD_CStreamOutSize() };
        loop {
            out.reserve(step);
            let mut output = z::ZSTD_outBuffer {
                dst: out.spare_capacity_mut().as_mut_ptr() as *mut c_void,
                size: out.capacity() - out.len(),
                pos: 0,
            };
            // SAFETY: the buffers describe valid memory of the sizes given.
            let remaining =
                check(unsafe { z::ZSTD_compressStream2(self.cctx, &mut output, &mut input, op) })?;
            // SAFETY: zstd initialized `output.pos` bytes of spare capacity.
            unsafe { out.set_len(out.len() + output.pos) };
            let done = match op {
                z::ZSTD_EndDirective::ZSTD_e_continue => input.pos == input.size,
                _ => remaining == 0,
            };
            if done {
                return Ok(());
            }
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: owned context, freed once.
        unsafe { z::ZSTD_freeCCtx(self.cctx) };
    }
}

/// Decompress the frames of `src`, at most `cap` bytes.
pub(crate) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut dst = Vec::new();
    if dst.try_reserve_exact(cap).is_err() {
        return Err(Error::InvalidData(format!(
            "zstd: cannot allocate {cap} bytes"
        )));
    }
    // SAFETY: `dst` has at least `cap` bytes of spare capacity; zstd writes
    // at most that and returns how many.
    let n = check(unsafe {
        z::ZSTD_decompress(
            dst.as_mut_ptr() as *mut c_void,
            cap,
            src.as_ptr() as *const c_void,
            src.len(),
        )
    })?;
    // SAFETY: zstd initialized the first `n <= cap` bytes.
    unsafe { dst.set_len(n) };
    Ok(dst)
}

/// [`Encoder::compress`] with a new encoder.
#[cfg(test)]
pub(crate) fn compress(src: &[u8]) -> Vec<u8> {
    Encoder::new().unwrap().compress(src).unwrap()
}

/// A streaming decompression context with libzstd's default limits.
pub(crate) struct Decoder {
    dctx: *mut z::ZSTD_DCtx,
}

// SAFETY: the context is owned and only used through `&mut self`.
unsafe impl Send for Decoder {}

impl Decoder {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: plain constructor; null is checked below.
        let dctx = unsafe { z::ZSTD_createDCtx() };
        if dctx.is_null() {
            return Err(Error::InvalidData("zstd: cannot create context".into()));
        }
        Ok(Decoder { dctx })
    }

    /// Back to the start of a stream.
    pub(crate) fn reset(&mut self) -> Result<()> {
        // SAFETY: `dctx` is a valid context.
        check(unsafe {
            z::ZSTD_DCtx_reset(self.dctx, z::ZSTD_ResetDirective::ZSTD_reset_session_only)
        })?;
        Ok(())
    }

    /// Decompress from `src` into `dst`. Returns the bytes consumed and
    /// produced, and whether the frame is finished and fully flushed.
    pub(crate) fn run(&mut self, src: &[u8], dst: &mut [u8]) -> Result<(usize, usize, bool)> {
        let mut input = z::ZSTD_inBuffer {
            src: src.as_ptr() as *const c_void,
            size: src.len(),
            pos: 0,
        };
        let mut output = z::ZSTD_outBuffer {
            dst: dst.as_mut_ptr() as *mut c_void,
            size: dst.len(),
            pos: 0,
        };
        // SAFETY: the buffers describe valid memory of the sizes given.
        let r = check(unsafe { z::ZSTD_decompressStream(self.dctx, &mut output, &mut input) })?;
        Ok((input.pos, output.pos, r == 0))
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: owned context, freed once.
        unsafe { z::ZSTD_freeDCtx(self.dctx) };
    }
}

/// Decoder of the zstd frames read from `src`, as a [`Read`].
pub(crate) struct ReadDecoder<R> {
    dec: Decoder,
    src: R,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
    frame_done: bool,
}

impl<R: Read> ReadDecoder<R> {
    /// Frames with a window over 2^`window_log_max` bytes are rejected.
    pub(crate) fn new(src: R, window_log_max: u32) -> Result<Self> {
        let dec = Decoder::new()?;
        // SAFETY: `dctx` is a valid context.
        check(unsafe {
            z::ZSTD_DCtx_setParameter(
                dec.dctx,
                z::ZSTD_dParameter::ZSTD_d_windowLogMax,
                window_log_max as i32,
            )
        })?;
        // SAFETY: pure function.
        let n = unsafe { z::ZSTD_DStreamInSize() };
        Ok(ReadDecoder {
            dec,
            src,
            buf: vec![0; n],
            pos: 0,
            len: 0,
            eof: false,
            frame_done: true,
        })
    }
}

impl<R: Read> Read for ReadDecoder<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos == self.len && !self.eof {
                self.len = self.src.read(&mut self.buf)?;
                self.pos = 0;
                self.eof = self.len == 0;
            }
            if self.pos == self.len && self.eof && self.frame_done {
                return Ok(0);
            }
            let (consumed, produced, frame_done) = self
                .dec
                .run(&self.buf[self.pos..self.len], dst)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.pos += consumed;
            self.frame_done = frame_done;
            if produced > 0 {
                return Ok(produced);
            }
            if self.eof && self.pos == self.len {
                // No input left and no progress: the frame never finished.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zstd: truncated frame",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A different libzstd changes the encoder output, which must stay the
    /// same from one release to the next.
    #[test]
    fn libzstd_is_1_5_5() {
        // SAFETY: pure function.
        assert_eq!(unsafe { z::ZSTD_versionNumber() }, LIBZSTD_VERSION);
    }

    #[test]
    fn round_trip() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i / 7) as u8).collect();
        let one = compress(&data);
        // The size is in the header, and the frame ends with an empty last
        // block.
        // SAFETY: reads at most `one.len()` bytes of `one`.
        let fcs = unsafe { z::ZSTD_getFrameContentSize(one.as_ptr() as *const c_void, one.len()) };
        assert_eq!(fcs, data.len() as u64);
        assert_eq!(one[one.len() - 3..], [1, 0, 0]);
        assert!(decompress(&one, data.len()).unwrap() == data);
        assert!(decompress(&one, data.len() - 1).is_err());

        let mut d = Decoder::new().unwrap();
        let mut out = vec![0u8; data.len()];
        let (mut used, mut done) = (0, 0);
        while done < out.len() {
            let (c, p, _) = d.run(&one[used..], &mut out[done..]).unwrap();
            used += c;
            done += p;
        }
        assert!(out == data);

        let mut back = Vec::new();
        ReadDecoder::new(&one[..], 27)
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert!(back == data);
        let mut cut = ReadDecoder::new(&one[..one.len() - 1], 27).unwrap();
        assert!(cut.read_to_end(&mut Vec::new()).is_err());
    }
}
