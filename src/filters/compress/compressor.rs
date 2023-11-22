/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::pool::{BufferPool, PoolBuffer};
use parking_lot::Mutex;
use std::{io, sync::Arc};

use lz4_flex::block;
use snap::raw;

/// A trait that provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
pub(crate) enum Compressor {
    Snappy(SnappyImpl),
    Lz4,
}

impl Compressor {
    pub fn encode(&self, pool: Arc<BufferPool>, contents: &mut PoolBuffer) -> io::Result<()> {
        let encoded = match self {
            Self::Snappy(imp) => {
                let size = raw::max_compress_len(contents.len());
                let mut encoded = pool.alloc_sized(size);

                let mut encoder = imp.encoder();

                let res = encoder.compress(contents, encoded.as_mut_slice(0..size));
                imp.absorb(encoder);

                let compressed = res?;
                encoded.truncate(compressed);
                encoded
            }
            Self::Lz4 => {
                let size = block::get_maximum_output_size(contents.len()) + 3;
                let mut encoded = pool.alloc_sized(size);

                let slen = size::write(encoded.as_mut_slice(0..size), contents.len() as u16);

                let compressed = block::compress_into(contents, encoded.as_mut_slice(slen..size))
                    .map_err(|_e| {
                    // This should be impossible
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "not enough space allocated for compressed output",
                    )
                })?;

                encoded.truncate(compressed + slen);
                encoded
            }
        };

        *contents = encoded;
        Ok(())
    }

    pub fn decode(&self, pool: Arc<BufferPool>, contents: &mut PoolBuffer) -> io::Result<()> {
        let decoded = match self {
            Self::Snappy(_imp) => {
                let size = raw::decompress_len(contents)?;
                let mut decoded = pool.alloc_sized(size);

                let decompressed =
                    raw::Decoder::new().decompress(contents, decoded.as_mut_slice(0..size))?;

                decoded.truncate(decompressed);
                decoded
            }
            Self::Lz4 => {
                let (size, slen) = size::read(contents);
                let mut decoded = pool.alloc_sized(size as _);

                let decompressed =
                    block::decompress_into(&contents[slen..], decoded.as_mut_slice(0..size as _))
                        .map_err(|_e| {
                        // This should be impossible
                        io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "not enough space allocated for decompressed output",
                        )
                    })?;

                decoded.truncate(decompressed);
                decoded
            }
        };

        *contents = decoded;
        Ok(())
    }
}

impl From<super::Mode> for Compressor {
    fn from(mode: super::Mode) -> Self {
        match mode {
            super::Mode::Snappy => Self::Snappy(SnappyImpl {
                encoders: Mutex::new(Vec::new()),
            }),
            super::Mode::Lz4 => Self::Lz4,
        }
    }
}

pub struct SnappyImpl {
    encoders: Mutex<Vec<raw::Encoder>>,
}

impl SnappyImpl {
    #[inline]
    fn encoder(&self) -> raw::Encoder {
        self.encoders.lock().pop().unwrap_or_else(raw::Encoder::new)
    }

    #[inline]
    fn absorb(&self, enc: raw::Encoder) {
        self.encoders.lock().push(enc);
    }
}

/// Sadly lz4_flex only has prepends the size when compressing to its own
/// allocated vector, so we can't use it, so we just implement our own based
/// on <https://developers.google.com/protocol-buffers/docs/encoding#varints>,
/// and bonus points, we have up to 3 bytes from the payload since lz4_flex always
/// encodes a full 4 byte u32, regardless of the actual length (which in our case
/// will always be <64k
mod size {
    #[inline]
    pub(super) fn write(data: &mut [u8], mut n: u16) -> usize {
        let mut i = 0;
        while n >= 0b1000_0000 {
            data[i] = (n as u8) | 0b1000_0000;
            n >>= 7;
            i += 1;
        }
        data[i] = n as u8;
        i + 1
    }

    #[inline]
    pub(super) fn read(data: &[u8]) -> (u16, usize) {
        let mut n: u16 = 0;
        let mut shift: u32 = 0;
        for (i, &b) in data.iter().enumerate() {
            if b < 0b1000_0000 {
                return match (b as u16).checked_shl(shift) {
                    None => (0, 0),
                    Some(b) => (n | b, i + 1),
                };
            }
            match ((b as u16) & 0b0111_1111).checked_shl(shift) {
                None => return (0, 0),
                Some(b) => n |= b,
            }
            shift += 7;
        }
        (0, 0)
    }
}
