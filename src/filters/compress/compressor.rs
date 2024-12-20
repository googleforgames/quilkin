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

use crate::filters::Packet;
use parking_lot::Mutex;
use std::io;

use lz4_flex::block;
use snap::raw;

/// A trait that provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
pub enum Compressor {
    Snappy(SnappyImpl),
    Lz4,
}

impl Compressor {
    pub fn encode<P: Packet>(&self, contents: &P) -> io::Result<P> {
        let input = contents.as_slice();
        let encoded = match self {
            Self::Snappy(imp) => {
                let size = raw::max_compress_len(input.len());
                let mut encoded = contents.alloc_sized(size).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "failed to allocate buffer for compress output",
                    )
                })?;

                let mut encoder = imp.encoder();

                let res = encoder.compress(input, &mut encoded.as_mut_slice()[..dbg!(size)]);
                imp.absorb(encoder);

                encoded.set_len(res?);
                encoded
            }
            Self::Lz4 => {
                let size = block::get_maximum_output_size(input.len()) + 3;
                let mut encoded = contents.alloc_sized(size).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "failed to allocate buffer for compress output",
                    )
                })?;

                let slen = size::write(encoded.as_mut_slice(), input.len() as u16);

                let compressed =
                    block::compress_into(input, &mut encoded.as_mut_slice()[slen..size]).map_err(
                        |_e| {
                            // This should be impossible
                            io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "not enough space allocated for compressed output",
                            )
                        },
                    )?;

                encoded.set_len(compressed + slen);
                encoded
            }
        };

        Ok(encoded)
    }

    pub fn decode<P: Packet>(&self, contents: &P) -> io::Result<P> {
        let input = contents.as_slice();
        let decoded = match self {
            Self::Snappy(_imp) => {
                let size = raw::decompress_len(input)?;
                let mut decoded = contents.alloc_sized(size).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "failed to allocate buffer for decompress output",
                    )
                })?;

                let decompressed = raw::Decoder::new().decompress(input, decoded.as_mut_slice())?;

                decoded.set_len(decompressed);
                decoded
            }
            Self::Lz4 => {
                let (size, slen) = size::read(input);
                let mut decoded = contents.alloc_sized(size as _).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "failed to allocate buffer for decompress output",
                    )
                })?;

                let decompressed = block::decompress_into(&input[slen..], decoded.as_mut_slice())
                    .map_err(|_e| {
                    // This should be impossible
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "not enough space allocated for decompressed output",
                    )
                })?;

                decoded.set_len(decompressed);
                decoded
            }
        };

        Ok(decoded)
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
