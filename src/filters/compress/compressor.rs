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

use snap::raw;

/// A trait that provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
pub(crate) enum Compressor {
    Snappy(SnappyImpl),
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
