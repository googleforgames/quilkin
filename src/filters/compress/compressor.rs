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

use std::io;

use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

/// A trait that provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
pub(crate) trait Compressor {
    /// Compress the contents of the Vec - overwriting the original content.
    fn encode(&self, contents: &mut Vec<u8>) -> io::Result<()>;
    /// Decompress the contents of the Vec - overwriting the original content.
    fn decode(&self, contents: &mut Vec<u8>) -> io::Result<()>;
}

pub(crate) struct Snappy {}

impl Compressor for Snappy {
    fn encode(&self, contents: &mut Vec<u8>) -> io::Result<()> {
        let input = std::mem::take(contents);
        let mut wtr = FrameEncoder::new(contents);
        io::copy(&mut input.as_slice(), &mut wtr)?;
        Ok(())
    }

    fn decode(&self, contents: &mut Vec<u8>) -> io::Result<()> {
        let input = std::mem::take(contents);
        let mut rdr = FrameDecoder::new(input.as_slice());
        io::copy(&mut rdr, contents)?;
        Ok(())
    }
}
