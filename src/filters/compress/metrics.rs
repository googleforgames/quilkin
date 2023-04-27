/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use prometheus::IntCounter;

use crate::{
    filters::{metrics, StaticFilter},
    metrics::Direction,
};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) read_compressed_bytes_total: IntCounter,
    pub(super) read_decompressed_bytes_total: IntCounter,
    pub(super) write_compressed_bytes_total: IntCounter,
    pub(super) write_decompressed_bytes_total: IntCounter,
}

fn compressed_bytes_total(direction: Direction) -> IntCounter {
    metrics::counter(
        super::Compress::NAME,
        "compressed_bytes_total",
        "Total number of compressed bytes either received or sent.",
        direction,
    )
}

fn decompressed_bytes_total(direction: Direction) -> IntCounter {
    metrics::counter(
        super::Compress::NAME,
        "decompressed_bytes_total",
        "Total number of decompressed bytes either received or sent.",
        direction,
    )
}

impl Metrics {
    pub(super) fn new() -> Self {
        Self {
            read_compressed_bytes_total: compressed_bytes_total(Direction::Read),
            read_decompressed_bytes_total: decompressed_bytes_total(Direction::Read),
            write_compressed_bytes_total: compressed_bytes_total(Direction::Write),
            write_decompressed_bytes_total: decompressed_bytes_total(Direction::Write),
        }
    }
}
