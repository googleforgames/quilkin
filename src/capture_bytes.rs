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

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Strategy to apply for acquiring a set of bytes in a packet
pub enum Strategy {
    #[serde(rename = "PREFIX")]
    /// Looks for the set of bytes at the beginning of the packet
    Prefix,
    #[serde(rename = "SUFFIX")]
    /// Look for the set of bytes at the end of the packet
    Suffix,
}

pub struct Context {
    pub strategy: Strategy,
    pub size: usize,
    pub remove: bool,
}

pub struct ProcessedPacket {
    pub packet: Vec<u8>,
    pub captured_bytes: Vec<u8>,
}

impl Context {
    /// Captures bytes from the input packet according to the configured parameters.
    /// Returns None if the input packet is too small to contain the configured capture
    /// size.
    pub fn capture(&self, mut packet: Vec<u8>) -> Option<ProcessedPacket> {
        if self.size > packet.len() {
            return None;
        }

        let size = self.size;
        let captured_bytes = match self.strategy {
            Strategy::Prefix => {
                if self.remove {
                    packet.drain(..size).collect()
                } else {
                    packet.iter().cloned().take(size).collect()
                }
            }
            Strategy::Suffix => {
                if self.remove {
                    packet.split_off(packet.len() - size)
                } else {
                    packet.iter().skip(packet.len() - size).cloned().collect()
                }
            }
        };

        Some(ProcessedPacket {
            packet,
            captured_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Context, Strategy};

    #[test]
    fn capture() {
        let tests = vec![
            // (capture_strategy, capture_remove, expected_packet, expected_capture)
            (Strategy::Prefix, true, "ello", "h"),
            (Strategy::Prefix, false, "hello", "h"),
            (Strategy::Suffix, true, "hell", "o"),
            (Strategy::Suffix, false, "hello", "o"),
        ];

        for (strategy, remove, expected_packet, expected_capture) in tests {
            let processed_packet = Context {
                strategy,
                size: 1,
                remove,
            }
            .capture("hello".to_string().into_bytes())
            .unwrap();

            assert_eq!(
                expected_packet,
                String::from_utf8(processed_packet.packet).unwrap()
            );

            assert_eq!(
                expected_capture,
                String::from_utf8(processed_packet.captured_bytes).unwrap()
            );
        }
    }

    #[test]
    fn capture_packet_too_small() {
        let tests = vec![
            // (capture_strategy, capture_remove, expected_packet)
            (Strategy::Prefix, true),
            (Strategy::Suffix, true),
            (Strategy::Prefix, false),
            (Strategy::Suffix, false),
        ];
        for (strategy, remove) in tests {
            let ctx = Context {
                strategy,
                size: 6,
                remove,
            };

            assert!(ctx.capture("hello".to_string().into_bytes()).is_none());
            assert!(ctx.capture("hello!".to_string().into_bytes()).is_some());
        }
    }
}
