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

//! Well known dynamic metadata used by Quilkin.

/// The default key under which the [`super::capture_bytes`] filter puts the
/// byte slices it extracts from each packet.
/// - **Type** `Vec<u8>`
pub const CAPTURED_BYTES: &str = "quilkin.dev/captured_bytes";

/// The default key under which the [`super::regex`] filter puts the
/// byte slices it extracts from each packet.
/// - **Type** `Vec<u8>`
pub const REGEX: &str = "quilkin.dev/regex";
