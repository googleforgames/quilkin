/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::sync::Arc;

use crate::Config;

pub mod completion;
pub mod nic;
pub mod poll;

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub struct Listener {
    /// ID of the worker.
    pub worker_id: usize,
    pub port: u16,
    pub config: Arc<Config>,
    pub sessions: Arc<crate::net::sessions::SessionPool>,
    pub buffer_pool: Arc<crate::collections::BufferPool>,
}
