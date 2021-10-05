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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind to UDP socket on address: {0}")]
    BindUdpSocket(tokio::io::Error),
    #[error("failed to send a packet to the destination address: {0}")]
    SendToDst(std::io::Error),
    #[error("failed to update session expiration time: {0}")]
    UpdateSessionExpiration(String),
    #[error("packet was dropped because it has a different version from the session's configured version")]
    VersionMismatch,
}
