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

use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    BindUdpSocket(tokio::io::Error),
    UpdateSessionExpiration(String),
    ToSocketAddr(eyre::Report),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::BindUdpSocket(inner) => {
                write!(f, "failed to bind to UDP socket on address: {}", inner)
            }
            Error::UpdateSessionExpiration(reason) => {
                write!(f, "failed to update session expiration time: {}", reason)
            }
            Error::ToSocketAddr(reason) => {
                write!(f, "failed to convert endpoint to address: {}", reason)
            }
        }
    }
}

impl std::error::Error for Error {}
