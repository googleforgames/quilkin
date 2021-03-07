/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use crate::proxy::sessions::error::Error as SessionError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Initialize(String),
    Session(SessionError),
    Bind(tokio::io::Error),
    RecvLoop(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Initialize(reason) => write!(f, "failed to startup properly: {}", reason),
            Error::Session(inner) => write!(f, "session error: {}", inner),
            Error::Bind(inner) => write!(f, "failed to bind to port: {}", inner),
            Error::RecvLoop(reason) => write!(f, "receive loop exited with an error: {}", reason),
        }
    }
}
