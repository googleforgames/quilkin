/*
 * Copyright 2020 Google LLC
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

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new<S: std::fmt::Display>(message: S) -> Self {
        Error {
            message: message.to_string(),
        }
    }
}

impl From<prometheus::Error> for Error {
    fn from(error: prometheus::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<crate::filters::chain::Error> for Error {
    fn from(error: crate::filters::chain::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}
