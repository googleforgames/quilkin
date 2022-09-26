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

#[tokio::main]
async fn main() {
    // Unwrap is safe here as it will only fail if called more than once.
    stable_eyre::install().unwrap();

    match <quilkin::Cli as clap::Parser>::parse().drive().await {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            tracing::error!(%error, "fatal error");
            std::process::exit(-1)
        }
    }
}
