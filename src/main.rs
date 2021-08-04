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

use std::sync::Arc;

use quilkin::runner;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), quilkin::runner::Error> {
    let log = quilkin::proxy::logger();
    let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
        format!("{}+debug", VERSION).into()
    } else {
        VERSION.into()
    };

    slog::info!(log, "Starting Quilkin"; "version" => &*version);

    let matches = clap::App::new(clap::crate_name!())
        .version(&*version)
        .about(clap::crate_description!())
        .arg(
            clap::Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("CONFIG")
                .help("The YAML configuration file")
                .takes_value(true),
        )
        .get_matches();

    let config = quilkin::config::Config::find(&log, matches.value_of("config")).map(Arc::new)?;

    runner::run_with_config(log, config, vec![]).await
}
