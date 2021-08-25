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

use clap::{App, AppSettings, Arg, SubCommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> quilkin::Result<()> {
    let log = quilkin::logger();
    let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
        format!("{}+debug", VERSION).into()
    } else {
        VERSION.into()
    };

    let config_arg = Arg::with_name("config")
        .short("c")
        .long("config")
        .value_name("CONFIG")
        .help("The YAML configuration file")
        .takes_value(true);

    let cli = App::new(clap::crate_name!())
        .version(&*version)
        .about(clap::crate_description!())
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("run")
                .about("Start Quilkin process.")
                .arg(config_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("test")
                .about("Execute one or more sets of tests.")
                .arg(config_arg),
        )
        .get_matches();

    slog::info!(log, "Starting Quilkin"; "version" => &*version);

    match cli.subcommand() {
        ("run", Some(matches)) => {
            let config =
                quilkin::config::Config::find(&log, matches.value_of("config")).map(Arc::new)?;

            quilkin::run_with_config(log, config, vec![]).await
        }

        ("test", Some(_matches)) => todo!(),

        (_, _) => unreachable!(),
    }
}
