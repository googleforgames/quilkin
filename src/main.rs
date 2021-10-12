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
    stable_eyre::install()?;

    let log = quilkin::logger();
    let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
        format!("{}+debug", VERSION).into()
    } else {
        VERSION.into()
    };

    const CONFIG_ARG: &str = "config";
    const ECHO_SERVER_ARG: &str = "echo-server";

    let config_arg = Arg::with_name(CONFIG_ARG)
        .short("c")
        .long(CONFIG_ARG)
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
                .arg(config_arg)
                .arg(Arg::with_name(ECHO_SERVER_ARG).long(ECHO_SERVER_ARG).help(
                    "Spawns a simple echo server for checking test \
                           output instead of sending data to `endpoints`. \
                           Default: `true` if `endpoints` is empty.",
                )),
        )
        .get_matches();

    slog::info!(log, "Starting Quilkin"; "version" => &*version);

    match cli.subcommand() {
        ("run", Some(matches)) => {
            let config =
                quilkin::config::Config::find(&log, matches.value_of(CONFIG_ARG)).map(Arc::new)?;

            quilkin::run_with_config(log, config, vec![]).await
        }

        ("test", Some(matches)) => {
            let mut testsuite =
                quilkin::config::TestSuite::find(&log, matches.value_of(CONFIG_ARG))?;

            if testsuite
                .config
                .source
                .get_static_endpoints()
                .map_or(false, |ep| ep.is_empty())
                || matches.is_present(ECHO_SERVER_ARG)
            {
                testsuite.use_echo_server = true;
            }

            quilkin::test(log, testsuite, vec![]).await
        }

        (_, _) => unreachable!(),
    }
}
