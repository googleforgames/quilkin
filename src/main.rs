/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use std::fs::File;

use clap::App;
use slog::{info, o, Drain, Logger};

use crate::config::{from_reader, ConnectionConfig};
use crate::server::Server;

mod config;
mod server;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let base_logger = logger();
    let log = base_logger.new(o!("source" => "main"));

    let matches = App::new("Quilkin Proxy")
        .version("0.1.0")
        .about("Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers")
        .arg(clap::Arg::with_name("filename")
            .short("f")
            .long("filename")
            .value_name("FILE")
            .help("The yaml configuration file")
            .required(true)
            .takes_value(true))
        .get_matches();

    let filename = matches.value_of("filename").unwrap();
    info!(log, "Starting Quilkin"; "version" => VERSION);

    let config = from_reader(File::open(filename).unwrap()).unwrap();
    match config.connections {
        ConnectionConfig::Sender { address, .. } => {
            info!(log, "Sender configuration"; "address" => address)
        }
        ConnectionConfig::Receiver { endpoints } => {
            info!(log, "Receiver configuration"; "endpoints" => endpoints.len())
        }
    }

    let _server = Server::new(base_logger);
}

fn logger() -> Logger {
    let drain = slog_json::Json::new(std::io::stdout())
        .set_pretty(false)
        .add_default_keys()
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());
    return log;
}
