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

mod config;

use crate::config::{from_reader, ConnectionConfig};
use clap::App;
use std::fs::File;

fn main() {
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
    println!("Configuration file loading: {}", filename);
    let config = from_reader(File::open(filename).unwrap()).unwrap();

    match config.connections {
        ConnectionConfig::Sender { address, .. } => {
            println!("Sender configuration pointed at: {}", address)
        }
        ConnectionConfig::Receiver { endpoints } => {
            println!("Receiver configuration, with {} endpoints", endpoints.len())
        }
    }
}
