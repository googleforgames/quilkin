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
use std::sync::Arc;

use clap::App;
use slog::{info, o};

use prometheus::Registry;
use quilkin::config::Config;
use quilkin::proxy::{logger, Builder, Metrics};
use tokio::signal;
use tokio::sync::oneshot;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
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

    let config = Arc::new(Config::from_reader(File::open(filename).unwrap()).unwrap());
    let server = Builder::from(config)
        .with_log(base_logger)
        .with_metrics(Metrics::new(
            Some("[::]:9091".parse().unwrap()),
            Registry::default(),
        ))
        .validate()
        .unwrap()
        .build();

    let (close, stop) = oneshot::channel::<()>();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        close.send(()).unwrap();
    });

    server.run(stop).await.unwrap();
    info!(log, "Shutting down");
}
