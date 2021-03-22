/*
 * Copyright 2021 Google LLC All Rights Reserved.
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
use slog::{info, o, Logger};
use tokio::signal;
use tokio::sync::watch;

use crate::config::Config;
use crate::extensions::{default_registry, FilterFactory, FilterRegistry};
use crate::proxy::{logger, Builder};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(debug_assertions)]
fn version() -> String {
    format!("{}+debug", VERSION)
}

#[cfg(not(debug_assertions))]
fn version() -> String {
    VERSION.into()
}

/// Wraps an error message returned by [`run`].
#[derive(Debug)]
pub struct Error(String);

/// Start and run a proxy. Any passed in [`FilterFactory`] are included
/// alongside the default filter factories..
pub async fn run(filter_factories: Vec<Box<dyn FilterFactory>>) -> Result<(), Error> {
    let version = version();
    let base_logger = logger();
    let log = base_logger.new(o!("source" => "run"));

    let matches = App::new("Quilkin Proxy")
        .version(version.as_str())
        .about("Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers")
        .arg(clap::Arg::with_name("filename")
            .short("f")
            .long("filename")
            .value_name("FILE")
            .help("The yaml configuration file")
            .required(true)
            .takes_value(true))
        .get_matches();

    let filename = matches
        .value_of("filename")
        .ok_or_else(|| Error("missing argument `filename`".into()))?;
    info!(log, "Starting Quilkin"; "version" => version);

    let config = Arc::new(
        Config::from_reader(File::open(filename).map_err(|err| Error(format!("{}", err)))?)
            .map_err(|err| Error(format!("{}", err)))?,
    );
    let server = Builder::from(config)
        .with_log(base_logger)
        .with_filter_registry(create_filter_registry(&log, filter_factories))
        .validate()
        .map_err(|err| Error(format!("{:?}", err)))?
        .build();

    let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
    tokio::spawn(async move {
        // Don't unwrap in order to ensure that we execute
        // any subsequent shutdown tasks.
        signal::ctrl_c().await.ok();
        shutdown_tx.send(()).ok();
    });

    match server.run(shutdown_rx).await {
        Ok(()) => {
            info!(log, "Shutting down");
            Ok(())
        }
        Err(err) => {
            info!(log, "Shutting down with error"; "error" => %err);
            Err(Error(format!("{:?}", err)))
        }
    }
}

fn create_filter_registry(
    log: &Logger,
    additional_filter_factories: Vec<Box<dyn FilterFactory>>,
) -> FilterRegistry {
    let mut registry = default_registry(log);
    registry.insert_all(additional_filter_factories);
    registry
}
