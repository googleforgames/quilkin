/*
 * Copyright 2021 Google LLC
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

use std::{fs::File, sync::Arc};

use clap::App;
use slog::{info, o};
use tokio::{signal, sync::watch};

use crate::{
    config::Config,
    filters::{DynFilterFactory, FilterRegistry, FilterSet},
    proxy::{logger, Builder},
};

#[cfg(doc)]
use crate::filters::FilterFactory;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONFIG_FILE: &str = "quilkin.yaml";

pub type Error = Box<dyn std::error::Error>;

#[cfg(debug_assertions)]
fn version() -> String {
    format!("{}+debug", VERSION)
}

#[cfg(not(debug_assertions))]
fn version() -> String {
    VERSION.into()
}

/// Start and run a proxy. Any passed in [`FilterFactory`]s are included
/// alongside the default filter factories.
pub async fn run(
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<(), Error> {
    let version = version();
    let base_logger = logger();
    let log = base_logger.new(o!("source" => "run"));

    let matches = App::new(clap::crate_name!())
        .version(version.as_str())
        .about(clap::crate_description!())
        .arg(
            clap::Arg::with_name("filename")
                .short("f")
                .long("filename")
                .value_name("FILE")
                .help("The yaml configuration file")
                .takes_value(true),
        )
        .get_matches();

    let config_env = std::env::var("QUILKIN_FILENAME").ok();
    let config_path = matches
        .value_of("filename")
        .or_else(|| config_env.as_deref())
        .or(Some(CONFIG_FILE))
        .map(|path| std::path::Path::new(path).canonicalize())
        .transpose()
        // Path wll always be `Some` here.
        .map(Option::unwrap)?;

    info!(log, "Starting Quilkin"; "version" => version);

    let config = File::open(&config_path)
        .or_else(|_| get_config_file())
        .map_err(Error::from)
        .and_then(|file| Config::from_reader(file).map_err(Error::from))
        .map(Arc::new)?;

    info!(log, "Found configuration file"; "path" => config_path.display());

    let server = Builder::from(config)
        .with_log(base_logger)
        .with_filter_registry(FilterRegistry::new(FilterSet::default_with(
            &log,
            filter_factories.into_iter(),
        )))
        .validate()?
        .build();

    let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
    tokio::spawn(async move {
        // Don't unwrap in order to ensure that we execute
        // any subsequent shutdown tasks.
        signal::ctrl_c().await.ok();
        shutdown_tx.send(()).ok();
    });

    if let Err(err) = server.run(shutdown_rx).await {
        info!(log, "Shutting down with error"; "error" => %err);
        Err(Error::from(err))
    } else {
        info!(log, "Shutting down");
        Ok(())
    }
}

fn get_config_file() -> Result<File, std::io::Error> {
    std::fs::File::open("./quilkin.yaml").or_else(|error| {
        if cfg!(unix) {
            std::fs::File::open("/etc/quilkin/quilkin.yaml")
        } else {
            Err(error)
        }
    })
}
