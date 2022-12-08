/*
 * Copyright 2022 Google LLC
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

mod generate_config_schema;
mod manage;
mod proxy;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{signal, sync::watch};

use crate::{admin::Mode, Config};

pub use self::{
    generate_config_schema::GenerateConfigSchema,
    manage::{Manage, Providers},
    proxy::Proxy,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ETC_CONFIG_PATH: &str = "/etc/quilkin/quilkin.yaml";

/// The Command-Line Interface for Quilkin.
#[derive(clap::Parser)]
#[non_exhaustive]
pub struct Cli {
    /// Whether to spawn the admin server or not.
    #[clap(env, long)]
    pub no_admin: bool,
    /// The path to the configuration file for the Quilkin instance.
    #[clap(short, long, env = "QUILKIN_CONFIG", default_value = "quilkin.yaml")]
    pub config: PathBuf,
    /// The port to bind for the admin server
    #[clap(long, env = "QUILKIN_ADMIN_ADDRESS")]
    pub admin_address: Option<std::net::SocketAddr>,
    /// Whether Quilkin will report any results to stdout/stderr.
    #[clap(short, long, env)]
    pub quiet: bool,
    #[clap(subcommand)]
    pub command: Commands,
}

/// The various Quilkin commands.
#[derive(Clone, clap::Subcommand)]
pub enum Commands {
    Proxy(Proxy),
    GenerateConfigSchema(GenerateConfigSchema),
    Manage(Manage),
}

impl Commands {
    pub fn admin_mode(&self) -> Option<Mode> {
        match self {
            Self::Proxy(_) => Some(Mode::Proxy),
            Self::Manage(_) => Some(Mode::Xds),
            Self::GenerateConfigSchema(_) => None,
        }
    }
}

impl Cli {
    /// Drives the main quilkin application lifecycle using the command line
    /// arguments.
    #[tracing::instrument(skip_all)]
    pub async fn drive(self) -> crate::Result<()> {
        let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
            format!("{VERSION}+debug").into()
        } else {
            VERSION.into()
        };

        if !self.quiet {
            let env_filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy();
            tracing_subscriber::fmt()
                .json()
                .with_file(true)
                .with_env_filter(env_filter)
                .init();
        }

        tracing::info!(
            version = &*version,
            commit = crate::metadata::build::GIT_COMMIT_HASH,
            "Starting Quilkin"
        );

        let config = Arc::new(Self::read_config(self.config)?);
        let _admin_task = if let Some(mode) = self.command.admin_mode().filter(|_| !self.no_admin) {
            if let Some(address) = self.admin_address {
                config
                    .admin
                    .store(Arc::new(crate::config::Admin { address }));
            }
            Some(tokio::spawn(crate::admin::server(mode, config.clone())))
        } else {
            config.admin.remove();
            None
        };

        let (shutdown_tx, mut shutdown_rx) = watch::channel::<()>(());

        #[cfg(target_os = "linux")]
        let mut sig_term_fut = signal::unix::signal(signal::unix::SignalKind::terminate())?;

        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            let sig_term = sig_term_fut.recv();
            #[cfg(not(target_os = "linux"))]
            let sig_term = std::future::pending();

            let signal = tokio::select! {
                _ = signal::ctrl_c() => "SIGINT",
                _ = sig_term => "SIGTERM",
            };

            tracing::info!(%signal, "shutting down from signal");
            // Don't unwrap in order to ensure that we execute
            // any subsequent shutdown tasks.
            shutdown_tx.send(()).ok();
        });

        let fut = tryhard::retry_fn({
            let shutdown_rx = shutdown_rx.clone();
            move || match self.command.clone() {
                Commands::Proxy(runner) => {
                    let config = config.clone();
                    let shutdown_rx = shutdown_rx.clone();
                    tokio::spawn(
                        async move { runner.run(config.clone(), shutdown_rx.clone()).await },
                    )
                }
                Commands::Manage(manager) => {
                    let config = config.clone();
                    tokio::spawn(async move { manager.manage(config.clone()).await })
                }
                Commands::GenerateConfigSchema(generator) => {
                    tokio::spawn(std::future::ready(generator.generate_config_schema()))
                }
            }
        })
        .retries(3)
        .on_retry(|_, _, error| {
            let error = error.to_string();
            async move {
                tracing::warn!(%error, "error would have caused fatal crash");
            }
        });

        tokio::select! {
            result = fut => result?,
            _ = shutdown_rx.changed() => Ok(())
        }
    }

    /// Searches for the configuration file, and panics if not found.
    fn read_config<A: AsRef<Path>>(path: A) -> Result<Config, eyre::Error> {
        let path = path.as_ref();
        let from_reader = |file| Config::from_reader(file).map_err(From::from);

        match std::fs::File::open(path) {
            Ok(file) => (from_reader)(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path=%path.display(), "provided path not found");
                match cfg!(unix).then(|| std::fs::File::open(ETC_CONFIG_PATH)) {
                    Some(Ok(file)) => (from_reader)(file),
                    Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!(path=%path.display(), "/etc path not found");
                        Ok(Config::default())
                    }
                    Some(Err(error)) => Err(error.into()),
                    None => Ok(Config::default()),
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}
