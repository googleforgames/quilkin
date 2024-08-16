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

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::builder::TypedValueParser;
use clap::crate_version;
use tokio::signal;

use crate::{components::admin::Admin, Config};
use strum_macros::{Display, EnumString};

pub use self::{
    agent::Agent, generate_config_schema::GenerateConfigSchema, manage::Manage, proxy::Proxy,
    qcmp::Qcmp, relay::Relay,
};

macro_rules! define_port {
    ($port:expr) => {
        pub const PORT: u16 = $port;

        pub fn default_port() -> u16 {
            PORT
        }
    };
}

pub mod agent;
pub mod generate_config_schema;
pub mod manage;
pub mod proxy;
pub mod qcmp;
pub mod relay;

const ETC_CONFIG_PATH: &str = "/etc/quilkin/quilkin.yaml";
const PORT_ENV_VAR: &str = "QUILKIN_PORT";

/// The Command-Line Interface for Quilkin.
#[derive(Debug, clap::Parser)]
#[command(version)]
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
    #[clap(
     long,
     default_value_t = LogFormats::Auto,
     value_parser = clap::builder::PossibleValuesParser::new(["auto", "json", "plain", "pretty"])
     .map(|s| s.parse::<LogFormats>().unwrap()),
     )]
    pub log_format: LogFormats,
}

/// The various log format options
#[derive(Copy, Clone, PartialEq, Eq, Debug, EnumString, Display, Default)]
pub enum LogFormats {
    #[strum(serialize = "auto")]
    #[default]
    Auto,
    #[strum(serialize = "json")]
    Json,
    #[strum(serialize = "plain")]
    Plain,
    #[strum(serialize = "pretty")]
    Pretty,
}

/// The various Quilkin commands.
#[derive(Clone, Debug, clap::Subcommand)]
pub enum Commands {
    Agent(Agent),
    GenerateConfigSchema(GenerateConfigSchema),
    Manage(Manage),
    #[clap(subcommand)]
    Qcmp(Qcmp),
    Proxy(Proxy),
    Relay(Relay),
}

impl Cli {
    /// Drives the main quilkin application lifecycle using the command line
    /// arguments.
    #[tracing::instrument(skip_all)]
    pub async fn drive(self, tx: Option<tokio::sync::oneshot::Sender<()>>) -> crate::Result<()> {
        if !self.quiet {
            let env_filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy();
            let subscriber = tracing_subscriber::fmt()
                .with_file(true)
                .with_thread_ids(true)
                .with_env_filter(env_filter);

            match self.log_format {
                LogFormats::Auto => {
                    use std::io::IsTerminal;
                    if !std::io::stdout().is_terminal() {
                        subscriber.json().init();
                    } else {
                        subscriber.init();
                    }
                }
                LogFormats::Json => subscriber.json().init(),
                LogFormats::Plain => subscriber.init(),
                LogFormats::Pretty => subscriber.pretty().init(),
            }
        }

        tracing::info!(
            version = crate_version!(),
            commit = crate::net::endpoint::metadata::build::GIT_COMMIT_HASH,
            "Starting Quilkin"
        );

        // Non-long running commands (e.g. ones with no administration server)
        // are executed here.
        use crate::components::{self, admin as admin_server};
        let mode = match &self.command {
            Commands::Qcmp(Qcmp::Ping(ping)) => return ping.run().await,
            Commands::GenerateConfigSchema(generator) => {
                return generator.generate_config_schema();
            }
            Commands::Agent(_) => Admin::Agent(<_>::default()),
            Commands::Proxy(proxy) => {
                let ready = components::proxy::Ready {
                    idle_request_interval: proxy
                        .idle_request_interval_secs
                        .map(std::time::Duration::from_secs)
                        .unwrap_or(admin_server::IDLE_REQUEST_INTERVAL),
                    ..Default::default()
                };
                Admin::Proxy(ready)
            }
            Commands::Manage(_mng) => {
                let ready = components::manage::Ready {
                    is_manage: true,
                    ..Default::default()
                };
                Admin::Manage(ready)
            }
            Commands::Relay(relay) => {
                let ready = components::relay::Ready {
                    idle_request_interval: relay
                        .idle_request_interval_secs
                        .map(std::time::Duration::from_secs)
                        .unwrap_or(admin_server::IDLE_REQUEST_INTERVAL),
                    ..Default::default()
                };
                Admin::Relay(ready)
            }
        };

        tracing::debug!(cli = ?self, "config parameters");

        let config = Arc::new(match Self::read_config(self.config)? {
            Some(config) => config,
            None if matches!(self.command, Commands::Agent(..)) => Config::default_agent(),
            None => Config::default_non_agent(),
        });

        if !self.no_admin {
            mode.server(config.clone(), self.admin_address);
        }

        let (shutdown_tx, shutdown_rx) = crate::make_shutdown_channel(Default::default());
        crate::alloc::spawn_heap_stats_updates(
            std::time::Duration::from_secs(10),
            shutdown_rx.clone(),
        );

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
            shutdown_tx.send(crate::ShutdownKind::Normal).ok();
        });

        match (self.command, mode) {
            (Commands::Agent(agent), Admin::Agent(ready)) => {
                agent.run(config, ready, shutdown_rx).await
            }
            (Commands::Proxy(runner), Admin::Proxy(ready)) => {
                runner.run(config, ready, tx, shutdown_rx).await
            }
            (Commands::Manage(manager), Admin::Manage(ready)) => {
                manager.run(config, ready, shutdown_rx).await
            }
            (Commands::Relay(relay), Admin::Relay(ready)) => {
                relay.run(config, ready, shutdown_rx).await
            }
            _ => unreachable!(),
        }
    }

    /// Searches for the configuration file, and panics if not found.
    fn read_config<A: AsRef<Path>>(path: A) -> Result<Option<Config>, eyre::Error> {
        let path = path.as_ref();
        let from_reader = |file| Config::from_reader(file).map_err(From::from).map(Some);

        match std::fs::File::open(path) {
            Ok(file) => (from_reader)(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path=%path.display(), "provided path not found");
                match cfg!(unix).then(|| std::fs::File::open(ETC_CONFIG_PATH)) {
                    Some(Ok(file)) => (from_reader)(file),
                    Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!(path=%path.display(), "/etc path not found");
                        Ok(None)
                    }
                    Some(Err(error)) => Err(error.into()),
                    None => Ok(None),
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}
