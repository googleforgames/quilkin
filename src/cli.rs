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

use crate::Config;
use strum_macros::{Display, EnumString};

pub use self::{
    agent::Agent,
    generate_config_schema::GenerateConfigSchema,
    manage::Manage,
    proxy::Proxy,
    qcmp::Qcmp,
    relay::Relay,
    service::{Finalizer, Service},
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
mod service;

const ETC_CONFIG_PATH: &str = "/etc/quilkin/quilkin.yaml";
const PORT_ENV_VAR: &str = "QUILKIN_PORT";

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Administration Options")]
pub struct AdminCli {
    /// Whether to spawn an administration server (metrics, profiling, etc).
    #[arg(
        long = "admin.enabled",
        env = "QUILKIN_ADMIN_ENABLED",
        value_name = "BOOL",
        num_args(0..=1),
        action=clap::ArgAction::Set,
        default_missing_value = "true",
        default_value_t = true
    )]
    enabled: bool,
    /// The address to bind for the admin server.
    #[clap(long = "admin.address", env = "QUILKIN_ADMIN_ADDRESS")]
    pub address: Option<std::net::SocketAddr>,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Locality Options")]
pub struct LocalityCli {
    /// The `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(long = "locality.region", env = "QUILKIN_LOCALITY_REGION")]
    pub region: Option<String>,
    /// The `zone` in the `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(
        long = "locality.region.zone",
        requires("region"),
        env = "QUILKIN_LOCALITY_ZONE"
    )]
    pub zone: Option<String>,
    /// The `sub_zone` in the `zone` in the `region` to set in the cluster map
    /// for any provider endpoints discovered.
    #[clap(
        long = "locality.region.sub_zone",
        requires("zone"),
        env = "QUILKIN_LOCALITY_SUB_ZONE"
    )]
    pub sub_zone: Option<String>,
}

impl LocalityCli {
    fn locality(&self) -> Option<crate::net::endpoint::Locality> {
        self.region.as_deref().map(|region| {
            crate::net::endpoint::Locality::new(
                region,
                self.zone.as_deref().unwrap_or_default(),
                self.sub_zone.as_deref().unwrap_or_default(),
            )
        })
    }
}

/// Quilkin: a non-transparent UDP proxy specifically designed for use with
/// large scale multiplayer dedicated game servers deployments, to
/// ensure security, access control, telemetry data, metrics and more.
#[derive(Debug, clap::Parser)]
#[command(version)]
#[non_exhaustive]
pub struct Cli {
    /// The path to the configuration file for the Quilkin instance.
    #[clap(short, long, env = "QUILKIN_CONFIG", default_value = "quilkin.yaml")]
    pub config: PathBuf,
    /// Whether Quilkin will report any results to stdout/stderr.
    #[clap(short, long, env)]
    pub quiet: bool,
    #[clap(subcommand)]
    pub command: Option<Commands>,
    #[clap(
     long,
     default_value_t = LogFormats::Auto,
     value_parser = clap::builder::PossibleValuesParser::new(["auto", "json", "plain", "pretty"])
     .map(|s| s.parse::<LogFormats>().unwrap()),
     )]
    pub log_format: LogFormats,
    #[command(flatten)]
    pub admin: AdminCli,
    #[command(flatten)]
    pub locality: LocalityCli,
    #[command(flatten)]
    pub providers: crate::config::providersv2::Providers,
    #[command(flatten)]
    pub service: Service,
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

impl LogFormats {
    /// Creates the tracing subscriber that pulls from the env for filters
    /// and outputs based on [Self].
    fn init_tracing_subscriber(self) {
        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .from_env_lossy();
        let subscriber = tracing_subscriber::fmt()
            .with_file(true)
            .with_thread_ids(true)
            .with_env_filter(env_filter);

        match self {
            LogFormats::Auto => {
                use std::io::IsTerminal;
                if !std::io::stdout().is_terminal() {
                    subscriber.with_ansi(false).json().init();
                } else {
                    subscriber.init();
                }
            }
            LogFormats::Json => subscriber.with_ansi(false).json().init(),
            LogFormats::Plain => subscriber.init(),
            LogFormats::Pretty => subscriber.pretty().init(),
        }
    }
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
    pub async fn drive(self) -> crate::Result<()> {
        if !self.quiet {
            self.log_format.init_tracing_subscriber();
        }

        tracing::info!(
            version = crate_version!(),
            commit = crate::net::endpoint::metadata::build::GIT_COMMIT_HASH,
            "Starting Quilkin"
        );

        // Non-long running commands (e.g. ones with no administration server)
        // are executed here.
        match self.command {
            Some(Commands::Qcmp(Qcmp::Ping(ping))) => return ping.run().await,
            Some(Commands::GenerateConfigSchema(generator)) => {
                return generator.generate_config_schema();
            }
            _ => {}
        }

        if !self.service.any_service_enabled() && self.command.is_none() {
            eyre::bail!("no service specified, shutting down");
        }

        tracing::debug!(cli = ?self, "config parameters");

        let config = Arc::new(match Self::read_config(self.config)? {
            Some(mut config) => {
                // Workaround deficiency in serde flatten + untagged
                if matches!(self.command, Some(Commands::Agent(..))) {
                    config.datacenter = match config.datacenter {
                        crate::config::DatacenterConfig::Agent {
                            icao_code,
                            qcmp_port,
                        } => crate::config::DatacenterConfig::Agent {
                            icao_code,
                            qcmp_port,
                        },
                        crate::config::DatacenterConfig::NonAgent { datacenters } => {
                            eyre::ensure!(datacenters.read().is_empty(), "starting an agent, but the configuration file has `datacenters` set");
                            crate::config::DatacenterConfig::Agent {
                                icao_code: crate::config::Slot::new(
                                    crate::config::IcaoCode::default(),
                                ),
                                qcmp_port: crate::config::Slot::new(0),
                            }
                        }
                    };
                }

                config
            }
            None if matches!(self.command, Some(Commands::Agent(..))) => Config::default_agent(),
            None => Config::default_non_agent(),
        });

        let ready = Arc::<std::sync::atomic::AtomicBool>::default();
        if self.admin.enabled {
            crate::components::admin::server(config.clone(), ready.clone(), self.admin.address);
        }

        let mut shutdown_rx = crate::signal::spawn_handler();

        crate::alloc::spawn_heap_stats_updates(
            std::time::Duration::from_secs(10),
            shutdown_rx.clone(),
        );

        let locality = self.locality.locality();
        self.providers
            .spawn_providers(&config, ready.clone(), locality.clone());

        match self.command {
            Some(Commands::Agent(agent)) => {
                let old_ready = agent::Ready {
                    provider_is_healthy: ready.clone(),
                    relay_is_healthy: ready.clone(),
                    ..<_>::default()
                };
                agent.run(locality, config, old_ready, shutdown_rx).await
            }

            Some(Commands::Proxy(runner)) => {
                let old_ready = proxy::Ready {
                    xds_is_healthy: parking_lot::RwLock::from(Some(ready.clone())).into(),
                    ..<_>::default()
                };
                runner.run(config, old_ready, None, shutdown_rx).await
            }

            Some(Commands::Manage(manager)) => {
                let old_ready = agent::Ready {
                    provider_is_healthy: ready.clone(),
                    is_manage: true,
                    ..<_>::default()
                };
                manager.run(locality, config, old_ready, shutdown_rx).await
            }

            Some(Commands::Relay(relay)) => {
                let old_ready = relay::Ready {
                    provider_is_healthy: ready.clone(),
                    ..<_>::default()
                };

                relay.run(locality, config, old_ready, shutdown_rx).await
            }
            Some(_) => unreachable!(),
            None => {
                self.service.spawn_services(&config, &shutdown_rx)?;
                shutdown_rx.changed().await.map_err(From::from)
            }
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
