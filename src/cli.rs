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

use std::{path::PathBuf, sync::Arc};

use clap::builder::TypedValueParser;
use clap::crate_version;

use strum_macros::{Display, EnumString};

pub use self::{generate_config_schema::GenerateConfigSchema, qcmp::Qcmp};

pub mod generate_config_schema;
pub mod qcmp;

const ETC_CONFIG_PATH: &str = "/etc/quilkin/quilkin.yaml";

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
    /// The airport ICAO code for the `region` of the instance. When provided
    /// enables geomapping metrics of instances.
    #[clap(
        long = "locality.icao",
        env = "QUILKIN_LOCALITY_ICAO",
        default_value_t = crate::config::IcaoCode::default()
    )]
    pub icao_code: crate::config::IcaoCode,
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
    /// The file prefix used for log files
    #[clap(
        long = "sys.log.file-prefix",
        env = "QUILKIN_SYS_LOG_FILE_PREFIX",
        default_value = "quilkin.log"
    )]
    pub log_file_prefix: String,
    /// An optional log file directory path that quilkin should log to
    #[clap(long = "sys.log.dir", env = "QUILKIN_SYS_LOG_DIRECTORY")]
    pub log_directory: Option<PathBuf>,
    #[command(flatten)]
    pub admin: AdminCli,
    #[command(flatten)]
    pub locality: LocalityCli,
    #[command(flatten)]
    pub providers: crate::config::providers::Providers,
    #[command(flatten)]
    pub service: crate::service::Service,
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
    fn init_tracing_subscriber(
        self,
        quiet: bool,
        file_writer: Option<tracing_appender::non_blocking::NonBlocking>,
    ) {
        use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};

        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .from_env_lossy();

        let mk_writer: BoxMakeWriter = match file_writer {
            Some(file_writer) => {
                if quiet {
                    BoxMakeWriter::new(file_writer)
                } else {
                    BoxMakeWriter::new(std::io::stdout.and(file_writer))
                }
            }
            None => {
                if quiet {
                    BoxMakeWriter::new(std::io::sink)
                } else {
                    BoxMakeWriter::new(std::io::stdout)
                }
            }
        };

        let subscriber = tracing_subscriber::fmt()
            .with_file(true)
            .with_thread_ids(true)
            .with_env_filter(env_filter)
            .with_writer(mk_writer);

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
    GenerateConfigSchema(GenerateConfigSchema),
    #[clap(subcommand)]
    Qcmp(Qcmp),
}

impl Cli {
    /// Drives the main quilkin application lifecycle using the command line
    /// arguments.
    #[tracing::instrument(skip_all)]
    pub async fn drive(self) -> crate::Result<()> {
        // Configure rolling log file appender if directory has been specified.
        // _log_file_guard should be kept in scope and will trigger the final flush to file when dropped
        let (file_writer, _log_file_guard) = match &self.log_directory {
            Some(log_directory) => {
                let file_appender = tracing_appender::rolling::Builder::new()
                    .rotation(tracing_appender::rolling::Rotation::HOURLY)
                    .filename_prefix(&self.log_file_prefix)
                    .max_log_files(5)
                    .build(log_directory)
                    .expect("failed to build rolling file appender");
                let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
                (Some(file_writer), Some(guard))
            }
            None => (None, None),
        };

        self.log_format
            .init_tracing_subscriber(self.quiet, file_writer);

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

        if !self.service.any_service_enabled()
            && self.command.is_none()
            && !self.providers.any_provider_enabled()
        {
            eyre::bail!("no service, provider, or command specified, shutting down");
        }

        tracing::debug!(cli = ?self, "config parameters");

        let config = self.read_config()?;

        let ready = Arc::<std::sync::atomic::AtomicBool>::default();
        let (shutdown_tx, mut shutdown_rx) = crate::signal::spawn_handler();
        if self.admin.enabled {
            tracing::debug!("spawning admin tasks");
            crate::components::admin::server(
                config.clone(),
                ready.clone(),
                shutdown_tx,
                self.admin.address,
            );
        }

        tracing::debug!("spawning heap stats tasks");
        crate::alloc::spawn_heap_stats_updates(
            std::time::Duration::from_secs(10),
            shutdown_rx.clone(),
        );

        // Just call this early so there isn't a potential race when spawning xDS
        quilkin_xds::metrics::set_registry(crate::metrics::registry());

        tracing::debug!("spawning provider tasks");
        let locality = self.locality.locality();
        let mut provider_tasks =
            self.providers
                .spawn_providers(&config, ready.clone(), locality.clone());

        tracing::debug!("spawning service tasks");
        let service_task =
            self.service
                .spawn_services(&config, &shutdown_rx, self.locality.icao_code)?;

        tracing::debug!("setting ready");
        if provider_tasks.is_empty() {
            ready.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        tracing::debug!("waiting for something to stop");
        tokio::select! {
            // result = shutdown_rx.changed() => {
            //     tracing::debug!("received shutdown stop in main drive()");
            //     result.map_err(From::from)
            // },
            Some(result) = provider_tasks.join_next() => {
                tracing::debug!(result=?result, "provider_tasks");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                result?
            },
            result = service_task => {
                tracing::debug!(result=?result, "service_task");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                result?
            },
        }
    }

    /// Searches for the configuration file, and panics if not found.
    fn read_config(&self) -> Result<Arc<crate::Config>, eyre::Error> {
        let paths = [&self.config, std::path::Path::new(ETC_CONFIG_PATH)];
        let mut paths = paths.iter();

        let file = loop {
            let Some(path) = paths.next() else {
                return Ok(<_>::default());
            };

            match std::fs::File::open(path) {
                Ok(file) => break file,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(path = %path.display(), "config path not found");
                    continue;
                }
                Err(err) => {
                    tracing::error!(path = %path.display(), error = ?err, "failed to read path");
                    eyre::bail!(err);
                }
            }
        };

        Ok(Arc::new(crate::Config::from_reader(file)?))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Timeout(std::time::Duration);

impl std::str::FromStr for Timeout {
    type Err = clap::Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let suffix_pos = src.find(char::is_alphabetic).unwrap_or(src.len());

        let num: u64 = src[..suffix_pos]
            .parse()
            .map_err(|err| clap::Error::raw(clap::error::ErrorKind::ValueValidation, err))?;
        let suffix = if suffix_pos == src.len() {
            "s"
        } else {
            &src[suffix_pos..]
        };

        let seconds = match suffix {
            "s" | "S" => num,
            "m" | "M" => num * 60,
            "h" | "H" => num * 60 * 60,
            "d" | "D" => num * 60 * 60 * 24,
            s => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    format!("unknown duration suffix '{s}'"),
                ));
            }
        };

        Ok(Self(std::time::Duration::from_secs(seconds)))
    }
}

impl std::ops::Deref for Timeout {
    type Target = std::time::Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
