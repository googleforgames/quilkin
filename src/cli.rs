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

pub(crate) mod admin;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::builder::TypedValueParser;
use clap::crate_version;
use tokio::signal;

use crate::Config;
use strum_macros::{Display, EnumString};

pub use self::{
    admin::Admin, agent::Agent, generate_config_schema::GenerateConfigSchema, manage::Manage,
    proxy::Proxy, qcmp::Qcmp, relay::Relay,
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

impl Commands {
    pub fn admin_mode(&self) -> Option<Admin> {
        match self {
            Self::Proxy(proxy) => Some(Admin::Proxy(proxy::RuntimeConfig {
                idle_request_interval: std::time::Duration::from_secs(
                    proxy.idle_request_interval_secs,
                ),
                ..<_>::default()
            })),
            Self::Agent(agent) => Some(Admin::Agent(agent::RuntimeConfig {
                idle_request_interval: std::time::Duration::from_secs(
                    agent.idle_request_interval_secs,
                ),
                ..<_>::default()
            })),
            Self::Relay(relay) => Some(Admin::Relay(relay::RuntimeConfig {
                idle_request_interval: std::time::Duration::from_secs(
                    relay.idle_request_interval_secs,
                ),
                ..<_>::default()
            })),
            Self::Manage(_) => Some(Admin::Manage(<_>::default())),
            Self::GenerateConfigSchema(_) | Self::Qcmp(_) => None,
        }
    }
}

impl Cli {
    /// Drives the main quilkin application lifecycle using the command line
    /// arguments.
    #[tracing::instrument(skip_all)]
    pub async fn drive(self, tx: Option<tokio::sync::oneshot::Sender<u16>>) -> crate::Result<()> {
        if !self.quiet {
            let env_filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy();
            let subscriber = tracing_subscriber::fmt()
                .with_file(true)
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
        match self.command {
            Commands::Qcmp(Qcmp::Ping(ping)) => return ping.run().await,
            Commands::GenerateConfigSchema(generator) => {
                return generator.generate_config_schema();
            }
            _ => {}
        }

        tracing::debug!(cli = ?self, "config parameters");

        let config = Arc::new(Self::read_config(self.config)?);
        let mode = self.command.admin_mode().unwrap();

        if !self.no_admin {
            mode.server(config.clone(), self.admin_address);
        }

        let (shutdown_tx, shutdown_rx) = crate::make_shutdown_channel(Default::default());

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

        match self.command {
            Commands::Agent(agent) => agent.run(config.clone(), mode, shutdown_rx.clone()).await,
            Commands::Proxy(runner) => {
                runner
                    .run(config.clone(), mode.clone(), tx, shutdown_rx.clone())
                    .await
            }
            Commands::Manage(manager) => {
                manager
                    .manage(config.clone(), mode, shutdown_rx.clone())
                    .await
            }
            Commands::Relay(relay) => relay.relay(config, mode, shutdown_rx.clone()).await,
            Commands::GenerateConfigSchema(_) | Commands::Qcmp(_) => unreachable!(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::time::{timeout, Duration};

    use crate::{
        config::{Filter, Providers},
        filters::{Capture, StaticFilter, TokenRouter},
        net::endpoint::Endpoint,
        temp_file,
        test::{create_socket, AddressType, TestConfig, TestHelper},
    };

    #[tokio::test]
    async fn datacenter_discovery() {
        let relay_xds_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let relay_mds_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let relay_config = Arc::new(Config::default());
        let relay = Relay {
            xds_port: relay_xds_port,
            mds_port: relay_mds_port,
            ..<_>::default()
        };

        let agent_file = tempfile::NamedTempFile::new().unwrap();
        let config = Config::default();

        std::fs::write(agent_file.path(), serde_yaml::to_string(&config).unwrap()).unwrap();

        let agent_qcmp_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();

        let icao_code: crate::config::IcaoCode = "EIDW".parse().unwrap();

        let agent_config = Arc::new(Config::default());
        let agent = Agent {
            relay: vec![format!("http://localhost:{relay_mds_port}")
                .parse()
                .unwrap()],
            region: None,
            sub_zone: None,
            zone: None,
            idle_request_interval_secs: admin::idle_request_interval_secs(),
            qcmp_port: agent_qcmp_port,
            icao_code: icao_code.clone(),
            provider: Some(Providers::File {
                path: agent_file.path().to_path_buf(),
            }),
        };

        let proxy_config = Arc::new(Config::default());
        let proxy = Proxy {
            management_server: vec![format!("http://localhost:{relay_xds_port}")
                .parse()
                .unwrap()],
            ..<_>::default()
        };

        let (_tx, shutdown_rx) = crate::make_shutdown_channel(Default::default());
        tokio::spawn({
            let config = relay_config.clone();
            let shutdown_rx = shutdown_rx.clone();
            async move {
                relay
                    .relay(config, Admin::Relay(<_>::default()), shutdown_rx)
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        tokio::spawn({
            let config = agent_config.clone();
            let shutdown_rx = shutdown_rx.clone();
            async move {
                agent
                    .run(config, Admin::Agent(<_>::default()), shutdown_rx)
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let (tx, proxy_init) = tokio::sync::oneshot::channel();
        tokio::spawn({
            let config = proxy_config.clone();
            let shutdown_rx = shutdown_rx.clone();
            async move {
                proxy
                    .run(config, Admin::Proxy(<_>::default()), Some(tx), shutdown_rx)
                    .await
            }
        });
        proxy_init.await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let datacenter = crate::config::Datacenter {
            qcmp_port: agent_qcmp_port,
            icao_code,
        };

        assert!(agent_config.datacenters.read().is_empty());
        assert!(!relay_config.datacenters.read().is_empty());
        assert!(!proxy_config.datacenters.read().is_empty());
        #[track_caller]
        fn assert_config(config: &Config, datacenter: &crate::config::Datacenter) {
            let dcs = config.datacenters.read();
            let ipv4_dc = dcs.get(&std::net::Ipv4Addr::LOCALHOST.into());
            let ipv6_dc = dcs.get(&std::net::Ipv6Addr::LOCALHOST.into());

            match (ipv4_dc, ipv6_dc) {
                (Some(dc), None) => assert_eq!(&*dc, datacenter),
                (None, Some(dc)) => assert_eq!(&*dc, datacenter),
                (Some(dc1), Some(dc2)) => {
                    assert_eq!(&*dc1, datacenter);
                    assert_eq!(&*dc2, datacenter);
                }
                (None, None) => panic!("No datacenter found"),
            };
        }
        assert_config(&relay_config, &datacenter);
        assert_config(&proxy_config, &datacenter);
    }

    #[tokio::test]
    async fn relay_routing() {
        let mut t = TestHelper::default();
        let (mut rx, server_socket) = t.open_socket_and_recv_multiple_packets().await;
        let filters_file = temp_file!("filters");
        let mut config = TestConfig::default();

        {
            config.filters = crate::filters::FilterChain::try_create([
                Filter {
                    name: Capture::factory().name().into(),
                    label: None,
                    config: Some(serde_json::json!({
                        "suffix": {
                            "size": 3,
                            "remove": true,
                        }
                    })),
                },
                Filter {
                    name: TokenRouter::factory().name().into(),
                    label: None,
                    config: None,
                },
            ])
            .unwrap();
            config.write_to_file(filters_file.path());
        }

        let endpoints_file = temp_file!("endpoints");
        let config = TestConfig::default();
        let server_port = server_socket.local_addr().unwrap().port();

        {
            config.clusters.insert_default(
                [Endpoint::with_metadata(
                    (std::net::Ipv4Addr::LOCALHOST, server_port).into(),
                    crate::net::endpoint::Metadata {
                        tokens: Some(b"abc".to_vec()).into_iter().collect(),
                    },
                )]
                .into(),
            );
            config.write_to_file(endpoints_file.path());
        }

        let relay_admin_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let relay = Cli {
            admin_address: Some((Ipv4Addr::LOCALHOST, relay_admin_port).into()),
            config: <_>::default(),
            no_admin: false,
            quiet: true,
            command: Commands::Relay(Relay {
                providers: Some(Providers::File {
                    path: filters_file.path().to_path_buf(),
                }),
                ..<_>::default()
            }),
            log_format: LogFormats::default(),
        };

        let control_plane_admin_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let control_plane = Cli {
            no_admin: false,
            quiet: true,
            admin_address: Some((Ipv4Addr::LOCALHOST, control_plane_admin_port).into()),
            config: <_>::default(),
            command: Commands::Agent(Agent {
                relay: vec!["http://localhost:7900".parse().unwrap()],
                region: None,
                sub_zone: None,
                zone: None,
                idle_request_interval_secs: admin::idle_request_interval_secs(),
                qcmp_port: crate::test::available_addr(&AddressType::Random)
                    .await
                    .port(),
                provider: Some(Providers::File {
                    path: endpoints_file.path().to_path_buf(),
                }),
                ..<_>::default()
            }),
            log_format: LogFormats::default(),
        };

        let proxy_admin_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let proxy = Cli {
            no_admin: false,
            quiet: true,
            admin_address: Some((Ipv4Addr::LOCALHOST, proxy_admin_port).into()),
            config: <_>::default(),
            command: Commands::Proxy(Proxy {
                management_server: vec!["http://localhost:7800".parse().unwrap()],
                ..<_>::default()
            }),
            log_format: LogFormats::default(),
        };

        tokio::spawn(relay.drive(None));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        tokio::spawn(control_plane.drive(None));
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let (tx, proxy_init) = tokio::sync::oneshot::channel();

        tokio::spawn(proxy.drive(Some(tx)));

        proxy_init.await.unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let socket = create_socket().await;
        let config = TestConfig::default();
        let proxy_address: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, 7777).into();

        let server_port = server_socket.local_addr().unwrap().port();
        for _ in 0..5 {
            let token = Token::new();
            tokio::time::sleep(Duration::from_millis(50)).await;

            {
                tracing::info!(%token, "writing new config");
                config.clusters.insert_default(
                    [Endpoint::with_metadata(
                        (std::net::Ipv6Addr::LOCALHOST, server_port).into(),
                        crate::net::endpoint::Metadata {
                            tokens: Some(token.inner.to_vec()).into_iter().collect(),
                        },
                    )]
                    .into(),
                );
                config.write_to_file(endpoints_file.path());
            }

            tokio::time::sleep(Duration::from_millis(580)).await;
            let mut msg = b"hello".to_vec();
            msg.extend_from_slice(&token.inner);
            tracing::info!(%token, "sending packet");
            socket.send_to(&msg, &proxy_address).await.unwrap();

            assert_eq!(
                "hello",
                timeout(Duration::from_millis(1000), rx.recv())
                    .await
                    .expect("should have received a packet")
                    .unwrap()
            );

            tracing::info!(%token, "received packet");

            tracing::info!(%token, "sending bad packet");
            // send an invalid packet
            socket
                .send_to(b"hello\xFF\xFF\xFF", &proxy_address)
                .await
                .unwrap();

            let result = timeout(Duration::from_millis(50), rx.recv()).await;
            assert!(result.is_err(), "should not have received a packet");
            tracing::info!(%token, "didn't receive bad packet");
        }
    }

    struct Token {
        inner: [u8; 3],
    }

    impl Token {
        fn new() -> Self {
            const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

            use rand::prelude::SliceRandom;
            let mut rng = rand::thread_rng();

            let mut inner = [0; 3];
            for (v, slot) in CHARS
                .choose_multiple(&mut rng, inner.len())
                .zip(inner.iter_mut())
            {
                *slot = *v;
            }

            Self { inner }
        }
    }

    use std::fmt;
    impl fmt::Display for Token {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(std::str::from_utf8(&self.inner).unwrap())
        }
    }
}
