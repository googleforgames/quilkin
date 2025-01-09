use quilkin::{
    collections::{BufferPool, PoolBuffer},
    components::{self, RunArgs},
    config::Providers,
    net::TcpListener,
    test::TestConfig,
    Config, ShutdownTx,
};
pub use serde_json::json;
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, sync::Arc};
use tokio::sync::mpsc;

pub static BUFFER_POOL: once_cell::sync::Lazy<Arc<BufferPool>> =
    once_cell::sync::Lazy::new(|| Arc::new(BufferPool::default()));

#[inline]
pub fn alloc_buffer(data: impl AsRef<[u8]>) -> PoolBuffer {
    BUFFER_POOL.clone().alloc_slice(data.as_ref())
}

/// Macro that can get the function name of the function the macro is invoked
/// within
#[macro_export]
macro_rules! func_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

/// Creates a temporary file with the specified prefix in a directory named
/// after the calling function, ie using it within a test will place it in a
/// temporary directory named after the test
#[macro_export]
macro_rules! temp_file {
    ($prefix:expr) => {{
        let name = $crate::func_name!();
        let name = name.strip_suffix("::{{closure}}").unwrap_or(name);
        let mut name = name.replace("::", ".");
        name.push('-');
        name.push_str($prefix);
        name.push('-');
        tempfile::NamedTempFile::with_prefix(name).unwrap()
    }};
}

pub use tracing::{subscriber::DefaultGuard, Level};

pub fn init_logging(level: Level, test_pkg: &'static str) -> DefaultGuard {
    use tracing_subscriber::{layer::SubscriberExt as _, Layer as _};
    let layer = tracing_subscriber::fmt::layer()
        .with_test_writer()
        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(level))
        .with_filter(tracing_subscriber::EnvFilter::new(format!(
            "{test_pkg}=trace,qt=trace,quilkin=trace,xds=trace"
        )));
    let sub = tracing_subscriber::Registry::default().with(layer);
    let disp = tracing::dispatcher::Dispatch::new(sub);
    tracing::dispatcher::set_default(&disp)
}

#[macro_export]
macro_rules! trace_test {
    ($(#[$attr:meta])* $name:ident, $body:block) => {
        $(#[$attr])*
        #[tokio::test]
        async fn $name() {
            // Get the module name
            let fname = $crate::func_name!();
            let mname = fname.rsplit("::").nth(2).unwrap();

            let _guard = init_logging($crate::Level::DEBUG, mname);

            $body
        }
    };
}

pub struct ServerPailConfig {
    pub packet_size: u16,
    pub num_packets: Option<usize>,
}

impl Default for ServerPailConfig {
    fn default() -> Self {
        Self {
            packet_size: 1024,
            num_packets: None,
        }
    }
}

#[derive(Default)]
pub struct AdminPailConfig;

#[derive(Default)]
pub struct RelayPailConfig {
    pub config: Option<quilkin::test::TestConfig>,
}

#[derive(Default)]
pub struct ProxyPailConfig {
    pub config: Option<quilkin::test::TestConfig>,
}

#[derive(Default)]
pub struct ManagementPailConfig {}

#[derive(Default)]
pub struct AgentPailConfig {
    pub endpoints: Vec<(&'static str, &'static [&'static str])>,
    pub icao_code: quilkin::config::IcaoCode,
}

pub enum PailConfig {
    /// Creates a UDP socket with an ephemeral port that will send received
    /// packets to a channel
    Server(ServerPailConfig),
    // Creates an admin server that is applied to any following relay, proxy, or management pails
    //Admin(AdminPailConfig),
    Relay(RelayPailConfig),
    Proxy(ProxyPailConfig),
    //Management(ManagementPailConfig),
    Agent(AgentPailConfig),
}

impl From<ServerPailConfig> for PailConfig {
    fn from(value: ServerPailConfig) -> Self {
        Self::Server(value)
    }
}

impl From<RelayPailConfig> for PailConfig {
    fn from(value: RelayPailConfig) -> Self {
        Self::Relay(value)
    }
}

impl From<AgentPailConfig> for PailConfig {
    fn from(value: AgentPailConfig) -> Self {
        Self::Agent(value)
    }
}

impl From<ProxyPailConfig> for PailConfig {
    fn from(value: ProxyPailConfig) -> Self {
        Self::Proxy(value)
    }
}

pub struct ConfigFile {
    pub path: PathBuf,
    pub config: TestConfig,
}

impl ConfigFile {
    pub fn update(&mut self, update: impl FnOnce(&mut TestConfig)) {
        update(&mut self.config);
        self.config.write_to_file(&self.path)
    }
}

macro_rules! abort_task {
    ($pail:ty) => {
        impl Drop for $pail {
            fn drop(&mut self) {
                self.task.abort();
            }
        }
    };
}

pub struct SandboxPailConfig {
    pub name: &'static str,
    pub config: PailConfig,
    pub dependencies: &'static [&'static str],
}

pub struct SandboxConfig {
    pub name: String,
    pub pails: Vec<SandboxPailConfig>,
}

pub type JoinHandle = tokio::task::JoinHandle<quilkin::Result<()>>;

pub struct ServerPail {
    /// The server socket's ephmeral port
    pub port: u16,
    pub packet_rx: Option<mpsc::Receiver<String>>,
    /// The join handle to the task driving the socket. Used to both cancel the task
    /// and/or wait for it to finish
    pub task: tokio::task::JoinHandle<usize>,
}

abort_task!(ServerPail);

pub struct RelayPail {
    pub xds_port: u16,
    pub mds_port: u16,
    pub task: JoinHandle,
    pub shutdown: ShutdownTx,
    pub config_file: Option<ConfigFile>,
    pub config: Arc<Config>,
}

abort_task!(RelayPail);

pub struct AgentPail {
    pub qcmp_port: u16,
    pub task: JoinHandle,
    pub shutdown: ShutdownTx,
    pub config_file: Option<ConfigFile>,
    pub config: Arc<Config>,
}

abort_task!(AgentPail);

pub struct ProxyPail {
    pub port: u16,
    pub qcmp_port: u16,
    pub phoenix_port: u16,
    pub task: JoinHandle,
    pub shutdown: ShutdownTx,
    pub config: Arc<Config>,
    pub delta_applies: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
}

abort_task!(ProxyPail);

pub type Pails = std::collections::BTreeMap<&'static str, Pail>;

pub enum Pail {
    Server(ServerPail),
    Relay(RelayPail),
    Agent(AgentPail),
    Proxy(ProxyPail),
}

impl Pail {
    #[inline]
    pub fn config(&self) -> Arc<Config> {
        match self {
            Self::Relay(p) => p.config.clone(),
            Self::Agent(p) => p.config.clone(),
            Self::Proxy(p) => p.config.clone(),
            Self::Server(_) => panic!("no config"),
        }
    }
}

impl Pail {
    pub fn construct(
        spc: SandboxPailConfig,
        pails: &Pails,
        td: &std::path::Path,
    ) -> (Self, Option<tokio::sync::oneshot::Receiver<()>>) {
        let mut rx = None;

        let pail = match spc.config {
            PailConfig::Server(sspc) => {
                let (packet_tx, packet_rx) = mpsc::channel::<String>(10);
                let socket = quilkin::net::DualStackEpollSocket::new(0)
                    .expect("failed to create server socket");

                let port = socket
                    .local_addr()
                    .expect("failed to bind server socket")
                    .port();

                tracing::debug!(port, spc.name, "bound server socket");

                let packet_size = sspc.packet_size as usize;
                let mut num_packets = sspc.num_packets.unwrap_or(usize::MAX);

                let task = tokio::spawn(async move {
                    let mut buf = vec![0; packet_size];
                    let mut received = 0;

                    while num_packets > 0 {
                        let (size, _) = socket
                            .recv_from(&mut buf)
                            .await
                            .expect("failed to receive packet");
                        received += size;
                        let pstr = std::str::from_utf8(&buf[..size])
                            .expect("received non-utf8 string in packet")
                            .to_owned();

                        packet_tx.send(pstr).await.expect("packet receiver dropped");

                        num_packets -= 1;
                    }

                    received
                });

                Self::Server(ServerPail {
                    port,
                    task,
                    packet_rx: Some(packet_rx),
                })
            }
            PailConfig::Relay(rpc) => {
                use components::relay;

                let xds_listener = TcpListener::bind(None).unwrap();
                let mds_listener = TcpListener::bind(None).unwrap();

                let xds_port = xds_listener.port();
                let mds_port = mds_listener.port();

                let path = td.join(spc.name);
                let mut tc = rpc.config.unwrap_or_default();
                tc.id = spc.name.into();
                tc.write_to_file(&path);

                let config_path = path.clone();

                let (shutdown, shutdown_rx) =
                    quilkin::make_shutdown_channel(quilkin::ShutdownKind::Testing);

                let config = Arc::new(Config::default_non_agent());
                config.id.store(Arc::new(spc.name.into()));

                let task = tokio::spawn(
                    relay::Relay {
                        xds_listener,
                        mds_listener,
                        provider: Some(Providers::File { path }),
                    }
                    .run(RunArgs {
                        config: config.clone(),
                        ready: relay::Ready::default(),
                        shutdown_rx,
                    }),
                );

                Self::Relay(RelayPail {
                    xds_port,
                    mds_port,
                    task,
                    shutdown,
                    config_file: Some(ConfigFile {
                        path: config_path,
                        config: tc,
                    }),
                    config,
                })
            }
            PailConfig::Agent(apc) => {
                let mut endpoints = std::collections::BTreeSet::new();

                for (dep_name, tokens) in apc.endpoints {
                    let Pail::Server(server) = &pails[dep_name] else {
                        panic!("expected '{dep_name}' to be a server pail for endpoint");
                    };

                    endpoints.insert(quilkin::net::Endpoint::with_metadata(
                        (std::net::Ipv4Addr::UNSPECIFIED, server.port).into(),
                        quilkin::net::endpoint::Metadata {
                            tokens: tokens.iter().map(|t| Vec::from(*t)).collect(),
                        },
                    ));
                }

                let mut tc = TestConfig::new();
                tc.clusters.insert_default(endpoints);
                tc.id = spc.name.into();

                let path = td.join(spc.name);
                tc.write_to_file(&path);

                let relay_servers = spc
                    .dependencies
                    .iter()
                    .filter_map(|dname| {
                        let Pail::Relay(RelayPail { mds_port, .. }) = &pails[dname] else {
                            return None;
                        };
                        Some(
                            format!("http://localhost:{mds_port}")
                                .parse()
                                .expect("failed to parse endpoint"),
                        )
                    })
                    .collect();

                let (shutdown, shutdown_rx) =
                    quilkin::make_shutdown_channel(quilkin::ShutdownKind::Testing);

                let qcmp_socket =
                    quilkin::net::raw_socket_with_reuse(0).expect("failed to bind qcmp socket");
                let qcmp_port = quilkin::net::socket_port(&qcmp_socket);

                let config_path = path.clone();
                let config = Arc::new(Config::default_agent());
                config.id.store(Arc::new(spc.name.into()));
                let acfg = config.clone();

                let task = tokio::spawn(async move {
                    components::agent::Agent {
                        locality: None,
                        icao_code: Some(apc.icao_code),
                        relay_servers,
                        qcmp_socket,
                        provider: Some(Providers::File { path }),
                        address_selector: None,
                    }
                    .run(RunArgs {
                        config,
                        ready: Default::default(),
                        shutdown_rx,
                    })
                    .await
                });

                Self::Agent(AgentPail {
                    qcmp_port,
                    task,
                    shutdown,
                    config_file: Some(ConfigFile {
                        path: config_path,
                        config: tc,
                    }),
                    config: acfg,
                })
            }
            PailConfig::Proxy(ppc) => {
                let socket = quilkin::net::raw_socket_with_reuse(0).expect("failed to bind socket");
                let qcmp =
                    quilkin::net::raw_socket_with_reuse(0).expect("failed to bind qcmp socket");
                let qcmp_port = quilkin::net::socket_port(&qcmp);
                let phoenix = TcpListener::bind(None).expect("failed to bind phoenix socket");
                let phoenix_port = phoenix.port();

                let port = quilkin::net::socket_port(&socket);

                let management_servers = spc
                    .dependencies
                    .iter()
                    .filter_map(|dname| {
                        let Pail::Relay(RelayPail { xds_port, .. }) = &pails[dname] else {
                            return None;
                        };
                        Some(
                            format!("http://localhost:{xds_port}")
                                .parse()
                                .expect("failed to parse endpoint"),
                        )
                    })
                    .collect();

                let (shutdown, shutdown_rx) =
                    quilkin::make_shutdown_channel(quilkin::ShutdownKind::Testing);

                let (tx, orx) = tokio::sync::oneshot::channel();

                let config = Arc::new(Config::default_non_agent());

                if let Some(cfg) = ppc.config {
                    if !cfg.clusters.is_empty() {
                        panic!("not implemented");
                    }

                    if !cfg.filters.is_empty() {
                        config.filters.store(Arc::new(cfg.filters));
                    }
                }

                let endpoints: std::collections::BTreeSet<_> = spc
                    .dependencies
                    .iter()
                    .filter_map(|dname| {
                        let Pail::Server(ServerPail { port, .. }) = &pails[dname] else {
                            return None;
                        };

                        Some(quilkin::net::Endpoint::new(
                            (std::net::Ipv6Addr::LOCALHOST, *port).into(),
                        ))
                    })
                    .collect();

                if !endpoints.is_empty() {
                    config
                        .clusters
                        .modify(|clusters| clusters.insert_default(endpoints));
                }

                config.id.store(Arc::new(spc.name.into()));
                let pconfig = config.clone();

                let (rttx, rtrx) = tokio::sync::mpsc::unbounded_channel();

                let task = tokio::spawn(async move {
                    components::proxy::Proxy {
                        num_workers: NonZeroUsize::new(1).unwrap(),
                        mmdb: None,
                        to: Vec::new(),
                        to_tokens: None,
                        management_servers,
                        socket: Some(socket),
                        qcmp,
                        phoenix,
                        notifier: Some(rttx),
                    }
                    .run(
                        RunArgs {
                            config: pconfig,
                            ready: Default::default(),
                            shutdown_rx,
                        },
                        Some(tx),
                    )
                    .await
                });

                rx = Some(orx);

                Self::Proxy(ProxyPail {
                    port,
                    qcmp_port,
                    phoenix_port,
                    shutdown,
                    task,
                    config,
                    delta_applies: Some(rtrx),
                })
            }
        };
        (pail, rx)
    }
}

pub struct Sandbox {
    pub pails: Pails,
    pub td: tempfile::TempDir,
}

#[macro_export]
macro_rules! sandbox_config {
    () => {{
        let fname = $crate::func_name!();
        let mut name = String::new();
        for comp in fname.split("::") {
            if comp.starts_with("{{") {
                continue;
            }

            if !name.is_empty() {
                name.push('.');
            }

            name.push_str(comp);
        }
        $crate::SandboxConfig::new(name)
    }};
}

impl SandboxConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pails: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        name: &'static str,
        config: impl Into<PailConfig>,
        deps: &'static [&'static str],
    ) {
        self.pails.push(SandboxPailConfig {
            name,
            config: config.into(),
            dependencies: deps,
        });
    }

    pub async fn spinup(self) -> Sandbox {
        // Validate that every dependency is satisfied
        for i in 0..self.pails.len() {
            let deps = self.pails[i].dependencies;

            for dep in deps {
                if !self.pails[..i].iter().any(|sp| sp.name == *dep) {
                    panic!(
                        "failed to locate dependency '{dep}' for '{}'",
                        self.pails[i].name
                    );
                }
            }
        }

        tracing::trace!("dependencies resolved");

        // Create a channel that is used to communicate readiness of each pail we create
        //let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Not necessarily used in every test, but in most
        let td = match tempfile::TempDir::with_prefix(&self.name) {
            Ok(td) => td,
            Err(err) => {
                panic!("failed to create temp dir '{}': {err:#}", self.name);
            }
        };

        let mut pails = Pails::new();
        for pc in self.pails {
            let name = pc.name;
            let (pail, rx) = Pail::construct(pc, &pails, td.path());

            if let Some(rx) = rx {
                rx.await.unwrap();
            }

            if pails.insert(name, pail).is_some() {
                panic!("{name} already existed");
            }
        }

        Sandbox { pails, td }
    }
}

impl Sandbox {
    #[inline]
    pub fn proxy(
        &mut self,
        name: &str,
    ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let Some(Pail::Proxy(pp)) = self.pails.get_mut(name) else {
            unreachable!()
        };
        (
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, pp.port)),
            pp.delta_applies.take().unwrap(),
        )
    }

    #[inline]
    pub fn packet_rx(&mut self, name: &str) -> mpsc::Receiver<String> {
        let Some(Pail::Server(pp)) = self.pails.get_mut(name) else {
            unreachable!()
        };
        pp.packet_rx.take().unwrap()
    }

    #[inline]
    pub fn server(&mut self, name: &str) -> (mpsc::Receiver<String>, SocketAddr) {
        let Some(Pail::Server(pp)) = self.pails.get_mut(name) else {
            unreachable!()
        };
        (
            pp.packet_rx.take().unwrap(),
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, pp.port)),
        )
    }

    #[inline]
    pub fn config_file(&mut self, name: &str) -> ConfigFile {
        let pail = self.pails.get_mut(name).unwrap();

        match pail {
            Pail::Relay(rp) => rp.config_file.take().unwrap(),
            Pail::Agent(ap) => ap.config_file.take().unwrap(),
            _ => unimplemented!("no config_file for this pail"),
        }
    }

    #[inline]
    pub fn socket(&self) -> (socket2::Socket, SocketAddr) {
        let socket = quilkin::net::raw_socket_with_reuse(0).unwrap();
        let port = quilkin::net::socket_port(&socket);

        (
            socket,
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        )
    }

    /// Creates an ephemeral socket that can be used to send messages to sandbox
    /// pails
    #[inline]
    pub fn client(&self) -> quilkin::net::DualStackEpollSocket {
        quilkin::net::DualStackEpollSocket::new(0).unwrap()
    }

    /// Sleeps for the specified number of milliseconds
    #[inline]
    pub async fn sleep(&self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await
    }

    /// Runs a future, expecting it complete before the specified timeout
    #[inline]
    pub async fn timeout<F>(&self, ms: u64, fut: F) -> F::Output
    where
        F: std::future::Future,
    {
        tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
            .await
            .expect("operation timed out")
    }

    #[inline]
    pub async fn maybe_timeout<F>(&self, ms: u64, fut: F) -> Option<F::Output>
    where
        F: std::future::Future,
    {
        tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
            .await
            .ok()
    }

    /// Runs a future, expecting it to timeout instead of resolving, panics if
    /// the future finishes before the timeout
    #[inline]
    pub async fn expect_timeout<F>(&self, ms: u64, fut: F)
    where
        F: std::future::Future,
        F::Output: std::fmt::Debug,
    {
        tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
            .await
            .expect_err("expected future to timeout");
    }
}
