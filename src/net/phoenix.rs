//! # Phoenix Network Coordinate System
//!
//! This module provides a framework for estimating network latencies between
//! nodes in a distributed system. By embedding nodes in a virtual coordinate
//! space, Phoenix allows for efficient estimation of network distance (latency)
//! without the need to directly measure the latency between every pair of nodes.
//!
//! ## Overview
//!
//! The Phoenix system works by assigning each node in the network a set of
//! coordinates that correspond to its position in a virtual space. The distance
//! between any two nodes in this space is indicative of the expected network
//! latency between them. This method reduces the overhead and scale issues
//! associated with all-to-all latency measurements.
//!
//! The system is designed to be both self-organizing and adaptive, meaning that
//! it can handle nodes joining, leaving, and changing latencies over time.
//! Phoenix periodically updates the coordinates of each node based on a subset
//! of latency measurements to reflect the current state of the network.

use std::{collections::HashMap, net::SocketAddr, ops::Range, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::config::IcaoCode;

pub fn spawn(
    listener: crate::net::TcpListener,
    config: Arc<crate::Config>,
    mut shutdown_rx: crate::ShutdownRx,
    measurer: crate::codec::qcmp::QcmpMeasurement,
) -> crate::Result<()> {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Response, Server as HyperServer, StatusCode};

    let phoenix = Phoenix::new(measurer);
    phoenix.add_nodes_from_config(&config);

    let crate::config::DatacenterConfig::NonAgent { datacenters } = &config.datacenter else {
        unreachable!("this shouldn't be spawned on an agent")
    };
    let mut config_watcher = datacenters.watch();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = runtime.block_on({
            let mut phoenix_watcher = phoenix.update_watcher();
            let config = config.clone();

            async move {
                let json = crate::config::Slot::new(serde_json::Map::default());

                tokio::spawn({
                    let phoenix = phoenix.clone();
                    async move { phoenix.background_update_task().await }
                });

                let json2 = json.clone();
                let make_svc = make_service_fn(move |_conn| {
                    let json = json2.clone();
                    #[allow(clippy::declare_interior_mutable_const)]
                    const JSON: hyper::header::HeaderValue =
                        hyper::header::HeaderValue::from_static("application/json");

                    async move {
                        Ok::<_, std::convert::Infallible>(service_fn(move |_| {
                            let json = json.clone();
                            async move {
                                tracing::trace!("serving phoenix request");
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(hyper::header::CONTENT_TYPE, JSON)
                                        .body(Body::from(serde_json::to_string(&json).unwrap()))
                                        .unwrap(),
                                )
                            }
                        }))
                    }
                });

                tracing::info!(addr=%listener.local_addr(), "starting phoenix HTTP service");
                let (stx, srx) = tokio::sync::oneshot::channel::<()>();

                let http_task = tokio::spawn(
                    HyperServer::from_tcp(listener.into())?
                        .serve(make_svc)
                        .with_graceful_shutdown(async move {
                            let _ = srx.await;
                        }),
                );

                let res = loop {
                    use eyre::WrapErr as _;

                    tokio::select! {
                        _ = shutdown_rx.changed() => break Ok::<_, eyre::Error>(()),
                        result = config_watcher.changed() => if let Err(err) = result {
                            break Err(err).context("config watcher sender dropped");
                        },
                        result = phoenix_watcher.changed() => if let Err(err) = result {
                            break Err(err).context("phoenix watcher sender dropped");
                        },
                    }

                    tracing::trace!("change detected, updating phoenix");
                    phoenix.add_nodes_from_config(&config);
                    let nodes = phoenix.ordered_nodes_by_latency();
                    let mut new_json = serde_json::Map::default();

                    for (identifier, latency) in nodes {
                        new_json.insert(identifier.to_string(), latency.into());
                    }

                    json.store(new_json.into());
                };

                if stx.send(()).is_err() {
                    tracing::error!("phoenix HTTP service task has already exited");
                }

                // This should happen quickly, abort if it takes too long
                let max_wait = std::time::Instant::now() + std::time::Duration::from_millis(100);
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(1));

                loop {
                    if http_task.is_finished() || std::time::Instant::now() > max_wait {
                        break;
                    }

                    interval.tick().await;
                }

                if !http_task.is_finished() {
                    http_task.abort();
                }

                if let Err(err) = http_task.await {
                    if let Ok(panic) = err.try_into_panic() {
                        let message = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("<unknown non-string panic>");

                        tracing::error!(panic = message, "phoenix HTTP task panicked");
                    }
                }

                res
            }
        });

        if let Err(err) = res {
            tracing::error!(err = %err, "phoenix thread failed with an error");
        }
    });

    Ok(())
}

use crate::time::DurationNanos;

#[derive(Copy, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct DistanceMeasure {
    pub incoming: DurationNanos,
    pub outgoing: DurationNanos,
}

impl Default for DistanceMeasure {
    fn default() -> Self {
        Self::from((0, 0))
    }
}

impl From<(i64, i64)> for DistanceMeasure {
    fn from(value: (i64, i64)) -> Self {
        Self {
            incoming: DurationNanos::from_nanos(value.0),
            outgoing: DurationNanos::from_nanos(value.1),
        }
    }
}

impl DistanceMeasure {
    #[inline]
    pub fn total_nanos(self) -> i64 {
        self.incoming.nanos() + self.outgoing.nanos()
    }

    #[inline]
    pub fn total(self) -> std::time::Duration {
        self.incoming.duration() + self.outgoing.duration()
    }
}

/// An implementation of measuring the network difference between two nodes.
#[async_trait]
pub trait Measurement {
    /// Gets the difference between this node and `address`, returning the
    /// latency in nanoseconds on success.
    async fn measure_distance(&self, address: SocketAddr) -> eyre::Result<DistanceMeasure>;
}

/// A `Phoenix` instance maintains a virtual coordinate space for nodes in a
/// distributed system to estimate their network latencies. It uses the provided
/// `Measurement` trait to periodically measure and update each node's
/// coordinates, allowing for latency estimation between any two nodes.
#[derive(Clone, Debug)]
pub struct Phoenix<M> {
    inner: Arc<Inner<M>>,
}

#[derive(Debug)]
pub struct Inner<M> {
    nodes: DashMap<SocketAddr, Node>,
    measurement: M,
    stability_threshold: Duration,
    adjustment_duration: Duration,
    interval_range: Range<Duration>,
    subset_percentage: f64,
    update_watcher: (
        tokio::sync::watch::Sender<()>,
        tokio::sync::watch::Receiver<()>,
    ),
}

impl<M: Measurement + 'static> Phoenix<M> {
    pub fn new(measurement: M) -> Self {
        Builder::new(measurement).build()
    }

    pub fn builder(measurement: M) -> Builder<M> {
        Builder::new(measurement)
    }

    /// Starts the background update task to continously sample from nodes
    /// and update their coordinates.
    pub async fn background_update_task(&self) {
        let mut current_interval = self.interval_range.start;
        let mut first = Some(self.all_nodes());

        loop {
            let mut total_difference = 0;
            let mut count = 0;

            let nodes_to_probe = first
                .take()
                .unwrap_or_else(|| self.random_subset_of_nodes());

            for address in nodes_to_probe {
                let Some(mut node) = self.nodes.get_mut(&address) else {
                    tracing::debug!(%address, "node removed between selection and measurement");
                    continue;
                };

                match self.measurement.measure_distance(address).await {
                    Ok(distance) => {
                        node.adjust_coordinates(distance);
                        total_difference += distance.total_nanos();
                        count += 1;
                    }
                    Err(error) => {
                        tracing::warn!(%address, %error, "error measuring distance");
                        node.increase_error_estimate();
                    }
                }
            }

            if count > 0 {
                let avg_difference_ns = total_difference / count;

                // Adjust the interval based on the avg_difference
                if Duration::from_nanos(avg_difference_ns as u64) < self.stability_threshold {
                    current_interval += self.adjustment_duration;
                } else {
                    current_interval -= self.adjustment_duration;
                }

                // Ensure current_interval remains within bounds
                current_interval =
                    current_interval.clamp(self.interval_range.start, self.interval_range.end);
            }

            let _ = self.update_watcher.0.send(());
            tokio::time::sleep(current_interval).await;
        }
    }

    fn update_watcher(&self) -> tokio::sync::watch::Receiver<()> {
        self.update_watcher.1.clone()
    }

    fn all_nodes(&self) -> Vec<SocketAddr> {
        self.nodes
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>()
    }

    fn random_subset_of_nodes(&self) -> Vec<SocketAddr> {
        use rand::seq::SliceRandom;
        let unmapped_nodes = self
            .nodes
            .iter()
            .filter(|entry| entry.coordinates.is_none());

        if unmapped_nodes.clone().count() > 0 {
            unmapped_nodes.map(|entry| *entry.key()).collect()
        } else {
            let mut nodes = self
                .nodes
                .iter()
                .map(|entry| *entry.key())
                .collect::<Vec<_>>();
            nodes.shuffle(&mut rand::thread_rng());
            let subset_size = (nodes.len() as f64 * self.subset_percentage).abs() as usize;

            nodes[..subset_size].to_vec()
        }
    }

    #[cfg(test)]
    async fn measure_all_nodes(&self) {
        for address in self
            .nodes
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>()
        {
            if let Some(mut node) = self.nodes.get_mut(&address) {
                let Ok(distance) = self.measurement.measure_distance(address).await else {
                    continue;
                };
                node.adjust_coordinates(distance);
            } else {
                self.nodes.entry(address).and_modify(|node| {
                    node.increase_error_estimate();
                });
            }
        }
    }

    pub fn get_coordinates(&self, address: &SocketAddr) -> Option<Coordinates> {
        self.nodes.get(address).and_then(|node| node.coordinates)
    }

    pub fn ordered_nodes_by_latency(&self) -> Vec<(IcaoCode, f64)> {
        use std::collections::hash_map::Entry;

        let origin = Coordinates::ORIGIN;
        let mut icao_map = HashMap::new();

        for entry in self.nodes.iter() {
            let Some(coordinates) = entry.value().coordinates else {
                continue;
            };
            let distance = origin.distance_to(&coordinates);
            let icao = entry.value().icao_code;

            match icao_map.entry(icao) {
                Entry::Vacant(entry) => {
                    entry.insert(distance);
                }
                Entry::Occupied(entry) => {
                    let old_distance = entry.into_mut();
                    if *old_distance > distance {
                        *old_distance = distance;
                    }
                }
            }
        }

        let mut vec = icao_map.into_iter().collect::<Vec<_>>();
        vec.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        vec
    }

    pub fn add_node(&self, address: SocketAddr, icao_code: IcaoCode) {
        self.nodes.insert(address, Node::new(icao_code));
    }

    pub fn add_node_if_not_exists(&self, address: SocketAddr, icao_code: IcaoCode) {
        self.nodes
            .entry(address)
            .or_insert_with(|| Node::new(icao_code));
    }

    pub fn add_nodes_from_config(&self, config: &crate::Config) {
        let crate::config::DatacenterConfig::NonAgent { datacenters } = &config.datacenter else {
            unreachable!("this shouldn't be called by an agent")
        };
        for entry in datacenters.write().iter() {
            let addr = (*entry.key(), entry.value().qcmp_port).into();
            self.add_node_if_not_exists(addr, entry.value().icao_code);
        }
    }
}

impl<M> std::ops::Deref for Phoenix<M> {
    type Target = Inner<M>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct Builder<M> {
    measurement: M,
    stability_threshold: Option<Duration>,
    adjustment_duration: Option<Duration>,
    interval_range: Option<Range<Duration>>,
    subset_percentage: Option<f64>,
}

impl<M: Measurement> Builder<M> {
    const DEFAULT_STABILITY_THRESHOLD: Duration = Duration::from_millis(50);
    const DEFAULT_ADJUSTMENT_DURATION: Duration = Duration::from_millis(5);
    const DEFAULT_INTERVAL_RANGE: Range<Duration> =
        Duration::from_secs(60)..Duration::from_secs(10 * 60);
    const DEFAULT_SUBSET: f64 = 0.5;

    /// Constructs a new [`Phoenix`] builder.
    pub fn new(measurement: M) -> Self {
        Builder {
            measurement,
            stability_threshold: None,
            adjustment_duration: None,
            interval_range: None,
            subset_percentage: None,
        }
    }

    /// The amount of time the check will change by depending on network stability.
    pub fn adjustment_duration(mut self, adjustment: Duration) -> Self {
        self.adjustment_duration = Some(adjustment);
        self
    }

    /// The threshold at which the path to a node is consider unstable.
    pub fn stability_threshold(mut self, threshold: Duration) -> Self {
        self.stability_threshold = Some(threshold);
        self
    }

    /// The range at which continually update the nodes measurements. This
    /// a range as the time will increase/decrease in response to
    /// network stability.
    ///
    /// # Panics
    /// If the start of the range is greater than end of the range.
    pub fn interval_range(mut self, range: Range<Duration>) -> Self {
        assert!(range.start < range.end);
        self.interval_range = Some(range);
        self
    }

    /// Sets the percentage of nodes to regularly measure at random.
    ///
    /// # Panics
    /// If the percentage is greater than 1.0 or lower or equal to 0.0.
    pub fn subset_percentage(mut self, percentage: f64) -> Self {
        assert!(percentage > 0.0 && percentage <= 1.0);
        self.subset_percentage = Some(percentage);
        self
    }

    pub fn build(self) -> Phoenix<M> {
        Phoenix {
            inner: Arc::new(Inner {
                nodes: DashMap::new(),
                measurement: self.measurement,
                stability_threshold: self
                    .stability_threshold
                    .unwrap_or(Self::DEFAULT_STABILITY_THRESHOLD),
                adjustment_duration: self
                    .adjustment_duration
                    .unwrap_or(Self::DEFAULT_ADJUSTMENT_DURATION),
                interval_range: self.interval_range.unwrap_or(Self::DEFAULT_INTERVAL_RANGE),
                subset_percentage: self.subset_percentage.unwrap_or(Self::DEFAULT_SUBSET),
                update_watcher: tokio::sync::watch::channel(()),
            }),
        }
    }
}

/// The network coordinates of a node in the phoenix system.
#[derive(Debug, Clone, Copy)]
pub struct Coordinates {
    x: f64,
    y: f64,
}

impl Coordinates {
    const ORIGIN: Self = Self { x: 0.0, y: 0.0 };

    fn distance_to(&self, other: &Coordinates) -> f64 {
        let x_diff = self.x - other.x;
        let y_diff = self.y - other.y;
        (x_diff.powi(2) + y_diff.powi(2)).sqrt()
    }
}

/// A node in Phoenix system, contains its location, and an estimate of how
/// imprecise the location may be due to errors.
#[derive(Debug, Clone)]
struct Node {
    coordinates: Option<Coordinates>,
    icao_code: IcaoCode,
    error_estimate: f64,
}

impl Node {
    fn new(icao_code: IcaoCode) -> Self {
        Node {
            coordinates: None,
            icao_code,
            error_estimate: 1.0,
        }
    }

    fn increase_error_estimate(&mut self) {
        self.error_estimate += 0.1;
    }

    fn adjust_coordinates(&mut self, distance: DistanceMeasure) {
        let incoming = distance.incoming.nanos() as f64;
        let outgoing = distance.outgoing.nanos() as f64;

        let Some(coordinates) = &mut self.coordinates else {
            self.coordinates = Some(Coordinates {
                x: incoming,
                y: outgoing,
            });
            return;
        };

        let weight = self.error_estimate;

        coordinates.x = (coordinates.x + (incoming * weight)) / 2.0;
        coordinates.y = (coordinates.y + (outgoing * weight)) / 2.0;
    }
}

#[cfg(test)]
mod tests {
    use crate::net::raw_socket_with_reuse;

    use super::*;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct LoggingMockMeasurement {
        latencies: HashMap<SocketAddr, DistanceMeasure>,
        probed_addresses: Arc<Mutex<HashSet<SocketAddr>>>,
    }

    #[async_trait]
    impl Measurement for LoggingMockMeasurement {
        async fn measure_distance(&self, address: SocketAddr) -> eyre::Result<DistanceMeasure> {
            self.probed_addresses.lock().await.insert(address);
            Ok(*self
                .latencies
                .get(&address)
                .unwrap_or(&DistanceMeasure::default()))
        }
    }

    struct MockMeasurement {
        latencies: HashMap<SocketAddr, DistanceMeasure>,
    }

    #[async_trait]
    impl Measurement for MockMeasurement {
        async fn measure_distance(&self, address: SocketAddr) -> eyre::Result<DistanceMeasure> {
            Ok(*self
                .latencies
                .get(&address)
                .unwrap_or(&DistanceMeasure::default()))
        }
    }

    #[derive(Debug)]
    struct FailedAddressesMock {
        latencies: HashMap<SocketAddr, DistanceMeasure>,
        failed_addresses: Arc<Mutex<HashSet<SocketAddr>>>,
    }

    #[async_trait]
    impl Measurement for FailedAddressesMock {
        async fn measure_distance(&self, address: SocketAddr) -> eyre::Result<DistanceMeasure> {
            let failed_addresses = self.failed_addresses.lock().await;
            if failed_addresses.contains(&address) {
                Err(eyre::eyre!("Measurement timed out"))
            } else {
                Ok(*self
                    .latencies
                    .get(&address)
                    .unwrap_or(&DistanceMeasure::default()))
            }
        }
    }

    fn abcd() -> IcaoCode {
        "ABCD".parse().unwrap()
    }

    fn efgh() -> IcaoCode {
        "EFGH".parse().unwrap()
    }

    fn ijkl() -> IcaoCode {
        "IJKL".parse().unwrap()
    }

    #[test]
    fn default_builder() {
        let _phoenix = Phoenix::new(MockMeasurement {
            latencies: <_>::default(),
        });
    }

    #[tokio::test]
    async fn coordinates_adjustment() {
        let mut mock_latencies = HashMap::new();
        mock_latencies.insert("127.0.0.1:8081".parse().unwrap(), (25, 25).into());
        let phoenix = Phoenix::new(MockMeasurement {
            latencies: mock_latencies,
        });

        phoenix.add_node("127.0.0.1:8080".parse().unwrap(), abcd());
        phoenix.add_node("127.0.0.1:8081".parse().unwrap(), efgh());
        phoenix.measure_all_nodes().await;

        let coords = phoenix
            .get_coordinates(&"127.0.0.1:8081".parse().unwrap())
            .unwrap();
        assert!(
            coords.x != 0.0 || coords.y != 0.0,
            "Coordinates were not adjusted."
        );
    }

    #[tokio::test]
    async fn ordered_nodes_by_latency() {
        let mut mock_latencies = HashMap::new();
        mock_latencies.insert("127.0.0.1:8080".parse().unwrap(), (10, 10).into());
        mock_latencies.insert("127.0.0.1:8081".parse().unwrap(), (50, 50).into());
        mock_latencies.insert("127.0.0.1:8082".parse().unwrap(), (30, 30).into());

        let phoenix = Phoenix::new(MockMeasurement {
            latencies: mock_latencies,
        });

        phoenix.add_node("127.0.0.1:8080".parse().unwrap(), abcd());
        phoenix.add_node("127.0.0.1:8081".parse().unwrap(), efgh());
        phoenix.add_node("127.0.0.1:8082".parse().unwrap(), ijkl());

        phoenix.measure_all_nodes().await;

        let ordered_nodes = phoenix.ordered_nodes_by_latency();

        assert_eq!(ordered_nodes[0].0, abcd());
        assert_eq!(ordered_nodes[1].0, ijkl());
        assert_eq!(ordered_nodes[2].0, efgh());
    }

    #[test]
    fn invalid_interval_range() {
        let measurement = MockMeasurement {
            latencies: HashMap::new(),
        };

        let result = std::panic::catch_unwind(|| {
            Builder::new(measurement)
                .interval_range(Duration::from_secs(10)..Duration::from_secs(5))
                .build()
        });

        assert!(
            result.is_err(),
            "Builder should panic when given an invalid interval range."
        );
    }

    #[test]
    fn node_not_added() {
        let mock_latencies = HashMap::new();
        let phoenix = Phoenix::new(MockMeasurement {
            latencies: mock_latencies,
        });
        let result = phoenix.get_coordinates(&"127.0.0.1:8080".parse().unwrap());

        assert!(
            result.is_none(),
            "Should not get coordinates for a node that was not added."
        );
    }

    #[test]
    fn invalid_subset_percentage() {
        let measurement = MockMeasurement {
            latencies: HashMap::new(),
        };

        let result =
            std::panic::catch_unwind(|| Builder::new(measurement).subset_percentage(1.5).build());

        assert!(
            result.is_err(),
            "Builder should panic when given an invalid subset percentage."
        );
    }

    #[tokio::test]
    async fn successful_measurements() {
        let latencies = HashMap::from([
            ("127.0.0.1:8080".parse().unwrap(), (100, 100).into()),
            ("127.0.0.1:8081".parse().unwrap(), (200, 200).into()),
        ]);
        let failed_addresses = Arc::new(Mutex::new(HashSet::new()));
        let measurement = FailedAddressesMock {
            latencies,
            failed_addresses,
        };

        let phoenix = Phoenix::new(measurement);

        phoenix.add_node("127.0.0.1:8080".parse().unwrap(), abcd());
        phoenix.add_node("127.0.0.1:8081".parse().unwrap(), efgh());

        phoenix.measure_all_nodes().await;

        let ordered_nodes = phoenix.ordered_nodes_by_latency();
        assert_eq!(ordered_nodes.len(), 2);
        assert_eq!(ordered_nodes[0].0, abcd());
        assert!(ordered_nodes[0].1 >= 100.);
        assert_eq!(ordered_nodes[1].0, efgh());
        assert!(ordered_nodes[1].1 >= 200.);
    }

    #[tokio::test]
    async fn failed_measurements_excluded() {
        let latencies = HashMap::from([
            ("127.0.0.1:8080".parse().unwrap(), (100, 100).into()),
            ("127.0.0.1:8081".parse().unwrap(), (200, 200).into()),
        ]);
        let failed_addresses = Arc::new(Mutex::new(HashSet::from(["127.0.0.1:8081"
            .parse()
            .unwrap()])));
        let measurement = FailedAddressesMock {
            latencies,
            failed_addresses,
        };

        let phoenix = Phoenix::new(measurement);

        phoenix.add_node("127.0.0.1:8080".parse().unwrap(), abcd());
        phoenix.add_node("127.0.0.1:8081".parse().unwrap(), efgh());

        phoenix.measure_all_nodes().await;

        let ordered_nodes = phoenix.ordered_nodes_by_latency();
        assert_eq!(ordered_nodes.len(), 1);
        assert_eq!(ordered_nodes[0].0, abcd());
        assert!(ordered_nodes[0].1 >= 100.);
    }

    #[tokio::test]
    async fn http_server() {
        let config = Arc::new(crate::Config::default_non_agent());
        let qcmp_listener = crate::net::TcpListener::bind(None).expect("failed to bind listener");
        let qcmp_port = qcmp_listener.port();
        config.datacenters().write().insert(
            std::net::Ipv4Addr::LOCALHOST.into(),
            crate::config::Datacenter {
                qcmp_port,
                icao_code: "ABCD".parse().unwrap(),
            },
        );

        let (_tx, rx) = crate::make_shutdown_channel(Default::default());
        let socket = raw_socket_with_reuse(qcmp_port).unwrap();
        crate::codec::qcmp::spawn(socket, rx.clone());
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        super::spawn(
            qcmp_listener,
            config.clone(),
            rx,
            crate::codec::qcmp::QcmpMeasurement::with_artificial_delay(
                std::time::Duration::from_millis(50),
            )
            .unwrap(),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = hyper::Client::new();

        let resp = client
            .get(format!("http://localhost:{qcmp_port}/").parse().unwrap())
            .await
            .map(|resp| resp.into_body())
            .map(hyper::body::to_bytes)
            .unwrap()
            .await
            .unwrap();

        let map = serde_json::from_slice::<serde_json::Map<_, _>>(&resp).unwrap();

        let coords = Coordinates {
            x: std::time::Duration::from_millis(50).as_nanos() as f64 / 2.0,
            y: std::time::Duration::from_millis(1).as_nanos() as f64 / 2.0,
        };

        let min = Coordinates::ORIGIN.distance_to(&coords);
        let max = min * 3.0;
        let distance = map["ABCD"].as_f64().unwrap();

        assert!(
            distance > min && distance < max,
            "expected distance {distance} to be > {min} and < {max}",
        );
    }
}
