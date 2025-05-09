/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::sync::Arc;

use super::sessions::SessionPool;
use crate::Config;

pub mod completion;
pub mod nic;
pub mod poll;
pub(crate) mod socket;

pub use socket::{Socket, SystemSocket};

/// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
/// Each received packet is placed on a queue to be processed by a worker task.
/// This function also spawns the set of worker tasks responsible for consuming packets
/// off the aforementioned queue and processing them through the filter chain and session
/// pipeline.
#[allow(clippy::type_complexity)]
pub fn listen(
    config: &Arc<Config>,
    udp_port: Option<u16>,
    qcmp_port: Option<u16>,
    workers: usize,
    xdp: crate::cli::XdpOptions,
    shutdown_rx: &crate::signal::ShutdownRx,
    backend: Backend,
) -> crate::Result<(
    impl Future<Output = crate::Result<()>> + use<>,
    Option<crate::cli::Finalizer>,
    Option<Arc<crate::net::sessions::SessionPool>>,
)> {
    if udp_port.is_none() && qcmp_port.is_none() {
        panic!("bug: `net::io::listen` requires either `udp` or `qcmp` to be set");
    }

    tracing::info!(%backend, "network I/O interface chosen");
    match backend {
        Backend::NetworkInterface => {
            let finalizer = nic::listen(
                config,
                udp_port.unwrap_or_default(),
                qcmp_port.unwrap_or_default(),
                xdp,
            )?;
            Ok((either::Left(std::future::pending()), finalizer, None))
        }
        backend => {
            if let Some(socket) = qcmp_port
                .map(|port| backend.socket_from_port(port))
                .transpose()?
            {
                crate::codec::qcmp::spawn(socket, shutdown_rx.clone())?;
            }

            let Some(port) = udp_port else {
                return Ok((either::Left(std::future::pending()), None, None));
            };

            let buffer_pool = Arc::new(crate::collections::BufferPool::new(workers, 2 * 1024));

            let mut worker_sends = Vec::with_capacity(workers);
            let mut session_sends = Vec::with_capacity(workers);
            for _ in 0..workers {
                let queue = crate::net::packet::queue(15, backend)?;
                session_sends.push(queue.0.clone());
                worker_sends.push(queue);
            }

            let sessions =
                SessionPool::new(config.clone(), session_sends, buffer_pool.clone(), backend);

            for (worker_id, ws) in worker_sends.into_iter().enumerate() {
                let worker = Listener {
                    worker_id,
                    port,
                    config: config.clone(),
                    sessions: sessions.clone(),
                    buffer_pool: buffer_pool.clone(),
                };

                if backend == Backend::Completion {
                    completion::listen(worker, ws)?;
                } else {
                    poll::listen(worker, ws)?;
                }
            }

            Ok((
                either::Right(std::future::pending()),
                Some(Box::from(
                    move |_shutdown_rx: &crate::signal::ShutdownRx| {},
                )),
                Some(sessions),
            ))
        }
    }
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub struct Listener {
    /// ID of the worker.
    pub worker_id: usize,
    pub port: u16,
    pub config: Arc<Config>,
    pub sessions: Arc<SessionPool>,
    pub buffer_pool: Arc<crate::collections::BufferPool>,
}

/// The underlying I/O listener responsible for actually sending and receiving
/// packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Polling based driven backend (e.g. `epoll`)
    Polling,
    /// Async "completion" based driven backend (e.g. `io-uring`)
    ///
    /// **Note:** Currently only supports Linux.
    Completion,
    /// Network Interface Controller driven backend (e.g. eBPF XDP)
    ///
    /// **Note:** Currently only supports Linux.
    NetworkInterface,
}

impl Backend {
    pub(crate) fn query(xdp: &crate::cli::XdpOptions) -> Self {
        nic::is_available(xdp)
            .then_some(Backend::NetworkInterface)
            .or_else(|| completion::is_available().then_some(Backend::Completion))
            .unwrap_or(Backend::Polling)
    }

    pub(crate) fn queue(self) -> std::io::Result<(Notifier, Receiver)> {
        match self {
            Self::NetworkInterface => unreachable!("queues are unsupported for NIC backends"),
            Self::Polling => Ok(poll::queue()),
            Self::Completion => completion::queue(),
        }
    }

    pub(crate) fn socket(self, addr: std::net::SocketAddr) -> std::io::Result<super::Socket> {
        match self {
            Self::NetworkInterface => unreachable!("sockets are unsupported for NIC backends"),
            Self::Polling => super::Socket::polling_from_addr(addr),
            Self::Completion => super::Socket::completion_from_addr(addr),
        }
    }

    pub(crate) fn socket_from_port(self, port: u16) -> std::io::Result<super::Socket> {
        self.socket((std::net::Ipv6Addr::UNSPECIFIED, port).into())
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkInterface => f.write_str(nic::NAME),
            Self::Completion => f.write_str(completion::NAME),
            Self::Polling => f.write_str(poll::NAME),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Notifier {
    Completion(completion::Notifier),
    Polling(poll::Notifier),
}

impl Notifier {
    pub fn notify(&self) {
        match self {
            Self::Completion(notify) => {
                notify.notify();
            }
            Self::Polling(notify) => {
                let _ = notify.send(true);
            }
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Receiver {
    Polling(poll::Receiver),
    Completion(completion::Receiver),
}

impl Receiver {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn as_completion_mut(&mut self) -> &mut completion::Receiver {
        match self {
            Self::Completion(notify) => notify,
            Self::Polling(_) => unreachable!("bug: `as_completion` called on `polling` backend"),
        }
    }

    pub fn as_polling(&self) -> &poll::Receiver {
        match self {
            Self::Polling(notify) => notify,
            Self::Completion(_) => unreachable!("bug: `as_polling` called on `completion` backend"),
        }
    }

    pub fn as_polling_mut(&mut self) -> &mut poll::Receiver {
        match self {
            Self::Polling(notify) => notify,
            Self::Completion(_) => {
                unreachable!("bug: `as_polling_mut` called on `completion` backend")
            }
        }
    }
}
