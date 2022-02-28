/*
 * Copyright 2020 Google LLC
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

use std::sync::Arc;

use tokio::sync::watch;

use crate::{
    proxy::{builder::ValidatedConfig, Admin},
    Result,
};

/// Server is the UDP server main implementation
pub struct Server {
    // We use pub(super) to limit instantiation only to the Builder.
    pub(super) config: Arc<ValidatedConfig>,
    // Admin may be turned off, primarily for testing.
    pub(super) admin: Option<Admin>,
}

impl Server {
    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, shutdown_rx: watch::Receiver<()>) -> Result<()> {
        tracing::info!(
            port = self.config.proxy.port,
            proxy_id = &*self.config.proxy.id,
            "Starting"
        );

        let socket = crate::Socket::bind_from_config(&*self.config, shutdown_rx.clone()).await?;

        if let Some(admin) = &self.admin {
            admin.run(socket.cluster(), socket.filters(), shutdown_rx.clone());
        }

        let num_workers = num_cpus::get();

        let workers = (0..num_workers).map(move |_| {
            let socket = socket.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    result = socket.process_worker() => {
                        result
                    }
                    _ = shutdown_rx.changed() => {
                        Ok(())
                    }
                }
            })
        });

        tracing::info!("Quilkin is ready.");
        for worker in workers {
            worker.await??;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use crate::{
        config::{self, Builder as ConfigBuilder},
        endpoint::Endpoint,
        proxy::Builder,
        test_utils::{load_test_filters, TestHelper},
    };

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = (Ipv4Addr::UNSPECIFIED, 12358);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.1)
            .with_static(
                vec![],
                vec![
                    Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                    Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
                ],
            )
            .build();
        t.run_server_with_config(config);

        let msg = "hello";
        endpoint1
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint1.packet_rx.await.unwrap());
        assert_eq!(msg, endpoint2.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn run_client() {
        let mut t = TestHelper::default();

        let endpoint = t.open_socket_and_recv_single_packet().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![],
                vec![Endpoint::new(endpoint.socket.local_addr().unwrap().into())],
            )
            .build();
        t.run_server_with_config(config);

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn run_with_filter() {
        let mut t = TestHelper::default();

        load_test_filters();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![config::Filter {
                    name: "TestFilter".to_string(),
                    config: None,
                }],
                vec![Endpoint::new(endpoint.socket.local_addr().unwrap().into())],
            )
            .build();
        t.run_server_with_builder(Builder::from(Arc::new(config)).disable_admin());

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();

        // since we don't know what the session ephemeral port is, we'll just
        // search for the filter strings.
        let result = endpoint.packet_rx.await.unwrap();
        assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
        assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
    }
}
