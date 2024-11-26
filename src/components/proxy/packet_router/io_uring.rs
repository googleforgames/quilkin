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

use eyre::Context as _;

impl super::DownstreamReceiveWorkerConfig {
    pub async fn spawn(
        self,
        shutdown: crate::ShutdownRx,
    ) -> eyre::Result<std::sync::mpsc::Receiver<()>> {
        use crate::components::proxy::io_uring_shared;

        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let socket =
            crate::net::DualStackLocalSocket::new(port).context("failed to bind socket")?;

        let io_loop = io_uring_shared::IoUringLoop::new(2000, socket)?;
        io_loop
            .spawn(
                format!("packet-router-{worker_id}"),
                io_uring_shared::PacketProcessorCtx::Router {
                    config,
                    sessions,
                    error_acc: super::super::error::ErrorAccumulator::new(error_sender),
                    worker_id,
                    destinations: Vec::with_capacity(1),
                },
                io_uring_shared::PacketReceiver::Router(upstream_receiver),
                buffer_pool,
                shutdown,
            )
            .context("failed to spawn io-uring loop")
    }
}
