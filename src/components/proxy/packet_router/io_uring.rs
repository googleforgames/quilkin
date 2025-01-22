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
    pub fn spawn(self, pending_sends: crate::net::PacketQueue) -> eyre::Result<()> {
        use crate::net::io_uring;

        let Self {
            worker_id,
            port,
            config,
            sessions,
            buffer_pool,
        } = self;

        let socket =
            crate::net::DualStackLocalSocket::new(port).context("failed to bind socket")?;

        let io_loop = io_uring::IoUringLoop::new(2000, socket)?;
        io_loop
            .spawn(
                format!("packet-router-{worker_id}"),
                io_uring::PacketProcessorCtx::Router {
                    config,
                    sessions,
                    worker_id,
                    destinations: Vec::with_capacity(1),
                },
                pending_sends,
                buffer_pool,
            )
            .context("failed to spawn io-uring loop")
    }
}
