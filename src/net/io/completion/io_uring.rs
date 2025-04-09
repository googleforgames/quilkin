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

pub fn is_available() -> bool {
    let Err(err) = io_uring::IoUring::new(2) else {
        return true;
    };

    if err.kind() == std::io::ErrorKind::PermissionDenied && in_container() {
        tracing::error!(
            "failed to call `io_uring_setup` due to EPERM ({err}), quilkin seems to be running inside a container meaning this is likely due to the seccomp profile not allowing the syscall"
        );
    } else {
        tracing::error!("failed to call `io_uring_setup` due to {err}");
    }

    false
}

fn in_container() -> bool {
    let sched = match std::fs::read_to_string("/proc/1/sched") {
        Ok(s) => s,
        Err(error) => {
            tracing::warn!(
                %error,
                "unable to read /proc/1/sched to determine if quilkin is in a container"
            );
            return false;
        }
    };
    let Some(line) = sched.lines().next() else {
        tracing::warn!("/proc/1/sched was empty");
        return false;
    };
    let Some(proc) = line.split(' ').next() else {
        tracing::warn!("first line of /proc/1/sched was empty");
        return false;
    };
    proc != "init" && proc != "systemd"
}

pub fn listen(
    super::Worker {
        worker_id,
        port,
        config,
        sessions,
        buffer_pool,
    }: super::Worker,
    pending_sends: crate::net::PacketQueue,
) -> eyre::Result<()> {
    use crate::net::io_uring;

    let socket = crate::net::DualStackLocalSocket::new(port).context("failed to bind socket")?;

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
