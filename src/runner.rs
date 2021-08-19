/*
 * Copyright 2021 Google LLC
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

use std::{net::Ipv4Addr, sync::Arc};

use slog::{debug, info, o};
use tokio::{
    signal,
    sync::{oneshot, watch},
};

use crate::{
    config::{Config, TestSuite},
    endpoint::Endpoint,
    filters::{DynFilterFactory, FilterRegistry, FilterSet},
    proxy::Builder,
    Result,
};

#[cfg(doc)]
use crate::filters::FilterFactory;

/// Calls [`run`] with the [`Config`] found by [`Config::find`] and the
/// default [`FilterSet`].
pub async fn run(filter_factories: impl IntoIterator<Item = DynFilterFactory>) -> Result<()> {
    let log = crate::proxy::logger();
    run_with_config(
        log.clone(),
        Config::find(&log, None).map(Arc::new)?,
        filter_factories,
    )
    .await
}

/// Start and run a proxy. Any passed in [`FilterFactory`]s are included
/// alongside the default filter factories.
pub async fn run_with_config(
    base_log: slog::Logger,
    config: Arc<Config>,
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<()> {
    let log = base_log.new(o!("source" => "run"));
    let server = Builder::from(config)
        .with_log(base_log)
        .with_filter_registry(FilterRegistry::new(FilterSet::default_with(
            &log,
            filter_factories.into_iter(),
        )))
        .validate()?
        .build();

    #[cfg(target_os = "linux")]
    let mut sig_term_fut = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
    let signal_log = log.clone();
    let (ready_tx, _ready_rx) = oneshot::channel();
    tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        let sig_term = sig_term_fut.recv();
        #[cfg(not(target_os = "linux"))]
        let sig_term = std::future::pending();

        tokio::select! {
            _ = signal::ctrl_c() => {
                debug!(signal_log, "Received SIGINT")
            }
            _ = sig_term => {
                debug!(signal_log, "Received SIGTERM")
            }
        }

        info!(signal_log, "Shutting down");
        // Don't unwrap in order to ensure that we execute
        // any subsequent shutdown tasks.
        shutdown_tx.send(()).ok();
    });

    if let Err(err) = server.run(ready_tx, shutdown_rx).await {
        info!(log, "Shutting down with error"; "error" => %err);
        Err(err)
    } else {
        Ok(())
    }
}

/// Start and run a proxy. Any passed in [`FilterFactory`]s are included
/// alongside the default filter factories.
pub async fn test(
    base_log: slog::Logger,
    mut testsuite: TestSuite,
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<()> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let mut receiver = socket.local_addr().unwrap();
    receiver.set_ip(Ipv4Addr::LOCALHOST.into());

    std::thread::spawn(move || {
        let mut packet = [0; 0xffff];
        loop {
            let (length, addr) = socket.recv_from(&mut packet).unwrap();
            let packet = &packet[..length];
            socket.send_to(packet, addr).unwrap();
        }
    });

    let log = base_log.new(o!("source" => "run"));

    {
        let endpoints = testsuite.config.source.get_static_endpoints_mut().unwrap();
        *endpoints = vec![Endpoint::new(receiver)];
    }

    let builder = Builder::from(Arc::new(dbg!(testsuite.config)))
        .with_log(base_log)
        .disable_admin()
        .with_filter_registry(FilterRegistry::new(FilterSet::default_with(
            &log,
            filter_factories.into_iter(),
        )))
        .validate()?;

    let server = builder.build();

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let (ready_tx, ready_rx) = oneshot::channel();
    let server_handle = tokio::spawn(server.run(ready_tx, shutdown_rx));

    let mut address = ready_rx.await?;
    address.set_ip(Ipv4Addr::LOCALHOST.into());

    let handles =
        futures::future::join_all(testsuite.options.tests.into_iter().map(|(name, options)| {
            let log = log.clone();
            tokio::spawn(async move {
                let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .await
                    .unwrap();

                socket
                    .send_to(options.input.as_bytes(), address)
                    .await
                    .unwrap();

                let mut buf = vec![0; 0xffff];
                let length = socket.recv(&mut buf).await.unwrap();
                assert_eq!(options.output.as_bytes(), &buf[..length]);
                slog::info!(log, "{} Completed Successfully ✅", name);
            })
        }))
        .await;

    if handles.into_iter().any(|result| result.is_err()) {
        panic!("Some tests failed to complete.");
    } else {
        slog::info!(log, "All tests completed successfully 🎉");
    }

    shutdown_tx.send(())?;
    server_handle.await.unwrap().unwrap();

    Ok(())
}
