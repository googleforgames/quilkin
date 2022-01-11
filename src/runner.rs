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

use std::sync::Arc;

use tokio::{signal, sync::watch};
use tracing::{debug, info, span, Level};

use crate::{
    config::Config,
    filters::{DynFilterFactory, FilterRegistry, FilterSet},
    proxy::Builder,
    Result,
};

#[cfg(doc)]
use crate::filters::FilterFactory;

/// Calls [`run`] with the [`Config`] found by [`Config::find`] and the
/// default [`FilterSet`].
pub async fn run(filter_factories: impl IntoIterator<Item = DynFilterFactory>) -> Result<()> {
    run_with_config(Config::find(None).map(Arc::new)?, filter_factories).await
}

/// Start and run a proxy. Any passed in [`FilterFactory`]s are included
/// alongside the default filter factories.
pub async fn run_with_config(
    config: Arc<Config>,
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<()> {
    let span = span!(Level::INFO, "source::run");
    let _enter = span.enter();

    let server = Builder::from(config)
        .with_filter_registry(FilterRegistry::new(FilterSet::default_with(
            filter_factories.into_iter(),
        )))
        .validate()?
        .build();

    #[cfg(target_os = "linux")]
    let mut sig_term_fut = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
    tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        let sig_term = sig_term_fut.recv();
        #[cfg(not(target_os = "linux"))]
        let sig_term = std::future::pending();

        tokio::select! {
            _ = signal::ctrl_c() => {
                debug!("Received SIGINT")
            }
            _ = sig_term => {
                debug!("Received SIGTERM")
            }
        }

        info!("Shutting down");
        // Don't unwrap in order to ensure that we execute
        // any subsequent shutdown tasks.
        shutdown_tx.send(()).ok();
    });

    if let Err(err) = server.run(shutdown_rx).await {
        info! (error = %err, "Shutting down with error");
        Err(err)
    } else {
        Ok(())
    }
}
