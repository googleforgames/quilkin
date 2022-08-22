/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::sync::Arc;

use notify::Watcher;

use crate::Config;

pub async fn watch(config: Arc<Config>, path: impl Into<std::path::PathBuf>) -> crate::Result<()> {
    let path = path.into();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::RecommendedWatcher::new(move |res| {
        tx.send(res).unwrap();
    })
    .unwrap();

    watcher.watch(&path, notify::RecursiveMode::Recursive)?;
    tracing::info!(path = %path.display(), "watching file");

    while let Some(event) = rx.recv().await.transpose()? {
        tracing::trace!(event = ?event.kind, "new file event");

        if !matches!(
            event.kind,
            notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
        ) {
            continue;
        }

        for path in event.paths {
            // At least on macOS it's not always safe to
            // immediately read file after the change, a small
            // delay fixes that.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            tracing::info!(path = %path.display(), "file changed, updating config");
            let buf = tokio::fs::read(path).await?;
            config.update_from_json(serde_yaml::from_slice(&buf)?)?;
        }
    }

    Err(eyre::eyre!("filesystem watch unexpectedly stopped"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn basic() {
        let source = Arc::new(crate::Config::default());
        let dest = Arc::new(crate::Config::default());
        let tmp_dir = tempdir::TempDir::new("path").unwrap();
        let file_path = tmp_dir.into_path().join("config.yaml");
        tokio::fs::write(&file_path, serde_yaml::to_string(&source).unwrap())
            .await
            .unwrap();
        let _handle = tokio::spawn(watch(dest.clone(), file_path.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        source.clusters.modify(|clusters| {
            clusters
                .default_cluster_mut()
                .push(crate::endpoint::Endpoint::with_metadata(
                    (std::net::Ipv4Addr::LOCALHOST, 4321).into(),
                    crate::endpoint::Metadata {
                        tokens: <_>::from([Vec::from(*b"1x7ijy6")]),
                    },
                ));
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tokio::fs::write(&file_path, serde_yaml::to_string(&source).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(source, dest);
    }
}
