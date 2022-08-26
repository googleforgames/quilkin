/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#[cfg(test)]
mod tests {
    use crate::{game_server, is_gameserver_ready, Client};
    use kube::api::PostParams;
    use kube::runtime::wait::await_condition;
    use kube::{Api, ResourceExt};
    use quilkin::config::watch::agones::crd::GameServer;
    use quilkin::test_utils::TestHelper;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    /// This test exists to test that we can connect to an Agones GameServer directly.
    /// Useful in case one is not sure if an issue is Quilkin or general connectivity issues, such
    /// as a firewall settings, or an issue with Agones itself.
    async fn gameserver_no_sidecar() {
        let client = Client::new().await;
        let gameservers: Api<GameServer> =
            Api::namespaced(client.kubernetes.clone(), client.namespace.as_str());

        let gs = game_server();

        let pp = PostParams::default();
        let gs = gameservers.create(&pp, &gs).await.unwrap();

        let name = gs.name();
        let ready = await_condition(gameservers.clone(), name.as_str(), is_gameserver_ready());
        timeout(Duration::from_secs(30), ready)
            .await
            .expect("GameServer should be ready")
            .unwrap();
        let gs = gameservers.get(name.as_str()).await.unwrap();

        let t = TestHelper::default();
        let recv = t.open_socket_and_recv_single_packet().await;
        let status = gs.status.unwrap();
        let address = format!("{}:{}", status.address, status.ports.unwrap()[0].port);
        recv.socket
            .send_to("hello".as_bytes(), address)
            .await
            .unwrap();

        let response = timeout(Duration::from_secs(30), recv.packet_rx)
            .await
            .expect("should receive packet")
            .unwrap();
        assert_eq!("ACK: hello\n", response);
    }
}
