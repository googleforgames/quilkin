use qt::*;
use quilkin::{components::proxy, net, test::TestConfig};

trace_test!(server, {
    let mut sc = qt::sandbox_config!();

    sc.push("server1", ServerPailConfig::default(), &[]);
    sc.push("server2", ServerPailConfig::default(), &[]);
    sc.push("proxy", ProxyPailConfig::default(), &["server1", "server2"]);

    let mut sb = sc.spinup().await;

    let mut server1_rx = sb.packet_rx("server1");
    let mut server2_rx = sb.packet_rx("server2");

    let (addr, _) = sb.proxy("proxy");

    tracing::trace!(%addr, "sending packet");
    let msg = "hello";

    let client = sb.client();

    client.send_to(msg.as_bytes(), &addr).await.unwrap();
    assert_eq!(
        msg,
        sb.timeout(100, server1_rx.recv())
            .await
            .expect("should get a packet")
    );
    assert_eq!(
        msg,
        sb.timeout(100, server2_rx.recv())
            .await
            .expect("should get a packet")
    );
});

trace_test!(client, {
    let mut sc = qt::sandbox_config!();

    sc.push("dest", ServerPailConfig::default(), &[]);
    sc.push("proxy", ProxyPailConfig::default(), &["dest"]);

    let mut sb = sc.spinup().await;

    let mut dest_rx = sb.packet_rx("dest");
    let (local_addr, _) = sb.proxy("proxy");
    let client = sb.client();

    let msg = "hello";
    tracing::debug!(%local_addr, "sending packet");
    client.send_to(msg.as_bytes(), &local_addr).await.unwrap();
    assert_eq!(msg, sb.timeout(100, dest_rx.recv()).await.unwrap(),);
});

trace_test!(with_filter, {
    let mut sc = qt::sandbox_config!();

    sc.push("server", ServerPailConfig::default(), &[]);
    sc.push(
        "proxy",
        ProxyPailConfig {
            config: Some(TestConfig::new()),
        },
        &["server"],
    );

    let mut sb = sc.spinup().await;
    let (local_addr, _) = sb.proxy("proxy");
    let mut rx = sb.packet_rx("server");
    let client = sb.client();

    let msg = "hello";
    client.send_to(msg.as_bytes(), &local_addr).await.unwrap();

    // search for the filter strings.
    let result = sb.timeout(100, rx.recv()).await.unwrap();
    assert!(result.starts_with(&format!("{msg}:odr:[::1]:")));
});

trace_test!(uring_receiver, {
    let mut sc = qt::sandbox_config!();

    sc.push("server", ServerPailConfig::default(), &[]);
    let mut sb = sc.spinup().await;

    let (mut packet_rx, endpoint) = sb.server("server");

    let config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    config
        .dyn_cfg
        .clusters()
        .unwrap()
        .modify(|clusters| clusters.insert_default([endpoint.into()].into()));

    let socket = sb.client();
    let (ws, addr) = sb.socket();

    let pending_sends = net::queue(1).unwrap();

    // we'll test a single DownstreamReceiveWorkerConfig
    proxy::packet_router::DownstreamReceiveWorkerConfig {
        worker_id: 1,
        port: addr.port(),
        config: config.clone(),
        buffer_pool: quilkin::test::BUFFER_POOL.clone(),
        sessions: proxy::SessionPool::new(
            config,
            vec![pending_sends.0.clone()],
            BUFFER_POOL.clone(),
        ),
    }
    .spawn(pending_sends)
    .expect("failed to spawn task");

    // Drop the socket, otherwise it can
    drop(ws);

    let msg = "hello-downstream";
    tracing::debug!("sending packet");
    socket.send_to(msg.as_bytes(), addr).await.unwrap();
    assert_eq!(msg, sb.timeout(200, packet_rx.recv()).await.unwrap());
});

trace_test!(
    #[ignore]
    recv_from,
    {
        let mut sc = qt::sandbox_config!();

        sc.push("server", ServerPailConfig::default(), &[]);
        let mut sb = sc.spinup().await;

        let (mut packet_rx, endpoint) = sb.server("server");

        let config = std::sync::Arc::new(quilkin::Config::default_non_agent());
        config
            .dyn_cfg
            .clusters()
            .unwrap()
            .modify(|clusters| clusters.insert_default([endpoint.into()].into()));

        let pending_sends: Vec<_> = [
            net::queue(1).unwrap(),
            net::queue(1).unwrap(),
            net::queue(1).unwrap(),
        ]
        .into_iter()
        .collect();

        let sessions = proxy::SessionPool::new(
            config.clone(),
            pending_sends.iter().map(|ps| ps.0.clone()).collect(),
            BUFFER_POOL.clone(),
        );

        const WORKER_COUNT: usize = 3;

        let (socket, addr) = sb.socket();
        proxy::packet_router::spawn_receivers(
            config,
            socket,
            pending_sends,
            &sessions,
            BUFFER_POOL.clone(),
        )
        .unwrap();

        let socket = std::sync::Arc::new(sb.client());
        let msg = "recv-from";

        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..WORKER_COUNT {
            let ss = socket.clone();
            tasks.spawn(async move { ss.send_to(msg.as_bytes(), addr).await.unwrap() });
        }

        while let Some(res) = tasks.join_next().await {
            assert_eq!(res.unwrap(), msg.len());
        }

        for _ in 0..WORKER_COUNT {
            assert_eq!(
                msg,
                sb.timeout(20, packet_rx.recv())
                    .await
                    .expect("should receive a packet")
            );
        }
    }
);
