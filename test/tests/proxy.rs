use qt::*;
use quilkin::test::TestConfig;

trace_test!(run_server, {
    let mut sc = qt::sandbox_config!();

    sc.push("server1", ServerPailConfig::default(), &[]);
    sc.push("server2", ServerPailConfig::default(), &[]);
    sc.push("proxy", ProxyPailConfig::default(), &["server1", "server2"]);

    let mut sb = sc.spinup().await;

    let mut server1_rx = sb.packet_rx("server1");
    let mut server2_rx = sb.packet_rx("server2");

    let addr = sb.proxy_addr();

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

trace_test!(run_client, {
    let mut sc = qt::sandbox_config!();

    sc.push("dest", ServerPailConfig::default(), &[]);
    sc.push("proxy", ProxyPailConfig::default(), &["dest"]);

    let mut sb = sc.spinup().await;

    let mut dest_rx = sb.packet_rx("dest");
    let local_addr = sb.proxy_addr();
    let client = sb.client();

    let msg = "hello";
    tracing::debug!(%local_addr, "sending packet");
    client.send_to(msg.as_bytes(), &local_addr).await.unwrap();
    assert_eq!(msg, sb.timeout(100, dest_rx.recv()).await.unwrap(),);
});

trace_test!(run_with_filter, {
    let mut sc = qt::sandbox_config!();

    sc.push("server", ServerPailConfig::default(), &[]);
    sc.push(
        "proxy",
        ProxyPailConfig {
            config: Some(TestConfig::new()),
            ..Default::default()
        },
        &["server"],
    );

    let mut sb = sc.spinup().await;
    let local_addr = sb.proxy_addr();
    let mut rx = sb.packet_rx("server");
    let client = sb.client();

    let msg = "hello";
    client.send_to(msg.as_bytes(), &local_addr).await.unwrap();

    // search for the filter strings.
    let result = sb.timeout(100, rx.recv()).await.unwrap();
    assert!(result.starts_with(&format!("{msg}:odr:[::1]:")));
});

// trace_test!(spawn_downstream_receive_workers, {
//     let mut sc = qt::sandbox_config!();

//     sc.push("server", ServerPailConfig::default(), &[]);
//     let mut sb = sc.spinup().await;

//     let (mut packet_rx, endpoint) = sb.server("server");

//     let (error_sender, mut error_receiver) = tokio::sync::mpsc::unbounded_channel();

//     tokio::task::spawn(async move {
//         while let Some(error) = error_receiver.recv().await {
//             tracing::error!(%error, "error sent from DownstreamReceiverWorker");
//         }
//     });

//     let config = std::sync::Arc::new(quilkin::Config::default_non_agent());
//     config
//         .clusters
//         .modify(|clusters| clusters.insert_default([endpoint.into()].into()));
//     let (tx, rx) = async_channel::unbounded();
//     let (_shutdown_tx, shutdown_rx) =
//         quilkin::make_shutdown_channel(quilkin::ShutdownKind::Testing);

//     let socket = sb.client();
//     let addr = socket.local_addr().unwrap();

//     // we'll test a single DownstreamReceiveWorkerConfig
//     let ready = quilkin::components::proxy::packet_router::DownstreamReceiveWorkerConfig {
//         worker_id: 1,
//         port: addr.port(),
//         upstream_receiver: rx.clone(),
//         config: config.clone(),
//         error_sender,
//         buffer_pool: quilkin::test::BUFFER_POOL.clone(),
//         sessions: quilkin::components::proxy::SessionPool::new(
//             config,
//             tx,
//             BUFFER_POOL.clone(),
//             shutdown_rx,
//         ),
//     }
//     .spawn();

//     sb.timeout(500, ready.notified()).await;

//     let msg = "hello-downstream";

//     socket.send_to(msg.as_bytes(), addr).await.unwrap();

//     assert_eq!(
//         msg,
//         sb.timeout(100, packet_rx.recv())
//             .await
//             .expect("should receive a packet")
//     );
// });

// #[tokio::test]
// async fn run_recv_from() {
//     let t = TestHelper::default();

//     let msg = "hello";
//     let endpoint = t.open_socket_and_recv_single_packet().await;
//     let local_addr = available_addr(&AddressType::Random).await;
//     let proxy = crate::cli::Proxy {
//         port: local_addr.port(),
//         qcmp_port: 0,
//         ..<_>::default()
//     };

//     let config = Arc::new(crate::Config::default_non_agent());
//     config.clusters.modify(|clusters| {
//         clusters.insert_default(
//             [crate::net::endpoint::Endpoint::from(
//                 endpoint.socket.local_addr().unwrap(),
//             )]
//             .into(),
//         )
//     });

//     let (tx, rx) = async_channel::unbounded();
//     let (_shutdown_tx, shutdown_rx) = crate::make_shutdown_channel(crate::ShutdownKind::Testing);

//     let sessions = SessionPool::new(config.clone(), tx, BUFFER_POOL.clone(), shutdown_rx);

//     proxy
//         .run_recv_from(&config, proxy.port, 1, &sessions, rx, BUFFER_POOL.clone())
//         .unwrap();
//     tokio::time::sleep(Duration::from_millis(500)).await;

//     let socket = create_socket().await;
//     socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
//     assert_eq!(
//         msg,
//         timeout(Duration::from_secs(1), endpoint.packet_rx)
//             .await
//             .expect("should receive a packet")
//             .unwrap()
//     );
// }
