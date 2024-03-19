use qt::*;

trace_test!(run_server, {
    let mut sc = qt::sandbox_config!();

    sc.push("server1", ServerPailConfig::default(), &[]);
    sc.push("server2", ServerPailConfig::default(), &[]);
    sc.push("proxy", ProxyPailConfig::default(), &["server1", "server2"]);

    let mut sb = sc.spinup().await;

    let mut server1_rx = {
        let Some(Pail::Server(sp)) = sb.pails.get_mut("server1") else {
            unreachable!()
        };

        sp.packet_rx.take().unwrap()
    };
    let mut server2_rx = {
        let Some(Pail::Server(sp)) = sb.pails.get_mut("server2") else {
            unreachable!()
        };

        sp.packet_rx.take().unwrap()
    };

    let Pail::Proxy(ProxyPail { port, .. }) = &sb.pails["proxy"] else {
        unreachable!();
    };

    let addr = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, *port));
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

// #[tokio::test]
// async fn run_client() {
//     let mut t = TestHelper::default();

//     let endpoint = t.open_socket_and_recv_single_packet().await;
//     let mut local_addr = available_addr(&AddressType::Ipv6).await;
//     crate::test::map_addr_to_localhost(&mut local_addr);
//     let mut dest = endpoint.socket.local_ipv6_addr().unwrap();
//     crate::test::map_addr_to_localhost(&mut dest);

//     let proxy = crate::cli::Proxy {
//         port: local_addr.port(),
//         qcmp_port: 0,
//         ..<_>::default()
//     };

//     let config = Arc::new(Config::default_non_agent());
//     config.clusters.modify(|clusters| {
//         clusters.insert_default([Endpoint::new(dest.into())].into());
//     });
//     t.run_server(config, Some(proxy), None).await;

//     let msg = "hello";
//     tracing::debug!(%local_addr, "sending packet");
//     endpoint
//         .socket
//         .send_to(msg.as_bytes(), &local_addr)
//         .await
//         .unwrap();
//     assert_eq!(
//         msg,
//         timeout(Duration::from_millis(100), endpoint.packet_rx)
//             .await
//             .unwrap()
//             .unwrap()
//     );
// }

// #[tokio::test]
// async fn run_with_filter() {
//     let mut t = TestHelper::default();

//     load_test_filters();
//     let endpoint = t.open_socket_and_recv_single_packet().await;
//     let local_addr = available_addr(&AddressType::Random).await;
//     let mut dest = endpoint.socket.local_ipv4_addr().unwrap();
//     crate::test::map_addr_to_localhost(&mut dest);
//     let config = Arc::new(Config::default_non_agent());
//     config.filters.store(
//         crate::filters::FilterChain::try_create([config::Filter {
//             name: "TestFilter".to_string(),
//             label: None,
//             config: None,
//         }])
//         .map(Arc::new)
//         .unwrap(),
//     );
//     config.clusters.modify(|clusters| {
//         clusters.insert_default([Endpoint::new(dest.into())].into());
//     });
//     t.run_server(
//         config,
//         Some(crate::cli::Proxy {
//             port: local_addr.port(),
//             qcmp_port: 0,
//             ..<_>::default()
//         }),
//         None,
//     )
//     .await;

//     let msg = "hello";
//     endpoint
//         .socket
//         .send_to(msg.as_bytes(), &local_addr)
//         .await
//         .unwrap();

//     // search for the filter strings.
//     let result = timeout(Duration::from_millis(100), endpoint.packet_rx)
//         .await
//         .unwrap()
//         .unwrap();
//     assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
//     assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
// }

// #[tokio::test]
// async fn spawn_downstream_receive_workers() {
//     let t = TestHelper::default();

//     let (error_sender, _error_receiver) = mpsc::unbounded_channel();
//     let addr = crate::test::available_addr(&AddressType::Random).await;
//     let endpoint = t.open_socket_and_recv_single_packet().await;
//     let msg = "hello";
//     let config = Arc::new(Config::default_non_agent());
//     config.clusters.modify(|clusters| {
//         clusters.insert_default([endpoint.socket.local_addr().unwrap().into()].into())
//     });
//     let (tx, rx) = async_channel::unbounded();
//     let (_shutdown_tx, shutdown_rx) = crate::make_shutdown_channel(crate::ShutdownKind::Testing);

//     // we'll test a single DownstreamReceiveWorkerConfig
//     DownstreamReceiveWorkerConfig {
//         worker_id: 1,
//         port: addr.port(),
//         upstream_receiver: rx.clone(),
//         config: config.clone(),
//         error_sender,
//         buffer_pool: BUFFER_POOL.clone(),
//         sessions: SessionPool::new(config, tx, BUFFER_POOL.clone(), shutdown_rx),
//     }
//     .spawn();
//     tokio::time::sleep(std::time::Duration::from_millis(500)).await;

//     let socket = create_socket().await;
//     socket.send_to(msg.as_bytes(), &addr).await.unwrap();

//     assert_eq!(
//         msg,
//         timeout(Duration::from_secs(1), endpoint.packet_rx)
//             .await
//             .expect("should receive a packet")
//             .unwrap()
//     );
// }

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
