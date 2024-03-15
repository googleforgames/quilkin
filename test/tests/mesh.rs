use qt::*;
use quilkin::{
    filters::{self, *},
    net::endpoint::Endpoint,
    test::*,
};
use std::net::SocketAddr;

trace_test!(relay_routing, {
    struct Token {
        inner: [u8; 3],
    }

    impl Token {
        fn new() -> Self {
            const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

            use rand::prelude::SliceRandom;
            let mut rng = rand::thread_rng();

            let mut inner = [0; 3];
            for (v, slot) in CHARS
                .choose_multiple(&mut rng, inner.len())
                .zip(inner.iter_mut())
            {
                *slot = *v;
            }

            Self { inner }
        }
    }

    use std::fmt;
    impl fmt::Display for Token {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(std::str::from_utf8(&self.inner).unwrap())
        }
    }

    let mut sc = qt::sandbox_config!();

    sc.push("server", ServerPailConfig::default(), &[]);
    sc.push(
        "relay",
        RelayPailConfig {
            config: TestConfig {
                filters: FilterChain::try_create([
                    Capture::as_filter_config(capture::Config {
                        metadata_key: filters::CAPTURED_BYTES.into(),
                        strategy: filters::capture::Strategy::Suffix(capture::Suffix {
                            size: 3,
                            remove: true,
                        }),
                    })
                    .unwrap(),
                    TokenRouter::as_filter_config(None).unwrap(),
                ])
                .unwrap(),
                ..Default::default()
            },
        },
        &[],
    );
    sc.push(
        "agent",
        AgentPailConfig {
            endpoints: vec![("server", &["abc"])],
        },
        &["server", "relay"],
    );
    sc.push("proxy", ProxyPailConfig {}, &["relay"]);

    let mut sandbox = sc.spinup().await;

    let (server_port, mut server_rx) = {
        let Some(Pail::Server(sp)) = sandbox.pails.get_mut("server") else {
            unreachable!()
        };

        (sp.port, sp.packet_rx.take().unwrap())
    };
    let Pail::Proxy(pp) = &sandbox.pails["proxy"] else {
        unreachable!()
    };
    let proxy_address = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, pp.port));
    let Pail::Agent(ap) = &sandbox.pails["agent"] else {
        unreachable!()
    };

    let client = create_socket().await;

    for _ in 0..5 {
        let token = Token::new();
        sandbox.sleep(50).await;

        ap.config.update(|config| {
            config.clusters.insert_default(
                [Endpoint::with_metadata(
                    (std::net::Ipv6Addr::LOCALHOST, server_port).into(),
                    quilkin::net::endpoint::Metadata {
                        tokens: Some(token.inner.to_vec()).into_iter().collect(),
                    },
                )]
                .into(),
            );
        });

        sandbox.sleep(580).await;

        let mut msg = b"hello".to_vec();
        msg.extend_from_slice(&token.inner);

        tracing::info!(%token, "sending packet");
        client.send_to(&msg, &proxy_address).await.unwrap();

        assert_eq!(
            "hello",
            sandbox.timeout(1000, server_rx.recv()).await.unwrap()
        );

        tracing::info!(%token, "received packet");

        tracing::info!(%token, "sending bad packet");
        // send an invalid packet
        client
            .send_to(b"hello\xFF\xFF\xFF", &proxy_address)
            .await
            .unwrap();

        sandbox.expect_timeout(50, server_rx.recv()).await;
        tracing::info!(%token, "didn't receive bad packet");
    }
});

// #[tokio::test]
// async fn datacenter_discovery() {
//     let relay_xds_port = crate::test::available_addr(&AddressType::Random)
//         .await
//         .port();
//     let relay_mds_port = crate::test::available_addr(&AddressType::Random)
//         .await
//         .port();
//     let relay_config = Arc::new(Config::default_non_agent());
//     let relay = Relay {
//         xds_port: relay_xds_port,
//         mds_port: relay_mds_port,
//         ..<_>::default()
//     };

//     let agent_file = tempfile::NamedTempFile::new().unwrap();
//     let config = Config::default_agent();

//     std::fs::write(agent_file.path(), serde_yaml::to_string(&config).unwrap()).unwrap();

//     let agent_qcmp_port = crate::test::available_addr(&AddressType::Random)
//         .await
//         .port();

//     let icao_code: crate::config::IcaoCode = "EIDW".parse().unwrap();

//     let agent_config = Arc::new(Config::default_agent());
//     let agent = Agent {
//         relay: vec![format!("http://localhost:{relay_mds_port}")
//             .parse()
//             .unwrap()],
//         region: None,
//         sub_zone: None,
//         zone: None,
//         idle_request_interval_secs: admin::idle_request_interval_secs(),
//         qcmp_port: agent_qcmp_port,
//         icao_code: icao_code.clone(),
//         provider: Some(Providers::File {
//             path: agent_file.path().to_path_buf(),
//         }),
//     };

//     let proxy_config = Arc::new(Config::default_non_agent());
//     let proxy = Proxy {
//         management_server: vec![format!("http://localhost:{relay_xds_port}")
//             .parse()
//             .unwrap()],
//         ..<_>::default()
//     };

//     let (_tx, shutdown_rx) = crate::make_shutdown_channel(Default::default());
//     tokio::spawn({
//         let config = relay_config.clone();
//         let shutdown_rx = shutdown_rx.clone();
//         async move {
//             relay
//                 .run(config, Admin::Relay(<_>::default()), shutdown_rx)
//                 .await
//         }
//     });
//     tokio::time::sleep(std::time::Duration::from_millis(150)).await;
//     tokio::spawn({
//         let config = agent_config.clone();
//         let shutdown_rx = shutdown_rx.clone();
//         async move {
//             agent
//                 .run(config, Admin::Agent(<_>::default()), shutdown_rx)
//                 .await
//         }
//     });
//     tokio::time::sleep(std::time::Duration::from_millis(250)).await;
//     let (tx, proxy_init) = tokio::sync::oneshot::channel();
//     tokio::spawn({
//         let config = proxy_config.clone();
//         let shutdown_rx = shutdown_rx.clone();
//         async move {
//             proxy
//                 .run(config, Admin::Proxy(<_>::default()), Some(tx), shutdown_rx)
//                 .await
//         }
//     });
//     proxy_init.await.unwrap();
//     tokio::time::sleep(Duration::from_millis(150)).await;

//     let datacenter = crate::config::Datacenter {
//         qcmp_port: agent_qcmp_port,
//         icao_code,
//     };

//     assert!(!relay_config.datacenters().read().is_empty());
//     assert!(!proxy_config.datacenters().read().is_empty());

//     #[track_caller]
//     fn assert_config(config: &Config, datacenter: &crate::config::Datacenter) {
//         let dcs = config.datacenters().read();
//         let ipv4_dc = dcs.get(&std::net::Ipv4Addr::LOCALHOST.into());
//         let ipv6_dc = dcs.get(&std::net::Ipv6Addr::LOCALHOST.into());

//         match (ipv4_dc, ipv6_dc) {
//             (Some(dc), None) => assert_eq!(&*dc, datacenter),
//             (None, Some(dc)) => assert_eq!(&*dc, datacenter),
//             (Some(dc1), Some(dc2)) => {
//                 assert_eq!(&*dc1, datacenter);
//                 assert_eq!(&*dc2, datacenter);
//             }
//             (None, None) => panic!("No datacenter found"),
//         };
//     }
//     assert_config(&relay_config, &datacenter);
//     assert_config(&proxy_config, &datacenter);
// }
