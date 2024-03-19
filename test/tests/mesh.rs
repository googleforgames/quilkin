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
                        metadata_key: filters::capture::CAPTURED_BYTES.into(),
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
            ..Default::default()
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

        ap.config_file.update(|config| {
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

#[tokio::test]
async fn datacenter_discovery() {
    let mut sc = qt::sandbox_config!();

    let icao_code = "EIDW".parse().unwrap();

    sc.push("relay", RelayPailConfig::default(), &[]);
    sc.push(
        "agent",
        AgentPailConfig {
            icao_code,
            ..Default::default()
        },
        &["relay"],
    );
    sc.push("proxy", ProxyPailConfig::default(), &["relay"]);

    let sandbox = sc.spinup().await;
    sandbox.sleep(150).await;

    let Pail::Agent(AgentPail { qcmp_port, .. }) = &sandbox.pails["agent"] else {
        unreachable!()
    };

    let datacenter = quilkin::config::Datacenter {
        qcmp_port: *qcmp_port,
        icao_code,
    };

    let Pail::Relay(RelayPail {
        config: relay_config,
        ..
    }) = &sandbox.pails["relay"]
    else {
        unreachable!()
    };
    let Pail::Proxy(ProxyPail {
        config: proxy_config,
        ..
    }) = &sandbox.pails["proxy"]
    else {
        unreachable!()
    };

    #[track_caller]
    fn assert_config(config: &quilkin::Config, datacenter: &quilkin::config::Datacenter) {
        let dcs = config.datacenters().read();
        let ipv4_dc = dcs.get(&std::net::Ipv4Addr::LOCALHOST.into());
        let ipv6_dc = dcs.get(&std::net::Ipv6Addr::LOCALHOST.into());

        match (ipv4_dc, ipv6_dc) {
            (Some(dc), None) => assert_eq!(&*dc, datacenter),
            (None, Some(dc)) => assert_eq!(&*dc, datacenter),
            (Some(dc1), Some(dc2)) => {
                assert_eq!(&*dc1, datacenter);
                assert_eq!(&*dc2, datacenter);
            }
            (None, None) => panic!("No datacenter found"),
        };
    }

    assert_config(&relay_config, &datacenter);
    assert_config(&proxy_config, &datacenter);
}
