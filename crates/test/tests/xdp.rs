#![cfg(target_os = "linux")]
#![allow(clippy::undocumented_unsafe_blocks)]

use quilkin::{
    filters::{self, StaticFilter as _},
    net::{
        self,
        xdp::process::{self, xdp},
    },
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

#[inline]
fn endpoints(eps: &[(SocketAddr, &[u8])]) -> BTreeSet<net::Endpoint> {
    eps.iter()
        .map(|(addr, token)| {
            quilkin::net::Endpoint::with_metadata(
                (*addr).into(),
                net::endpoint::Metadata {
                    tokens: [token.to_vec()].into_iter().collect(),
                },
            )
        })
        .collect()
}

/// Validates we can do basic processing and forwarding of packets
#[tokio::test]
async fn simple_forwarding() {
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1111);
    const PROXY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 7777);
    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(5, 5, 5, 5), 8888);

    let config = quilkin::Config::default_non_agent();
    config.filters.store(Arc::new(
        filters::FilterChain::try_create([
            filters::Capture::as_filter_config(filters::capture::Config {
                metadata_key: filters::capture::CAPTURED_BYTES.into(),
                strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                    size: 1,
                    remove: false,
                }),
            })
            .unwrap(),
            filters::TokenRouter::as_filter_config(None).unwrap(),
        ])
        .unwrap(),
    ));
    config.clusters.modify(|clusters| {
        clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf0])]));
    });

    let mut state = process::State {
        external_port: PROXY.port().into(),
        config: Arc::new(config),
        destinations: Vec::with_capacity(1),
        sessions: Arc::new(Default::default()),
        local_ipv4: *PROXY.ip(),
        local_ipv6: Ipv6Addr::from_bits(0),
    };

    let data = [0xf0u8; 11];

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 0,
            frame_count: 1,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    let mut client_packet = unsafe { umem.alloc().unwrap() };

    etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
        .ipv4(CLIENT.ip().octets(), PROXY.ip().octets(), 64)
        .udp(CLIENT.port(), PROXY.port())
        .write(&mut client_packet, &data)
        .unwrap();

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    rx_slab.push_front(client_packet);
    let mut tx_slab = xdp::HeapSlab::with_capacity(1);
    process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

    assert!(rx_slab.is_empty());
    let server_packet = tx_slab.pop_back().unwrap();

    let mut packet_headers = etherparse::PacketHeaders::from_ethernet_slice(&server_packet)
        .expect("failed to parse packet");

    let th = packet_headers.transport.as_mut().unwrap();
    let udp = th.mut_udp().unwrap();
    assert_eq!(
        udp.checksum,
        udp.calc_checksum_ipv4_raw(PROXY.ip().octets(), SERVER.ip().octets(), &data)
            .unwrap()
    );

    insta::assert_debug_snapshot!(&packet_headers);
}

/// Validates that we can change between ipv4 <-> ipv6 packets
#[tokio::test]
async fn changes_ip_version() {
    const SERVER: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1), 1111, 0, 0);
    const PROXY4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 7777);
    const PROXY6: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(2, 2, 2, 2, 2, 2, 2, 2), 7777, 0, 0);
    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(5, 5, 5, 5), 8888);

    let config = quilkin::Config::default_non_agent();
    config.filters.store(Arc::new(
        filters::FilterChain::try_create([
            filters::Capture::as_filter_config(filters::capture::Config {
                metadata_key: filters::capture::CAPTURED_BYTES.into(),
                strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                    size: 1,
                    remove: false,
                }),
            })
            .unwrap(),
            filters::TokenRouter::as_filter_config(None).unwrap(),
        ])
        .unwrap(),
    ));
    config.clusters.modify(|clusters| {
        clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf1])]));
    });

    let mut state = process::State {
        external_port: PROXY4.port().into(),
        config: Arc::new(config),
        destinations: Vec::with_capacity(1),
        sessions: Arc::new(Default::default()),
        local_ipv4: *PROXY4.ip(),
        local_ipv6: *PROXY6.ip(),
    };

    let data = [0xf1u8; 11];

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 20,
            frame_count: 1,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    let mut tx_slab = xdp::HeapSlab::with_capacity(1);

    let port = {
        let mut client_packet = unsafe { umem.alloc().unwrap() };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv4(CLIENT.ip().octets(), PROXY4.ip().octets(), 64)
            .udp(CLIENT.port(), PROXY4.port())
            .write(&mut client_packet, &data)
            .unwrap();

        rx_slab.push_front(client_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        assert!(rx_slab.is_empty());
        let server_packet = tx_slab.pop_back().unwrap();

        let mut packet_headers = etherparse::PacketHeaders::from_ethernet_slice(&server_packet)
            .expect("failed to parse packet");

        let port = {
            let th = packet_headers.transport.as_mut().unwrap();
            let udp = th.mut_udp().unwrap();
            assert_eq!(
                udp.checksum,
                udp.calc_checksum_ipv6_raw(PROXY6.ip().octets(), SERVER.ip().octets(), &data)
                    .unwrap()
            );
            udp.source_port
        };

        insta::assert_debug_snapshot!(&packet_headers);
        umem.free_packet(server_packet);
        port
    };

    let mut server_packet = unsafe { umem.alloc().unwrap() };

    etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
        .ipv6(SERVER.ip().octets(), PROXY6.ip().octets(), 64)
        .udp(SERVER.port(), port)
        .write(&mut server_packet, &data)
        .unwrap();

    rx_slab.push_front(server_packet);
    process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

    assert!(rx_slab.is_empty());
    let client_packet = tx_slab.pop_back().unwrap();

    let mut packet_headers = etherparse::PacketHeaders::from_ethernet_slice(&client_packet)
        .expect("failed to parse packet");

    let th = packet_headers.transport.as_mut().unwrap();
    let udp = th.mut_udp().unwrap();
    assert_eq!(
        udp.checksum,
        udp.calc_checksum_ipv4_raw(PROXY4.ip().octets(), CLIENT.ip().octets(), &data)
            .unwrap()
    );

    insta::assert_debug_snapshot!(&packet_headers);
}

/// Validates we can do both removal and concatenation to the packet buffer
#[tokio::test]
async fn packet_manipulation() {
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1111);
    const PROXY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 7777);
    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(5, 5, 5, 5), 8888);

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 20,
            frame_count: 1,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    let mut tx_slab = xdp::HeapSlab::with_capacity(1);

    // Test suffix removal
    {
        let config = quilkin::Config::default_non_agent();
        config.filters.store(Arc::new(
            filters::FilterChain::try_create([
                filters::Capture::as_filter_config(filters::capture::Config {
                    metadata_key: filters::capture::CAPTURED_BYTES.into(),
                    strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                        size: 1,
                        remove: true,
                    }),
                })
                .unwrap(),
                filters::TokenRouter::as_filter_config(None).unwrap(),
            ])
            .unwrap(),
        ));
        config.clusters.modify(|clusters| {
            clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf1])]));
        });

        let mut state = process::State {
            external_port: PROXY.port().into(),
            config: Arc::new(config),
            destinations: Vec::with_capacity(1),
            sessions: Arc::new(Default::default()),
            local_ipv4: *PROXY.ip(),
            local_ipv6: Ipv6Addr::from_bits(0),
        };

        let data = [0xf1u8; 11];
        let mut len = data.len();

        while len > 0 {
            let mut client_packet = unsafe { umem.alloc().unwrap() };

            etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
                .ipv4(CLIENT.ip().octets(), PROXY.ip().octets(), 64)
                .udp(CLIENT.port(), PROXY.port())
                .write(&mut client_packet, &data[..len])
                .unwrap();

            rx_slab.push_front(client_packet);
            process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

            assert!(rx_slab.is_empty());
            let server_packet = tx_slab.pop_back().unwrap();

            let udp = xdp::packet::net_types::UdpPacket::parse_packet(&server_packet)
                .unwrap()
                .unwrap();
            len -= 1;
            assert_eq!(
                &server_packet[udp.data_offset..udp.data_offset + udp.data_length],
                &data[..len]
            );

            umem.free_packet(server_packet);
        }
    }

    // Test prefix removal
    {
        let config = quilkin::Config::default_non_agent();
        config.filters.store(Arc::new(
            filters::FilterChain::try_create([
                filters::Capture::as_filter_config(filters::capture::Config {
                    metadata_key: filters::capture::CAPTURED_BYTES.into(),
                    strategy: filters::capture::Strategy::Prefix(filters::capture::Prefix {
                        size: 1,
                        remove: true,
                    }),
                })
                .unwrap(),
                filters::TokenRouter::as_filter_config(None).unwrap(),
            ])
            .unwrap(),
        ));
        config.clusters.modify(|clusters| {
            clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf1])]));
        });

        let mut state = process::State {
            external_port: PROXY.port().into(),
            config: Arc::new(config),
            destinations: Vec::with_capacity(1),
            sessions: Arc::new(Default::default()),
            local_ipv4: *PROXY.ip(),
            local_ipv6: Ipv6Addr::from_bits(0),
        };

        let data = [0xf1u8; 11];
        let mut len = data.len();

        while len > 0 {
            let mut client_packet = unsafe { umem.alloc().unwrap() };

            etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
                .ipv4(CLIENT.ip().octets(), PROXY.ip().octets(), 64)
                .udp(CLIENT.port(), PROXY.port())
                .write(&mut client_packet, &data[..len])
                .unwrap();

            rx_slab.push_front(client_packet);
            process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

            assert!(rx_slab.is_empty());
            let server_packet = tx_slab.pop_back().unwrap();

            let udp = xdp::packet::net_types::UdpPacket::parse_packet(&server_packet)
                .unwrap()
                .unwrap();
            len -= 1;
            assert_eq!(
                &server_packet[udp.data_offset..udp.data_offset + udp.data_length],
                &data[..len]
            );

            umem.free_packet(server_packet);
        }
    }

    // Test suffix removal, combined with read append and write prepend
    {
        let concat_data = [0xff; 11];
        let config = quilkin::Config::default_non_agent();
        config.filters.store(Arc::new(
            filters::FilterChain::try_create([
                filters::Capture::as_filter_config(filters::capture::Config {
                    metadata_key: filters::capture::CAPTURED_BYTES.into(),
                    strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                        size: 18,
                        remove: true,
                    }),
                })
                .unwrap(),
                filters::TokenRouter::as_filter_config(None).unwrap(),
                filters::Concatenate::as_filter_config(filters::concatenate::Config {
                    on_read: filters::concatenate::Strategy::Append,
                    on_write: filters::concatenate::Strategy::Prepend,
                    bytes: concat_data.to_vec(),
                })
                .unwrap(),
            ])
            .unwrap(),
        ));
        let data = [0xf1u8; 20];
        config.clusters.modify(|clusters| {
            clusters.insert(None, endpoints(&[(SERVER.into(), &data[..data.len() - 2])]));
        });

        let mut state = process::State {
            external_port: PROXY.port().into(),
            config: Arc::new(config),
            destinations: Vec::with_capacity(1),
            sessions: Arc::new(Default::default()),
            local_ipv4: *PROXY.ip(),
            local_ipv6: Ipv6Addr::from_bits(0),
        };

        let mut client_packet = unsafe { umem.alloc().unwrap() };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv4(CLIENT.ip().octets(), PROXY.ip().octets(), 64)
            .udp(CLIENT.port(), PROXY.port())
            .write(&mut client_packet, &data)
            .unwrap();

        rx_slab.push_front(client_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        let server_packet = tx_slab.pop_back().unwrap();

        let udp = xdp::packet::net_types::UdpPacket::parse_packet(&server_packet)
            .unwrap()
            .unwrap();
        let pdata = server_packet[udp.data_offset..udp.data_offset + udp.data_length].to_vec();
        assert_eq!(&pdata[..2], &data[..2]);
        assert_eq!(&pdata[2..], &concat_data,);

        umem.free_packet(server_packet);
        let mut server_packet = unsafe { umem.alloc().unwrap() };
        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv4(SERVER.ip().octets(), PROXY.ip().octets(), 64)
            .udp(SERVER.port(), udp.src_port.host())
            .write(&mut server_packet, &pdata)
            .unwrap();

        rx_slab.push_front(server_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);
        let server_packet = tx_slab.pop_back().unwrap();

        let udp = xdp::packet::net_types::UdpPacket::parse_packet(&server_packet)
            .unwrap()
            .unwrap();
        let pdata = &server_packet[udp.data_offset..udp.data_offset + udp.data_length];
        assert_eq!(&pdata[..concat_data.len()], &concat_data,);
        assert_eq!(&pdata[concat_data.len()..concat_data.len() + 2], &data[..2]);
        assert_eq!(&pdata[concat_data.len() + 2..], &concat_data,);
    }
}

/// Ensures that client packets can get routed to multiple servers
#[tokio::test]
async fn multiple_servers() {
    const PROXY: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(2, 2, 2, 2, 2, 2, 2, 2), 7777, 0, 0);
    const CLIENT: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(5, 5, 5, 5, 5, 5, 5, 5), 8888, 0, 0);

    let mut servers: Vec<_> = (1..20)
        .map(|i| SocketAddrV6::new(Ipv6Addr::new(i, i, i, i, i, i, i, i), 1000 + i, 0, 0))
        .collect();

    let config = quilkin::Config::default_non_agent();
    config.filters.store(Arc::new(
        filters::FilterChain::try_create([
            filters::Capture::as_filter_config(filters::capture::Config {
                metadata_key: filters::capture::CAPTURED_BYTES.into(),
                strategy: filters::capture::Strategy::Prefix(filters::capture::Prefix {
                    size: 1,
                    remove: false,
                }),
            })
            .unwrap(),
            filters::TokenRouter::as_filter_config(None).unwrap(),
        ])
        .unwrap(),
    ));
    let tok = [0xf1u8];
    config.clusters.modify(|clusters| {
        clusters.insert(
            None,
            endpoints(
                servers
                    .iter()
                    .map(|a| (SocketAddr::from(*a), &tok[..]))
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        )
    });

    let mut state = process::State {
        external_port: PROXY.port().into(),
        config: Arc::new(config),
        destinations: Vec::with_capacity(1),
        sessions: Arc::new(Default::default()),
        local_ipv4: Ipv4Addr::from_bits(0),
        local_ipv6: *PROXY.ip(),
    };

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 20,
            frame_count: 20,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    let mut tx_slab = xdp::HeapSlab::with_capacity(20);

    let mut client_packet = unsafe { umem.alloc().unwrap() };

    etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
        .ipv6(CLIENT.ip().octets(), PROXY.ip().octets(), 64)
        .udp(CLIENT.port(), PROXY.port())
        .write(&mut client_packet, &tok)
        .unwrap();

    rx_slab.push_front(client_packet);
    process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

    while let Some(sp) = tx_slab.pop_front() {
        let udp = xdp::packet::net_types::UdpPacket::parse_packet(&sp)
            .unwrap()
            .unwrap();

        let std::net::IpAddr::V6(dip) = udp.ips.destination() else {
            unreachable!("expected ipv6 adddress");
        };

        servers.remove(servers.iter().position(|s| s.ip() == &dip).unwrap());
    }

    assert!(servers.is_empty());
}

/// Ensures that surpassing the session limits doesn't completely break
#[tokio::test]
async fn many_sessions() {
    use xdp::packet::net_types as nt;

    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1111);
    const PROXY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 7777);

    let config = quilkin::Config::default_non_agent();
    config.filters.store(Arc::new(
        filters::FilterChain::try_create([
            filters::Capture::as_filter_config(filters::capture::Config {
                metadata_key: filters::capture::CAPTURED_BYTES.into(),
                strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                    size: 1,
                    remove: false,
                }),
            })
            .unwrap(),
            filters::TokenRouter::as_filter_config(None).unwrap(),
        ])
        .unwrap(),
    ));
    config.clusters.modify(|clusters| {
        clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf0])]));
    });

    let mut state = process::State {
        external_port: PROXY.port().into(),
        config: Arc::new(config),
        destinations: Vec::with_capacity(1),
        sessions: Arc::new(Default::default()),
        local_ipv4: *PROXY.ip(),
        local_ipv6: Ipv6Addr::from_bits(0),
    };

    let data = [0xf0u8; 11];

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 0,
            frame_count: 1,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    fn swap(packet: &mut xdp::Packet) {
        let udp = nt::UdpPacket::parse_packet(packet).unwrap().unwrap();

        let new = nt::UdpPacket {
            src_mac: udp.dst_mac,
            src_port: udp.dst_port,
            dst_mac: udp.src_mac,
            dst_port: udp.src_port,
            ips: match udp.ips {
                nt::IpAddresses::V4 {
                    source,
                    destination,
                } => nt::IpAddresses::V4 {
                    source: destination,
                    destination: source,
                },
                _ => unreachable!(),
            },
            data_offset: udp.data_offset,
            data_length: udp.data_length,
            hop: udp.hop - 1,
            checksum: 0.into(),
        };

        new.set_packet_headers(packet).unwrap();
        packet.calc_udp_checksum().unwrap();
    }

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    let mut tx_slab = xdp::HeapSlab::with_capacity(1);
    for i in 1..10000u32 {
        let mut client_packet = unsafe { umem.alloc().unwrap() };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv4(i.to_ne_bytes(), PROXY.ip().octets(), 64)
            .udp(i as u16, PROXY.port())
            .write(&mut client_packet, &data)
            .unwrap();

        rx_slab.push_front(client_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        let mut server_packet = tx_slab.pop_back().unwrap();

        swap(&mut server_packet);

        rx_slab.push_front(server_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        let client_packet = tx_slab.pop_back().unwrap();

        let udp = nt::UdpPacket::parse_packet(&client_packet)
            .unwrap()
            .unwrap();

        assert_eq!(
            &client_packet[udp.data_offset..udp.data_offset + udp.data_length],
            &data
        );
        assert_eq!(udp.dst_mac, nt::MacAddress([3, 3, 3, 3, 3, 3]));
        assert_eq!(udp.dst_port, (i as u16).into());
        assert_eq!(udp.src_mac, nt::MacAddress([4, 4, 4, 4, 4, 4]));
        assert_eq!(udp.src_port.host(), PROXY.port());
        assert_eq!(
            udp.ips,
            nt::IpAddresses::V4 {
                source: *PROXY.ip(),
                destination: Ipv4Addr::from_bits(i.to_be())
            }
        );

        umem.free_packet(client_packet);
    }
}

/// Ensures that we free packets back to the umem when we drop packets instead of forward them
#[tokio::test]
async fn frees_dropped_packets() {
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1111);
    const PROXY4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 7777);
    const PROXY6: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(2, 2, 2, 2, 2, 2, 2, 2), 7777, 0, 0);
    const CLIENT: SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 9999, 0, 0);

    let config = quilkin::Config::default_non_agent();
    config.filters.store(Arc::new(
        filters::FilterChain::try_create([
            filters::Capture::as_filter_config(filters::capture::Config {
                metadata_key: filters::capture::CAPTURED_BYTES.into(),
                strategy: filters::capture::Strategy::Suffix(filters::capture::Suffix {
                    size: 1,
                    remove: false,
                }),
            })
            .unwrap(),
            filters::TokenRouter::as_filter_config(None).unwrap(),
        ])
        .unwrap(),
    ));
    config.clusters.modify(|clusters| {
        clusters.insert(None, endpoints(&[(SERVER.into(), &[0xf0])]));
    });

    let mut state = process::State {
        external_port: PROXY4.port().into(),
        config: Arc::new(config),
        destinations: Vec::with_capacity(1),
        sessions: Arc::new(Default::default()),
        local_ipv4: *PROXY4.ip(),
        local_ipv6: *PROXY6.ip(),
    };

    let data = [0xf0u8; 11];

    let mut umem = xdp::Umem::map(
        xdp::umem::UmemCfgBuilder {
            frame_size: xdp::umem::FrameSize::TwoK,
            head_room: 0,
            frame_count: 1,
            tx_metadata: false,
        }
        .build()
        .unwrap(),
    )
    .unwrap();

    let mut rx_slab = xdp::HeapSlab::with_capacity(1);
    let mut tx_slab = xdp::HeapSlab::with_capacity(1);

    // sanity check the umem won't allow more than 1 packet at a time
    unsafe {
        let first = umem.alloc().unwrap();
        assert!(umem.alloc().is_none());
        umem.free_packet(first);
    };

    // Client packet that doesn't have a token
    {
        let mut client_packet = unsafe { umem.alloc().unwrap() };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv6(CLIENT.ip().octets(), PROXY6.ip().octets(), 64)
            .udp(CLIENT.port(), PROXY6.port())
            .write(&mut client_packet, &[1])
            .unwrap();

        rx_slab.push_front(client_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        assert!(tx_slab.is_empty());
    }

    // Valid client packet
    {
        // If this fails, the dropped packet wasn't freed
        let mut client_packet = unsafe { umem.alloc().expect("umem has no available packets") };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv6(CLIENT.ip().octets(), PROXY6.ip().octets(), 64)
            .udp(CLIENT.port(), PROXY6.port())
            .write(&mut client_packet, &data)
            .unwrap();

        rx_slab.push_front(client_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        let server_packet = tx_slab.pop_back().unwrap();
        umem.free_packet(server_packet);
    }

    // Server packet that doesn't have a session
    {
        let mut server_packet = unsafe { umem.alloc().expect("umem has no available packets") };

        etherparse::PacketBuilder::ethernet2([3, 3, 3, 3, 3, 3], [4, 4, 4, 4, 4, 4])
            .ipv4(SERVER.ip().octets(), PROXY4.ip().octets(), 64)
            .udp(CLIENT.port(), PROXY4.port())
            .write(&mut server_packet, &[1, 2, 3])
            .unwrap();

        rx_slab.push_front(server_packet);
        process::process_packets(&mut rx_slab, &mut umem, &mut tx_slab, &mut state);

        assert!(tx_slab.is_empty());
        unsafe { umem.alloc().expect("umem should have available memory") };
    }
}
