/*
 * Copyright 2020 Google LLC
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

use xdp::nic::NicIndex;

const PROGRAM: &[u8] = include_bytes!("../bin/packet-router.bin");

#[derive(thiserror::Error, Debug)]
pub enum BindError {
    #[error("'XSK' map not found in eBPF program")]
    MissingXskMap,
    #[error("failed to insert socket: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("failed to bind socket: {0}")]
    Socket(#[from] xdp::socket::SocketError),
    #[error("failed to determine queue count for NIC: {0}")]
    UnknownQueueCount(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("eBPF load error")]
    Ebpf(#[from] aya::EbpfError),
    #[error("failed to read ephemeral port range")]
    Io(#[from] std::io::Error),
    #[error("the default Linux ephemeral port range 32768..=60999 has been modified to {0}..={1}")]
    DefaultPortRangeModified(u16, u16),
}

pub struct EbpfProgram {
    bpf: aya::Ebpf,
}

impl EbpfProgram {
    /// Loads the XDP program.
    ///
    /// The external port, the port used by clients, must be passed in due to
    /// how globals work in eBPF.
    pub fn load(external_port: u16) -> Result<Self, LoadError> {
        let mut loader = aya::EbpfLoader::new();
        let port = external_port.to_be();
        loader.set_global("EXTERNAL_PORT_NO", &port, true);

        // We exploit the fact that Linux by default does not assign ephemeral
        // ports in the full range allowed by IANA, but we want to sanity check
        // it here, as otherwise something else could have been assigned an
        // ephemeral port that we think we can use, which would lead to both
        // quilkin and whatever program was assigned that port misbehaving
        let port_range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")?;
        let (start, end) =
            port_range
                .split_once(char::is_whitespace)
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected 2 u16 integers",
                ))?;
        let start: u16 = start.parse().map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse range start '{start}'"),
            )
        })?;
        let end: u16 = end.parse().map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse range end '{end}'"),
            )
        })?;

        if end > 60999 {
            return Err(LoadError::DefaultPortRangeModified(start, end));
        }

        Ok(Self {
            bpf: loader.load(PROGRAM)?,
        })
    }

    /// Gets the information for the default NIC
    pub fn get_default_nic() -> std::io::Result<Option<NicIndex>> {
        let table = std::fs::read_to_string("/proc/net/route")?;

        // In most cases there will probably only be one NIC that talks to
        // the rest of the network, but just in case, fail if there is
        // more than one, so the user is forced to specify. We _could_ go
        // further and use netlink to get the route for a global IP eg. 8.8.8.8,
        // but the rtnetlink crate is...pretty bad to work with
        let mut def_iface = None;

        // skip column headers
        for line in table.lines().skip(1) {
            let mut iter = line.split(char::is_whitespace).filter_map(|s| {
                let s = s.trim();
                (!s.is_empty()).then_some(s)
            });

            let Some(name) = iter.next() else {
                continue;
            };
            let Some(flags) = iter.nth(2).and_then(|f| u16::from_str_radix(f, 16).ok()) else {
                continue;
            };

            if flags & (libc::RTF_UP | libc::RTF_GATEWAY) != libc::RTF_UP | libc::RTF_GATEWAY {
                continue;
            }

            let Some(iface) = NicIndex::lookup_by_name(name)? else {
                continue;
            };

            if let Some(def) = def_iface {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("unable to determine default interface, found {def:?} and {iface:?}"),
                ));
            }

            def_iface = Some(iface);
        }

        Ok(def_iface)
    }

    /// Gets the information of the NIC with the specified name
    #[inline]
    pub fn get_nic(name: &str) -> std::io::Result<Option<NicIndex>> {
        NicIndex::lookup_by_name(name)
    }

    /// Binds the specified sockets and inserts them into the eBPF map
    pub fn bind_sockets(
        &mut self,
        nic: NicIndex,
        sb: Vec<(xdp::socket::XdpSocketBuilder, xdp::socket::BindFlags)>,
    ) -> Result<Vec<xdp::socket::XdpSocket>, BindError> {
        use std::os::fd::AsRawFd as _;
        {
            let q_count = nic.queue_count().map_err(BindError::UnknownQueueCount)?.1;
            assert_eq!(sb.len() as u32, q_count, "shared Umem is not supported at the moment, we require there is an AF_XDP socket per NIC queue");
        }

        let mut xsk_map = aya::maps::XskMap::try_from(
            self.bpf.map_mut("XSK").expect("failed to retrieve XSK map"),
        )?;

        let mut sockets = Vec::with_capacity(sb.len());
        for (i, (sb, bf)) in sb.into_iter().enumerate() {
            xsk_map.set(i as _, sb.as_raw_fd(), 0)?;
            sockets.push(sb.bind(nic, i as _, bf)?);
        }

        Ok(sockets)
    }

    pub fn attach(
        &mut self,
        nic: NicIndex,
        flags: aya::programs::XdpFlags,
    ) -> Result<aya::programs::xdp::XdpLinkId, aya::programs::ProgramError> {
        if let Err(error) = aya_log::EbpfLogger::init(&mut self.bpf) {
            tracing::warn!(%error, "failed to initialize eBPF logging");
        }

        // We use this entrypoint for now, but in the future we could also use
        // a round robin mode when the xdp lib supports shared Umem
        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut("all_queues")
            .expect("failed to locate 'all_queues' program")
            .try_into()
            .expect("'all_queues' is not an xdp program");
        program.load()?;

        program.attach_to_if_index(nic.into(), flags)
    }
}
