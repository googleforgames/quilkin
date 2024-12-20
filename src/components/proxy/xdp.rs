use quilkin_xdp::xdp::{
    self,
    nic::{NicIndex, NicName},
};
mod process;

pub enum NicConfig<'n> {
    /// Specifies a NIC by name, setup will fail if a NIC with that name doesn't exist
    Name(&'n str),
    /// Specifies a NIC by index, setup will fail if the index isn't valid
    Index(u32),
    /// The NIC will be determined from the set of available NICs, setup will fail
    /// if more than one NIC is found that could be used for handling traffic
    Default,
}

/// User supplied configuration
pub struct XdpConfig<'n> {
    /// The NIC to attach to
    pub nic: NicConfig<'n>,
    /// The external port that downstream clients use to communicate with Quilkin
    pub external_port: u16,
    /// The maximum amount of memory, in bytes, that the memory mappings used for
    /// packet buffers will be allowed to take.
    ///
    /// Quilkin currently uses one [`UMEM`](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#umem)
    /// for each socket, and there is one socket per NIC queue. Setup will fail
    /// if this option is set at a too low value.
    ///
    /// By default we use 4MiB per queue, eg. 128 MiB on a 32 queue NIC
    ///
    /// Note that there are other ring buffers allocated that aren't counted
    /// under this allocation, but they are much smaller
    pub maximum_packet_memory: Option<u64>,
    /// Requires that the chosen NIC supports [`XDP_ZEROCOPY`](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-copy-and-xdp-zerocopy-bind-flags)
    ///
    /// If this is false, zero copy will be used if the NIC supports it, but will
    /// fallback to copy mode if not, which will mean lower performance
    pub require_zero_copy: bool,
    /// Requires that the chosen NIC supports [`XDP_TXMD_FLAGS_TIMESTAMP`](https://docs.kernel.org/6.8/networking/xsk-tx-metadata.html)
    /// which allows [internet checksum]() calculation to be offloaded to the NIC
    pub require_tx_checksum: bool,
}

impl Default for XdpConfig<'_> {
    fn default() -> Self {
        Self {
            nic: NicConfig::Default,
            external_port: 7777,
            maximum_packet_memory: None,
            require_zero_copy: false,
            require_tx_checksum: false,
        }
    }
}

pub struct XdpWorkers {
    ebpf_prog: quilkin_xdp::EbpfProgram,
    workers: Vec<quilkin_xdp::XdpWorker>,
    nic: NicIndex,
    external_port: NetworkU16,
}

#[derive(thiserror::Error, Debug)]
pub enum NicUnavailable {
    #[error("failed to query NIC: {0}")]
    Query(#[source] std::io::Error),
    #[error("no NICs available that could be considered a default")]
    NoAvailableDefault,
    #[error("no NIC named '{0}'")]
    UnknownName(String),
    #[error("no NIC with index '{0}'")]
    UnknownIndex(u32),
}

#[derive(thiserror::Error, Debug)]
pub enum XdpSetupError {
    #[error("NIC is unavailable: {0}")]
    NicUnavailable(#[from] NicUnavailable),
    #[error("failed to query device capabilities for {0}: {1}")]
    NicQuery(NicName, #[source] std::io::Error),
    #[error("`XDP_ZEROCOPY` is unavailable for {0}")]
    ZeroCopyUnavailable(NicName),
    #[error("`XDP_TXMD_FLAGS_TIMESTAMP` is unavailable for {0}")]
    TxChecksumUnavailable(NicName),
    #[error("the requested maximum packet memory {max:.2}{xunit} must be at least {min:.2}{nunit} as {nic} has a queue count of {queue_count}")]
    MinimumMemoryRequirementsExceeded {
        max: f64,
        xunit: &'static str,
        min: f64,
        nunit: &'static str,
        nic: NicName,
        queue_count: u32,
    },
    #[error("XDP error: {0}")]
    Xdp(#[from] xdp::error::Error),
}

/// Attempts to setup XDP by querying NIC support and allocating ring buffers
/// based on user configuration, failing if requirements cannot be met
///
/// This function currently only supports one mode of operation, which is that
/// a socket is bound to every available queue on the NIC, and when [`spawn_xdp_io`]
/// is invoked, each socket is processed in its own thread
///
/// Binding to fewer queues is possible in the future but requires additional
/// work in the `xdp` crate
pub fn setup_xdp_io(config: XdpConfig<'_>) -> Result<XdpWorkers, XdpSetupError> {
    let nic_index = match config.nic {
        NicConfig::Default => quilkin_xdp::get_default_nic()
            .map_err(NicUnavailable::Query)?
            .ok_or(NicUnavailable::NoAvailableDefault)?,
        NicConfig::Name(name) => xdp::nic::NicIndex::lookup_by_name(name)
            .map_err(NicUnavailable::Query)?
            .ok_or_else(|| NicUnavailable::UnknownName(name.to_owned()))?,
        NicConfig::Index(index) => xdp::nic::NicIndex::new(index),
    };

    let name = nic_index
        .name()
        .map_err(|_err| NicUnavailable::UnknownIndex(nic_index.index()))?;

    tracing::info!("using NIC {name}({})", nic_index.index());

    let device_caps = nic_index
        .query_capabilities()
        .map_err(|err| XdpSetupError::NicQuery(name, err))?;

    if config.require_zero_copy
        && matches!(device_caps.zero_copy, xdp::nic::XdpZeroCopy::Unavailable)
    {
        return Err(XdpSetupError::ZeroCopyUnavailable(name));
    }

    if config.require_tx_checksum && !device_caps.tx_metadata.checksum() {
        return Err(XdpSetupError::TxChecksumUnavailable(name));
    }

    // Bit arbitrary, but set the floor at 128 packets per umem
    const MINIMUM_UMEM_COUNT: u64 = 128;
    // We don't support unaligned chunks, so this size can only be 2k or 4k,
    // and we only need 2k since we only care about non-fragmented UDP packets
    const PACKET_SIZE: u64 = 2 * 1024;

    let packet_count = if let Some(max) = config.maximum_packet_memory {
        let bytes_per_socket = max / device_caps.queue_count as u64;
        let packet_count = (bytes_per_socket / PACKET_SIZE).next_power_of_two();
        if MINIMUM_UMEM_COUNT > packet_count {
            fn byte_units(b: u64) -> (f64, &'static str) {
                let mut units = b as f64;
                let mut unit = 0;
                const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];

                while units > 1024.0 {
                    units /= 1024.0;
                    unit += 1;
                }

                (units, UNITS[unit])
            }

            let (max, xunit) = byte_units(max);
            let (min, nunit) =
                byte_units(MINIMUM_UMEM_COUNT * PACKET_SIZE * device_caps.queue_count as _);

            return Err(XdpSetupError::MinimumMemoryRequirementsExceeded {
                max,
                xunit,
                min,
                nunit,
                nic: name,
                queue_count: device_caps.queue_count,
            });
        }

        packet_count as u32
    } else {
        2 * 1024
    };

    let mut ebpf_prog = quilkin_xdp::EbpfProgram::load(config.external_port)?;

    let umem_cfg = xdp::umem::UmemCfgBuilder {
        frame_size: xdp::umem::FrameSize::TwoK,
        // Provide enough headroom so that we can convert an ipv4 header to ipv6
        // header without needing to copy any bytes. note this doesn't take into
        // account if a filter adds or removes bytes from the beginning of the
        // data payload
        head_room: (xdp::frame::net_types::Ipv6Hdr::LEN - xdp::frame::net_types::Ipv4Hdr::LEN)
            as u32,
        frame_count: packet_count,
        // TODO: This should be done in the type system so we can avoid logic
        // that doesn't change during the course of operation, but for now just
        // do it at runtime
        tx_metadata: device_caps.tx_metadata.checksum(),
    }
    .build()?;

    let ring_cfg = xdp::RingConfigBuilder::default().build()?;
    let workers = ebpf_prog.create_and_bind_sockets(nic_index, umem_cfg, &device_caps, ring_cfg)?;

    Ok(XdpWorkers {
        ebpf_prog,
        workers,
        nic: nic_index,
        external_port: NetworkU16(config.external_port.to_be()),
    })
}

/// We need the u64 for the call to pthread_cancel, but unfortunately `std::thread::ThreadId`
/// doesn't have that on [stable](https://doc.rust-lang.org/std/thread/struct.ThreadId.html#method.as_u64)
type ThreadId = u64;

pub struct XdpLoop {
    threads: Vec<(ThreadId, std::thread::JoinHandle<()>)>,
    ebpf_prog: quilkin_xdp::EbpfProgram,
    xdp_link: quilkin_xdp::aya::programs::xdp::XdpLinkId,
}

impl XdpLoop {
    /// Detaches the eBPF program from the attacked NIC and cancels all I/O
    /// threads, waiting for them to exit
    pub async fn shutdown(self) {
        tokio::task::spawn_blocking(|| {
            if let Err(error) = self.ebpf_prog.detach(self.xdp_link) {
                tracing::error!(%error, "failed to detach eBPF program");
            }

            for (tid, _) in &mut self.threads {
                // This will only fail if the thread doesn't exist, so we just
                // make it so that we skip joining if that happens
                // SAFETY: this should be safe to call even if the thread doesn't
                // exist
                let err = unsafe { libc::pthread_cancel(*tid) };
                match err {
                    0 => {}
                    libc::ESCRH => {
                        tracing::warn!(tid, "thread does not exist");
                        *tid = 0;
                    }
                    other => {
                        tracing::warn!(
                            tid,
                            err,
                            "thread could not be cancelled, but the error seems to be incorrect"
                        );
                        *tid = 0;
                    }
                }
            }

            for (tid, jh) in self.threads {
                if tid == 0 {
                    continue;
                }

                if let Err(error) = jh.join() {
                    if let Some(error) = error.downcast_ref::<&'static str>() {
                        tracing::error!(tid, error, "XDP I/O thread enountered error");
                    } else if let Some(error) = error.downcast_ref::<String>() {
                        tracing::error!(tid, error, "XDP I/O thread enountered error");
                    } else {
                        tracing::error!(tid, ?error, "XDP I/O thread enountered error");
                    };
                }
            }
        })
        .await;
    }
}

pub fn spawn(
    workers: XdpWorkers,
    config: std::sync::Arc<crate::Config>,
) -> Result<XdpLoop, XdpSpawnError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);

    let external_port = workers.external_port;
    let mut threads = Vec::with_capacity(workers.workers.len());
    for (i, mut worker) in workers.workers.into_iter().enumerate() {
        let tx = tx.clone();
        let cfg = config.clone();

        let jh = std::thread::Builder::new()
            .name(format!("xdp-io-{i}"))
            .spawn(move || {
                // Enqueue buffers to the fill ring to ensure that we don't miss any packets
                // SAFETY: we keep the umem alive for as long as the socket is alive
                unsafe { worker.fill.enqueue(&mut worker.umem, BATCH_SIZE * 2) };

                // SAFETY: there are no invariants to uphold
                tx.send(unsafe { libc::pthread_self() }).unwrap();
                io_loop(worker, external_port, cfg)
            })?;

        let tid = rx.recv().unwrap();
        threads.push((tid, jh));
    }

    // Now that all the io loops are running, attach the eBPF program to route
    // packets to the bound sockets
    let mut ebpf_prog = workers.ebpf_prog;
    let xdp_link =
        ebpf_prog.attach(workers.nic, quilkin_xdp::aya::programs::XdpFlags::default())?;

    Ok(XdpLoop {
        threads,
        ebpf_prog,
        xdp_link,
    })
}

const BATCH_SIZE: usize = 64;
use xdp::{
    frame::net_types::{NetworkU16, UdpPacket},
    Frame,
};

fn io_loop(
    worker: quilkin_xdp::XdpWorker,
    external_port: NetworkU16,
    cfg: std::sync::Arc<crate::Config>,
) {
    let quilkin_xdp::XdpWorker {
        mut umem,
        mut socket,
        mut fill,
        mut rx,
        mut tx,
        mut completion,
    } = worker;

    const POLL_TIMEOUT: xdp::socket::PollTimeout =
        xdp::socket::PollTimeout::new(Some(std::time::Duration::from_millis(100)));

    // SAFETY: the cases of unsafe in this code block all concern the relationship
    // between frames and the Umem, the frames cannot outlive the Umem which is
    // the owner of the actual memory map
    unsafe {
        let mut slab = xdp::Slab::with_capacity(BATCH_SIZE);
        let mut pending_sends = 0;

        loop {
            // Wait for packets to be received/sent, note that
            // [poll](https://www.man7.org/linux/man-pages/man2/poll.2.html) also acts
            // as a [cancellation point](https://www.man7.org/linux/man-pages/man7/pthreads.7.html),
            // so shutdown will cause the thread to exit here
            let Ok(true) = socket.poll(POLL_TIMEOUT) else {
                continue;
            };

            let recvd = rx.recv(&umem, &mut slab);

            let enqueued_sends = if recvd > 0 {
                // Ensure the fill ring doesn't get starved, dropping packets
                fill.enqueue(&mut umem, BATCH_SIZE * 2 - recvd);

                process::process_packets(&mut slab, &mut umem, &mut tx, external_port, &cfg)
            } else {
                0
            };

            // Return frames that have completed sending
            pending_sends -= completion.dequeue(&mut umem, pending_sends);
            pending_sends += enqueued_sends;
        }
    }
}
