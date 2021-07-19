use std::net::SocketAddr;

/// UpstreamPacket represents a packet that needs to go somewhere
pub struct UpstreamPacket {
    pub dest: SocketAddr,
    pub contents: Vec<u8>,
}

impl UpstreamPacket {
    pub fn new(dest: SocketAddr, contents: Vec<u8>) -> UpstreamPacket {
        UpstreamPacket { dest, contents }
    }
}
