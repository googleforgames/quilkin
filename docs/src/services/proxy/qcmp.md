# Quilkin Control Message Protocol (QCMP)

| services | ports | Protocol |
|----------|-------|-----------|
| QCMP | 7600 | UDP (IPv4 OR IPv6) |

In addition to the TCP based administration API, Quilkin provides a meta API
over UDP. The purpose of this API is to provide meta operations that can be
used by untrusted clients. Currently the API is focuses on providing pings for
latency measurement but that may change overtime as new features are added.

## Protocol Data Unit
The following is a [Kaitai Struct](https://kaitai.io/) configuration of the protocol data unit
accepted by Quilkin proxies.

```yaml
meta:
  id: quilkin_packet
  endian: be
seq:
  - id: magic_header
    contents: "QLKN"
  - id: protocol_version
    type: u1
  - id: packet_type
    type: u1
  - id: packet_length
    type: u2
  - id: packet
    size: packet_length
    type:
      switch-on: packet_type
      cases:
        0: ping_packet
        1: ping_reply_packet

types:
  ping_packet:
    doc: |
        Sent by a client to a proxy containing the time when the client sent the
        packet along with a unique nonce. The timestamp should be a UTC unix
        timestamp in **nanoseconds**.
    seq:
      - id: nonce
        type: u1
      - id: client_sent_timestamp
        type: u8

  ping_reply_packet:
    doc: |
        A reply from a proxy containing the ping's nonce, the client sent time,
        the server's receive time, and the server's sent time. The timestamps
        should be UTC unix timestamps in **nanoseconds**.
    seq:
      - id: nonce
        type: u1
      - id: client_sent_timestamp
        type: u8
      - id: server_receive_timestamp
        type: u8
      - id: server_sent_timestamp
        type: u8
```
