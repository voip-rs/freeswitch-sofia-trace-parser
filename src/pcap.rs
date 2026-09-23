//! Synthesize libpcap-classic packets from parsed FreeSWITCH SIP frames/messages.
//!
//! The dump format records only the remote endpoint, direction, transport, and
//! decrypted SIP payload. This module fills in synthetic local addresses,
//! TCP sequence numbers, IP headers, and pcap framing so the result loads in
//! Wireshark/`tshark` with SIP dissection working out of the box.
//!
//! Caller supplies the policy (local addresses, date anchor for time-only
//! timestamps); the library makes no assumptions.
//!
//! Three entry points are offered, matching the three iterator levels:
//!
//! - [`PcapWriter::write_frame`] for [`Frame`] (Level 1, raw frames)
//! - [`PcapWriter::write_message`] for [`SipMessage`] (Level 2, reassembled)
//! - [`PcapWriter::write_parsed`] for [`ParsedSipMessage`] (Level 3, parsed)
//!
//! All three share the same IP/TCP/UDP synthesis and TCP sequence tracking.
//!
//! # Quick start
//!
//! ```no_run
//! use std::fs::File;
//! use freeswitch_sofia_trace_parser::{MessageIterator, PcapConfig, PcapWriter};
//!
//! let dump = File::open("profile.dump").unwrap();
//! let pcap = File::create("trace.pcap").unwrap();
//! let mut w = PcapWriter::new(pcap, PcapConfig::default()).unwrap();
//! for result in MessageIterator::new(dump) {
//!     let msg = result.unwrap();
//!     w.write_message(&msg).unwrap();
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::types::{
    days_from_civil, Direction, Frame, FrameMeta, ParsedSipMessage, SipMessage, Timestamp,
    Transport,
};

const PCAP_MAGIC_USEC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;

const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;

const SLL_PKTTYPE_HOST: u16 = 0; // recv
const SLL_PKTTYPE_OUTGOING: u16 = 4; // sent
const SLL_ARPHRD_ETHER: u16 = 1;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
/// IANA RFC 3692-style experimentation/testing.
const IP_PROTO_TESTING: u8 = 253;

const TCP_FLAG_PSH_ACK: u16 = 0x018;

const SLL_HEADER_LEN: u16 = 16;
const IPV4_HEADER_LEN: u16 = 20;
const IPV6_HEADER_LEN: u16 = 40;
const UDP_HEADER_LEN: u16 = 8;
const TCP_HEADER_LEN: u16 = 20;

/// What protocol layer the synthesized packet stops at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapLayer {
    /// IP header + SIP payload as the IP payload (proto 253).
    /// Link type LINKTYPE_RAW.
    Network,
    /// IP header + UDP/TCP header + SIP payload.
    /// Link type LINKTYPE_LINUX_SLL — direction encoded in `pkttype`.
    Transport,
}

/// Caller-supplied policy for pcap synthesis.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PcapConfig {
    /// Local endpoint to use when the remote is IPv4.
    pub local_v4: SocketAddr,
    /// Local endpoint to use when the remote is IPv6.
    pub local_v6: SocketAddr,
    /// Anchor date for `Timestamp::TimeOnly` values. `None` → epoch.
    pub date_base: Option<(u16, u8, u8)>,
    /// Where to stop synthesis.
    pub layer: PcapLayer,
}

impl PcapConfig {
    /// Local endpoint for IPv4 remotes.
    pub fn with_local_v4(mut self, addr: SocketAddr) -> Self {
        self.local_v4 = addr;
        self
    }

    /// Local endpoint for IPv6 remotes.
    pub fn with_local_v6(mut self, addr: SocketAddr) -> Self {
        self.local_v6 = addr;
        self
    }

    /// Anchor date for `Timestamp::TimeOnly` values.
    pub fn with_date_base(mut self, date: (u16, u8, u8)) -> Self {
        self.date_base = Some(date);
        self
    }

    /// Where to stop synthesis.
    pub fn with_layer(mut self, layer: PcapLayer) -> Self {
        self.layer = layer;
        self
    }
}

impl Default for PcapConfig {
    fn default() -> Self {
        // RFC 5737 TEST-NET-1 / RFC 3849 documentation prefix.
        Self {
            local_v4: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 5060)),
            local_v6: SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 5060)),
            date_base: None,
            layer: PcapLayer::Transport,
        }
    }
}

/// Errors specific to pcap synthesis.
#[derive(Debug)]
#[non_exhaustive]
pub enum PcapError {
    Io(io::Error),
    InvalidAddress(String),
    /// Remote address family does not match configured local family.
    AddressFamilyMismatch,
    /// Payload longer than the IP family's length field can carry, or than the
    /// snaplen the file header advertises. Refused rather than truncated: a
    /// short length field reads as the dump's truth.
    PayloadTooLarge {
        /// Payload length in bytes.
        len: usize,
        /// Largest payload this packet shape carries.
        max: usize,
    },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "pcap io error: {e}"),
            PcapError::InvalidAddress(s) => write!(f, "invalid address: {s}"),
            PcapError::AddressFamilyMismatch => {
                f.write_str("address family mismatch between remote and configured local")
            }
            PcapError::PayloadTooLarge { len, max } => {
                write!(
                    f,
                    "payload of {len} bytes exceeds the {max} this packet carries"
                )
            }
        }
    }
}

impl std::error::Error for PcapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PcapError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

#[derive(Default)]
struct ConnectionState {
    /// Running SEQ for the FreeSWITCH→peer direction (Sent).
    sent_seq: u32,
    /// Running SEQ for the peer→FreeSWITCH direction (Recv).
    recv_seq: u32,
}

/// Streaming writer that emits libpcap-classic format on construction and one
/// synthetic packet per `write_frame` / `write_message` call.
pub struct PcapWriter<W: Write> {
    writer: W,
    config: PcapConfig,
    /// Keyed by peer endpoint, so both directions of one connection share
    /// the same sequence state.
    connections: HashMap<(Transport, SocketAddr), ConnectionState>,
}

impl<W: Write> PcapWriter<W> {
    /// Construct and write the libpcap global header.
    pub fn new(mut writer: W, config: PcapConfig) -> io::Result<Self> {
        let linktype = match config.layer {
            PcapLayer::Network => LINKTYPE_RAW,
            PcapLayer::Transport => LINKTYPE_LINUX_SLL,
        };
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&PCAP_MAGIC_USEC.to_le_bytes());
        hdr[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
        hdr[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
        // thiszone (i32) and sigfigs (u32) stay zero.
        hdr[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
        hdr[20..24].copy_from_slice(&linktype.to_le_bytes());
        writer.write_all(&hdr)?;
        Ok(Self {
            writer,
            config,
            connections: HashMap::new(),
        })
    }

    /// Emit one packet for a Level-1 frame.
    pub fn write_frame(&mut self, frame: &Frame) -> Result<(), PcapError> {
        self.emit(frame.meta(), &frame.content, None)
    }

    /// Emit one packet for a Level-2 reassembled message.
    pub fn write_message(&mut self, msg: &SipMessage) -> Result<(), PcapError> {
        self.emit(msg.meta(), &msg.content, None)
    }

    /// Emit one packet for a Level-3 parsed message. The wire-format payload
    /// is reconstructed via [`ParsedSipMessage::to_bytes`].
    pub fn write_parsed(&mut self, msg: &ParsedSipMessage) -> Result<(), PcapError> {
        self.write_parsed_with_local(msg, None)
    }

    /// Like [`write_parsed`](Self::write_parsed), but with an explicit local
    /// endpoint override for this packet only. When `local_override` is
    /// `Some`, it replaces [`PcapConfig::local_v4`] / [`PcapConfig::local_v6`]
    /// just for this packet (still validated for matching IP family). Useful
    /// for callers that derive the actual FreeSWITCH local address per
    /// connection from SIP `Via:` headers.
    pub fn write_parsed_with_local(
        &mut self,
        msg: &ParsedSipMessage,
        local_override: Option<SocketAddr>,
    ) -> Result<(), PcapError> {
        self.emit(msg.meta(), &msg.to_bytes(), local_override)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Consume the writer and return the inner `W`.
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn emit(
        &mut self,
        meta: FrameMeta<'_>,
        payload: &[u8],
        local_override: Option<SocketAddr>,
    ) -> Result<(), PcapError> {
        let remote = meta
            .socket_addr()
            .ok_or_else(|| PcapError::InvalidAddress(meta.address.to_string()))?;
        let local = match local_override {
            Some(addr) => addr,
            None => match remote {
                SocketAddr::V4(_) => self.config.local_v4,
                SocketAddr::V6(_) => self.config.local_v6,
            },
        };
        let (src, dst) = match meta.direction {
            Direction::Recv => (remote, local),
            Direction::Sent => (local, remote),
        };
        let ips = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => IpPair::V4(s, d),
            (IpAddr::V6(s), IpAddr::V6(d)) => IpPair::V6(s, d),
            _ => return Err(PcapError::AddressFamilyMismatch),
        };
        let (ts_sec, ts_usec) = timestamp_to_unix(meta.timestamp, self.config.date_base);

        let max = payload_limit(self.config.layer, ips, meta.transport);
        let payload_len = match u16::try_from(payload.len()) {
            Ok(len) if payload.len() <= max => len,
            _ => {
                return Err(PcapError::PayloadTooLarge {
                    len: payload.len(),
                    max,
                })
            }
        };

        let packet = match self.config.layer {
            PcapLayer::Network => build_layer3(ips, payload, payload_len),
            PcapLayer::Transport => self.build_layer4(meta, ips, src, dst, payload, payload_len),
        };

        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        rec[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        let len = packet.len() as u32;
        rec[8..12].copy_from_slice(&len.to_le_bytes());
        rec[12..16].copy_from_slice(&len.to_le_bytes());
        self.writer.write_all(&rec)?;
        self.writer.write_all(&packet)?;
        Ok(())
    }

    fn build_layer4(
        &mut self,
        meta: FrameMeta<'_>,
        ips: IpPair,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        payload_len: u16,
    ) -> Vec<u8> {
        let direction = meta.direction;
        let mut out = sll_header(direction, ips.ethertype());

        let (transport_proto, segment_len, transport_segment) = match meta.transport {
            Transport::Udp => {
                let segment_len = payload_len.saturating_add(UDP_HEADER_LEN);
                (
                    IP_PROTO_UDP,
                    segment_len,
                    build_udp(ips, src.port(), dst.port(), payload, segment_len),
                )
            }
            Transport::Tcp | Transport::Tls | Transport::Wss => {
                let peer = match direction {
                    Direction::Sent => dst,
                    Direction::Recv => src,
                };
                let conn = self.connections.entry((meta.transport, peer)).or_default();
                let (seq, ack) = match direction {
                    Direction::Sent => (conn.sent_seq, conn.recv_seq),
                    Direction::Recv => (conn.recv_seq, conn.sent_seq),
                };
                let segment_len = payload_len.saturating_add(TCP_HEADER_LEN);
                let seg = build_tcp(ips, src.port(), dst.port(), seq, ack, payload, segment_len);
                let advance = payload_len as u32;
                match direction {
                    Direction::Sent => conn.sent_seq = conn.sent_seq.wrapping_add(advance),
                    Direction::Recv => conn.recv_seq = conn.recv_seq.wrapping_add(advance),
                }
                (IP_PROTO_TCP, segment_len, seg)
            }
        };

        let ip = build_ip(ips, transport_proto, segment_len);
        out.extend_from_slice(&ip);
        out.extend_from_slice(&transport_segment);
        out
    }
}

/// Largest payload a packet of this shape carries: what the IP family's length
/// field holds after its headers, bounded by the advertised snaplen.
fn payload_limit(layer: PcapLayer, ips: IpPair, transport: Transport) -> usize {
    let ip_header = match ips {
        IpPair::V4(..) => IPV4_HEADER_LEN,
        IpPair::V6(..) => IPV6_HEADER_LEN,
    };
    let (link_header, transport_header) = match layer {
        PcapLayer::Network => (0, 0),
        PcapLayer::Transport => match transport {
            Transport::Udp => (SLL_HEADER_LEN, UDP_HEADER_LEN),
            _ => (SLL_HEADER_LEN, TCP_HEADER_LEN),
        },
    };
    // IPv4 counts its own header in the field; IPv6 counts only what follows.
    let ip_field = match ips {
        IpPair::V4(..) => u16::MAX - ip_header,
        IpPair::V6(..) => u16::MAX,
    };
    let snaplen = PCAP_SNAPLEN.saturating_sub((link_header + ip_header + transport_header) as u32);
    (ip_field.saturating_sub(transport_header) as usize).min(snaplen as usize)
}

/// A source/destination pair of the same IP family, so every layer below
/// takes the validation done once in `emit` for granted.
#[derive(Debug, Clone, Copy)]
enum IpPair {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl IpPair {
    fn ethertype(&self) -> u16 {
        match self {
            IpPair::V4(..) => ETHERTYPE_IPV4,
            IpPair::V6(..) => ETHERTYPE_IPV6,
        }
    }
}

fn sll_header(direction: Direction, ethertype: u16) -> Vec<u8> {
    let mut h = vec![0u8; 16];
    let pkttype = match direction {
        Direction::Recv => SLL_PKTTYPE_HOST,
        Direction::Sent => SLL_PKTTYPE_OUTGOING,
    };
    h[0..2].copy_from_slice(&pkttype.to_be_bytes());
    h[2..4].copy_from_slice(&SLL_ARPHRD_ETHER.to_be_bytes());
    // addr_length and addr[8] stay zero — no MAC available.
    h[14..16].copy_from_slice(&ethertype.to_be_bytes());
    h
}

fn build_layer3(ips: IpPair, payload: &[u8], payload_len: u16) -> Vec<u8> {
    let ip = build_ip(ips, IP_PROTO_TESTING, payload_len);
    let mut out = Vec::with_capacity(ip.len() + payload.len());
    out.extend_from_slice(&ip);
    out.extend_from_slice(payload);
    out
}

fn build_ip(ips: IpPair, protocol: u8, payload_len: u16) -> Vec<u8> {
    match ips {
        IpPair::V4(s, d) => build_ipv4(s, d, protocol, payload_len),
        IpPair::V6(s, d) => build_ipv6(s, d, protocol, payload_len),
    }
}

fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN.saturating_add(payload_len);
    let mut h = vec![0u8; 20];
    h[0] = 0x45; // version=4, IHL=5
    h[1] = 0; // DSCP/ECN
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    // identification, flags, fragment offset stay zero.
    h[6] = 0x40; // Don't Fragment
    h[8] = 64; // TTL
    h[9] = protocol;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let csum = checksum_ones_complement(&h);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: u16) -> Vec<u8> {
    let mut h = vec![0u8; 40];
    // version=6, traffic class=0, flow label=0
    h[0] = 0x60;
    h[4..6].copy_from_slice(&payload_len.to_be_bytes());
    h[6] = next_header;
    h[7] = 64; // hop limit
    h[8..24].copy_from_slice(&src.octets());
    h[24..40].copy_from_slice(&dst.octets());
    h
}

fn build_udp(
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    segment_len: u16,
) -> Vec<u8> {
    let mut h = vec![0u8; segment_len as usize];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());
    h[4..6].copy_from_slice(&segment_len.to_be_bytes());
    // checksum at h[6..8] left zero for now
    h[8..].copy_from_slice(payload);
    let csum = transport_checksum(ips, IP_PROTO_UDP, &h, segment_len);
    // RFC 768: a transmitted zero checksum is replaced with all-ones.
    let csum = if csum == 0 { 0xffff } else { csum };
    h[6..8].copy_from_slice(&csum.to_be_bytes());
    h
}

fn build_tcp(
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
    segment_len: u16,
) -> Vec<u8> {
    let mut h = vec![0u8; segment_len as usize];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&ack.to_be_bytes());
    // data offset (5 << 12) | flags
    let off_flags: u16 = (5 << 12) | TCP_FLAG_PSH_ACK;
    h[12..14].copy_from_slice(&off_flags.to_be_bytes());
    h[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
                                                        // checksum at h[16..18] left zero for now
                                                        // urgent at h[18..20] left zero
    h[20..].copy_from_slice(payload);
    let csum = transport_checksum(ips, IP_PROTO_TCP, &h, segment_len);
    h[16..18].copy_from_slice(&csum.to_be_bytes());
    h
}

fn checksum_ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum(ips: IpPair, protocol: u8, segment: &[u8], segment_len: u16) -> u16 {
    let mut buf = Vec::with_capacity(40 + segment.len());
    match ips {
        IpPair::V4(s, d) => {
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.push(0);
            buf.push(protocol);
            buf.extend_from_slice(&segment_len.to_be_bytes());
        }
        IpPair::V6(s, d) => {
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&(segment_len as u32).to_be_bytes());
            buf.extend_from_slice(&[0, 0, 0, protocol]);
        }
    }
    buf.extend_from_slice(segment);
    checksum_ones_complement(&buf)
}

fn timestamp_to_unix(ts: Timestamp, date_base: Option<(u16, u8, u8)>) -> (u32, u32) {
    let (y, mo, d, h, m, s, us) = match ts {
        Timestamp::DateTime {
            year,
            month,
            day,
            hour,
            min,
            sec,
            usec,
        } => (year, month, day, hour, min, sec, usec),
        Timestamp::TimeOnly {
            hour,
            min,
            sec,
            usec,
        } => {
            let (y, mo, d) = date_base.unwrap_or((1970, 1, 1));
            (y, mo, d, hour, min, sec, usec)
        }
    };
    let days = days_from_civil(y as i64, mo as u32, d as u32);
    let secs = days * 86400 + h as i64 * 3600 + m as i64 * 60 + s as i64;
    let secs = if secs < 0 { 0 } else { secs as u32 };
    (secs, us)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(direction: Direction, transport: Transport, addr: &str, payload: &[u8]) -> Frame {
        Frame {
            direction,
            byte_count: payload.len(),
            transport,
            address: addr.to_string(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content: payload.to_vec(),
            offset: 0,
        }
    }

    fn writer_transport() -> PcapWriter<Vec<u8>> {
        PcapWriter::new(Vec::new(), PcapConfig::default()).unwrap()
    }

    fn writer_network() -> PcapWriter<Vec<u8>> {
        let cfg = PcapConfig {
            layer: PcapLayer::Network,
            ..PcapConfig::default()
        };
        PcapWriter::new(Vec::new(), cfg).unwrap()
    }

    #[test]
    fn pcap_global_header_transport() {
        let w = PcapWriter::new(Vec::new(), PcapConfig::default()).unwrap();
        let bytes = w.into_inner();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[0..4], &PCAP_MAGIC_USEC.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            LINKTYPE_LINUX_SLL
        );
    }

    #[test]
    fn pcap_global_header_network() {
        let w = writer_network();
        let bytes = w.into_inner();
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            LINKTYPE_RAW
        );
    }

    #[test]
    fn udp_ipv4_packet_layout() {
        let mut w = writer_transport();
        let f = frame(
            Direction::Recv,
            Transport::Udp,
            "10.0.0.1:5060",
            b"OPTIONS x",
        );
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        // Skip 24 (global) + 16 (record) = 40
        let pkt = &bytes[40..];
        // SLL: pkttype recv = 0
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), SLL_PKTTYPE_HOST);
        // ethertype IPv4
        assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), ETHERTYPE_IPV4);
        // IPv4 starts at offset 16
        let ip = &pkt[16..36];
        assert_eq!(ip[0], 0x45);
        assert_eq!(ip[9], IP_PROTO_UDP);
        // UDP starts at 36, src port = remote (5060)
        let udp = &pkt[36..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 5060);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 5060);
        // payload
        assert_eq!(&udp[8..], b"OPTIONS x");
    }

    #[test]
    fn udp_ipv6_packet_layout() {
        let mut w = writer_transport();
        let f = frame(Direction::Sent, Transport::Udp, "[2001:db8::2]:5060", b"OK");
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let pkt = &bytes[40..];
        assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), ETHERTYPE_IPV6);
        // IPv6 version nibble = 6
        assert_eq!(pkt[16] >> 4, 6);
        // next header = UDP
        assert_eq!(pkt[22], IP_PROTO_UDP);
    }

    #[test]
    fn tcp_seq_advances_per_direction() {
        let mut w = writer_transport();
        let s1 = frame(Direction::Sent, Transport::Tcp, "10.0.0.1:5060", b"AAAA"); // 4 bytes
        let s2 = frame(Direction::Sent, Transport::Tcp, "10.0.0.1:5060", b"BB"); // 2 bytes
        let r1 = frame(Direction::Recv, Transport::Tcp, "10.0.0.1:5060", b"ZZZ"); // 3 bytes
        w.write_frame(&s1).unwrap();
        w.write_frame(&s2).unwrap();
        w.write_frame(&r1).unwrap();
        let bytes = w.into_inner();
        // Each record: 16 record header + 16 SLL + 20 IPv4 + 20 TCP + payload
        let rec_size = |payload: usize| 16 + 16 + 20 + 20 + payload;
        let s1_off = 24; // after global
        let s2_off = s1_off + rec_size(4);
        let r1_off = s2_off + rec_size(2);

        let tcp_seq = |off: usize| {
            let tcp = &bytes[off + 16 + 16 + 20..];
            u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]])
        };
        let tcp_ack = |off: usize| {
            let tcp = &bytes[off + 16 + 16 + 20..];
            u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]])
        };

        assert_eq!(tcp_seq(s1_off), 0);
        assert_eq!(tcp_seq(s2_off), 4);
        assert_eq!(tcp_ack(s2_off), 0); // recv hasn't moved yet
        assert_eq!(tcp_seq(r1_off), 0);
        assert_eq!(tcp_ack(r1_off), 6); // sent advanced 4+2
    }

    #[test]
    fn tls_encoded_as_tcp() {
        let mut w = writer_transport();
        let f = frame(Direction::Sent, Transport::Tls, "10.0.0.1:5061", b"INVITE");
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let pkt = &bytes[40..];
        assert_eq!(pkt[16 + 9], IP_PROTO_TCP);
        let tcp = &pkt[16 + 20..];
        // payload follows the 20-byte TCP header
        assert_eq!(&tcp[20..], b"INVITE");
    }

    #[test]
    fn time_only_uses_date_base() {
        let cfg = PcapConfig {
            date_base: Some((2026, 4, 28)),
            ..PcapConfig::default()
        };
        let mut w = PcapWriter::new(Vec::new(), cfg).unwrap();
        let f = Frame {
            direction: Direction::Recv,
            byte_count: 1,
            offset: 0,
            transport: Transport::Udp,
            address: "10.0.0.1:5060".into(),
            timestamp: Timestamp::TimeOnly {
                hour: 1,
                min: 2,
                sec: 3,
                usec: 4,
            },
            content: b"x".to_vec(),
        };
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let rec = &bytes[24..];
        let ts_sec = u32::from_le_bytes(rec[0..4].try_into().unwrap());
        // 2026-04-28 01:02:03 UTC
        let expected = days_from_civil(2026, 4, 28) as u32 * 86400 + 3600 + 120 + 3;
        assert_eq!(ts_sec, expected);
    }

    #[test]
    fn time_only_no_base_is_epoch() {
        let mut w = writer_transport();
        let f = frame(Direction::Recv, Transport::Udp, "10.0.0.1:5060", b"x");
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let rec = &bytes[24..];
        let ts_sec = u32::from_le_bytes(rec[0..4].try_into().unwrap());
        assert!(ts_sec < 86400);
    }

    #[test]
    fn direction_pkttype() {
        let mut w = writer_transport();
        let r = frame(Direction::Recv, Transport::Udp, "10.0.0.1:5060", b"x");
        let s = frame(Direction::Sent, Transport::Udp, "10.0.0.1:5060", b"y");
        w.write_frame(&r).unwrap();
        w.write_frame(&s).unwrap();
        let bytes = w.into_inner();
        // Each record: 16 + 16 + 20 + 8 + 1 = 61
        let rec_size = 16 + 16 + 20 + 8 + 1;
        let r_off = 24 + 16; // skip global header + first record header
        let s_off = 24 + rec_size + 16;
        assert_eq!(u16::from_be_bytes([bytes[r_off], bytes[r_off + 1]]), 0);
        assert_eq!(u16::from_be_bytes([bytes[s_off], bytes[s_off + 1]]), 4);
    }

    #[test]
    fn tcp_checksum_validates() {
        let mut w = writer_transport();
        let f = frame(
            Direction::Sent,
            Transport::Tcp,
            "10.0.0.1:5060",
            b"REGISTER",
        );
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let pkt = &bytes[40..];
        let ip = &pkt[16..36];
        let src: [u8; 4] = ip[12..16].try_into().unwrap();
        let dst: [u8; 4] = ip[16..20].try_into().unwrap();
        let tcp = &pkt[36..];
        // Recompute and confirm equal to what's in the field.
        let recomputed = transport_checksum(
            IpPair::V4(Ipv4Addr::from(src), Ipv4Addr::from(dst)),
            IP_PROTO_TCP,
            &{
                let mut s = tcp.to_vec();
                s[16] = 0;
                s[17] = 0;
                s
            },
            tcp.len() as u16,
        );
        let stored = u16::from_be_bytes([tcp[16], tcp[17]]);
        assert_eq!(recomputed, stored);
    }

    #[test]
    fn network_layer_proto_field() {
        let mut w = writer_network();
        let f4 = frame(Direction::Recv, Transport::Udp, "10.0.0.1:5060", b"x");
        let f6 = frame(Direction::Recv, Transport::Udp, "[2001:db8::2]:5060", b"y");
        w.write_frame(&f4).unwrap();
        w.write_frame(&f6).unwrap();
        let bytes = w.into_inner();
        // First packet: record header 16, then IPv4 (20 bytes)
        let p1 = &bytes[24 + 16..];
        assert_eq!(p1[9], IP_PROTO_TESTING);
        // Skip first packet (20 + 1 payload) + record header
        let p1_len = 20 + 1;
        let p2 = &bytes[24 + 16 + p1_len + 16..];
        // IPv6 next_header at offset 6
        assert_eq!(p2[6], IP_PROTO_TESTING);
    }

    #[test]
    fn invalid_address_returns_error() {
        let mut w = writer_transport();
        let f = frame(Direction::Recv, Transport::Udp, "not-an-address", b"x");
        let err = w.write_frame(&f).unwrap_err();
        assert!(matches!(err, PcapError::InvalidAddress(_)));
    }

    #[test]
    fn oversize_payload_is_refused() {
        let mut w = writer_transport();
        let payload = vec![b'x'; 70 * 1024];
        let f = frame(Direction::Recv, Transport::Udp, "10.0.0.1:5060", &payload);
        let err = w.write_frame(&f).unwrap_err();
        match err {
            PcapError::PayloadTooLarge { len, max } => {
                assert_eq!(len, payload.len());
                assert!(max < len);
            }
            other => panic!("expected PayloadTooLarge, got {other}"),
        }
    }

    #[test]
    fn large_payload_within_snaplen_writes() {
        let mut w = writer_transport();
        let payload = vec![b'x'; 60 * 1024];
        let f = frame(Direction::Recv, Transport::Udp, "10.0.0.1:5060", &payload);
        w.write_frame(&f).unwrap();
        let bytes = w.into_inner();
        let captured = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
        assert_eq!(captured, 16 + 20 + 8 + payload.len());
        assert!(captured <= PCAP_SNAPLEN as usize);
    }

    #[test]
    fn bracketed_ipv4_accepted() {
        let f = frame(
            Direction::Recv,
            Transport::Udp,
            "[184.150.75.232]:51916",
            b"x",
        );
        let addr = f.meta().socket_addr().unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 51916);
    }

    #[test]
    fn days_from_civil_epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    use crate::types::SipMessageType;

    fn parsed(
        direction: Direction,
        transport: Transport,
        addr: &str,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> ParsedSipMessage {
        ParsedSipMessage {
            direction,
            transport,
            address: addr.to_string(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            message_type: SipMessageType::Request {
                method: method.to_string(),
                uri: uri.to_string(),
            },
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
            frame_count: 1,
            offset: 0,
        }
    }

    #[test]
    fn write_parsed_payload_round_trips() {
        let mut w = writer_transport();
        let msg = parsed(
            Direction::Recv,
            Transport::Udp,
            "10.0.0.1:5060",
            "OPTIONS",
            "sip:host",
            &[("Call-ID", "rt-test"), ("Content-Length", "0")],
            b"",
        );
        let expected_payload = msg.to_bytes();
        w.write_parsed(&msg).unwrap();
        let bytes = w.into_inner();
        // global 24 + record 16 + SLL 16 + IPv4 20 + UDP 8 = 84
        let payload = &bytes[84..];
        assert_eq!(payload, expected_payload.as_slice());
    }

    #[test]
    fn write_parsed_matches_write_message() {
        let payload = b"OPTIONS sip:host SIP/2.0\r\nCall-ID: eq-test\r\n\r\n";
        let mut wm = PcapWriter::new(Vec::new(), PcapConfig::default()).unwrap();
        wm.write_message(&SipMessage {
            direction: Direction::Recv,
            transport: Transport::Udp,
            address: "10.0.0.1:5060".into(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content: payload.to_vec(),
            frame_count: 1,
            offset: 0,
        })
        .unwrap();
        let from_message = wm.into_inner();

        let mut wp = PcapWriter::new(Vec::new(), PcapConfig::default()).unwrap();
        wp.write_parsed(&parsed(
            Direction::Recv,
            Transport::Udp,
            "10.0.0.1:5060",
            "OPTIONS",
            "sip:host",
            &[("Call-ID", "eq-test")],
            b"",
        ))
        .unwrap();
        let from_parsed = wp.into_inner();

        assert_eq!(from_message, from_parsed);
    }

    #[test]
    fn write_parsed_with_local_overrides_default() {
        let mut w = writer_transport();
        let msg = parsed(
            Direction::Recv,
            Transport::Udp,
            "10.0.0.1:5060",
            "OPTIONS",
            "sip:host",
            &[("Call-ID", "ovr-test")],
            b"",
        );
        let local: SocketAddr = "10.20.30.40:5070".parse().unwrap();
        w.write_parsed_with_local(&msg, Some(local)).unwrap();
        let bytes = w.into_inner();
        // global 24 + record 16 + SLL 16 = 56, IPv4 src at +12
        let ip = &bytes[56..76];
        assert_eq!(ip[12..16], [10, 0, 0, 1]); // remote (sender, recv direction)
        assert_eq!(ip[16..20], [10, 20, 30, 40]); // local override (receiver)
                                                  // UDP starts at offset 76; dst port = local port = 5070
        let udp = &bytes[76..];
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 5070);
    }

    #[test]
    fn write_parsed_with_local_rejects_family_mismatch() {
        let mut w = writer_transport();
        let msg = parsed(
            Direction::Sent,
            Transport::Udp,
            "[2001:db8::2]:5060",
            "OPTIONS",
            "sip:host",
            &[("Call-ID", "fam-test")],
            b"",
        );
        let local_v4: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let err = w.write_parsed_with_local(&msg, Some(local_v4)).unwrap_err();
        assert!(matches!(err, PcapError::AddressFamilyMismatch));
    }
}
