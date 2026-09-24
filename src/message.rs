use std::collections::{HashMap, VecDeque};

use tracing::{debug, info, trace};

use crate::finders::{CRLF, CRLFCRLF};
use crate::frame::{FrameIterator, ParseError};
use crate::startline::{sip_start, SipStart};
use crate::types::{
    Direction, ParseStats, SipMessage, SkipTracking, StaleClock, Timestamp, Transport,
    UnparsedRegion,
};

/// Connections named in one eviction warning; the rest are counted.
const EVICTION_SAMPLE: usize = 4;

/// Level 2 streaming parser: reassembles TCP segments into complete SIP messages.
///
/// Wraps a [`FrameIterator`] and groups TCP frames by `(Direction, Address)`.
/// Messages are emitted when headers and Content-Length body bytes are fully
/// available. UDP frames pass through as-is (1:1 mapping).
///
/// Stale TCP connection buffers are evicted after 2 hours of inactivity to
/// maintain constant memory on multi-day dump streams.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::MessageIterator;
///
/// let file = File::open("profile.dump").unwrap();
/// for msg in MessageIterator::new(file) {
///     let msg = msg.unwrap();
///     println!("{} {} {} ({} frames)",
///         msg.timestamp, msg.direction, msg.address, msg.frame_count);
/// }
/// ```
pub struct MessageIterator<R> {
    frames: FrameIterator<R>,
    buffers: HashMap<ConnectionKey, ConnectionBuffer>,
    ready: VecDeque<SipMessage>,
    exhausted: bool,
    clock: StaleClock,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    direction: Direction,
    address: String,
}

struct ConnectionBuffer {
    transport: Transport,
    timestamp: Timestamp,
    offset: u64,
    content: Vec<u8>,
    frame_count: usize,
    last_seen: u64,
}

impl<R: std::io::Read> MessageIterator<R> {
    /// Create a new message iterator reading from the given source.
    pub fn new(reader: R) -> Self {
        MessageIterator {
            frames: FrameIterator::new(reader),
            buffers: HashMap::new(),
            ready: VecDeque::new(),
            exhausted: false,
            clock: StaleClock::new(),
        }
    }

    /// Enable capturing of skipped bytes in the underlying [`FrameIterator`];
    /// `false` selects [`SkipTracking::CountOnly`]. Whichever of this and
    /// [`skip_tracking`](Self::skip_tracking) is called last wins.
    pub fn capture_skipped(mut self, enable: bool) -> Self {
        self.frames = self.frames.capture_skipped(enable);
        self
    }

    /// Set the level of detail for unparsed region tracking.
    pub fn skip_tracking(mut self, tracking: SkipTracking) -> Self {
        self.frames = self.frames.skip_tracking(tracking);
        self
    }

    /// Borrow the accumulated parse statistics from the underlying frame parser.
    pub fn parse_stats(&self) -> &ParseStats {
        self.frames.stats()
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_unparsed(&mut self) -> Vec<UnparsedRegion> {
        self.frames.drain_unparsed()
    }

    fn sweep_stale_buffers(&mut self) {
        let clock = &self.clock;
        let mut incomplete = 0usize;
        let mut pending_bytes = 0usize;
        let mut dropped: Vec<String> = Vec::new();
        self.buffers.retain(|key, buf| {
            if !clock.is_stale(buf.last_seen) {
                return true;
            }
            if buf.content.is_empty() {
                trace!(
                    address = %key.address,
                    direction = %key.direction,
                    elapsed_secs = clock.now().saturating_sub(buf.last_seen),
                    "evicted empty stale connection buffer"
                );
            } else {
                incomplete += 1;
                pending_bytes += buf.content.len();
                if dropped.len() < EVICTION_SAMPLE {
                    dropped.push(format!(
                        "{}/{} {}",
                        buf.transport, key.direction, key.address
                    ));
                }
            }
            false
        });
        if incomplete > 0 {
            let stats = self.frames.stats_mut();
            stats.stale_evictions += incomplete as u64;
            stats.stale_evicted_bytes += pending_bytes as u64;
            info!(
                buffers = incomplete,
                pending_bytes,
                connections = %dropped.join(", "),
                undisplayed = incomplete - dropped.len(),
                "evicted stale connection buffers with incomplete data"
            );
        }
    }

    fn flush_all(&mut self) {
        let mut loss = ResyncLoss::default();
        for (key, mut buf) in std::mem::take(&mut self.buffers) {
            extract_complete(&mut buf, &key, &mut self.ready, &mut loss);

            if !buf.content.is_empty() {
                let content = std::mem::take(&mut buf.content);
                let frame_count = buf.frame_count;
                self.ready
                    .push_back(message(&buf, &key, content, frame_count));
            }
        }
        self.record_resync_loss(loss);
    }

    fn record_resync_loss(&mut self, loss: ResyncLoss) {
        if loss.count == 0 {
            return;
        }
        let stats = self.frames.stats_mut();
        stats.non_sip_prefixes += loss.count;
        stats.non_sip_prefix_bytes += loss.bytes;
    }
}

impl<R: std::io::Read> Iterator for MessageIterator<R> {
    type Item = Result<SipMessage, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(msg) = self.ready.pop_front() {
            return Some(Ok(msg));
        }

        if self.exhausted {
            return None;
        }

        loop {
            match self.frames.next() {
                Some(Ok(frame)) => {
                    if frame.transport == Transport::Udp {
                        return Some(Ok(SipMessage {
                            direction: frame.direction,
                            transport: frame.transport,
                            address: frame.address,
                            timestamp: frame.timestamp,
                            content: frame.content,
                            offset: frame.offset,
                            frame_count: 1,
                        }));
                    }

                    let now = self.clock.observe(frame.timestamp);
                    if self.clock.sweep_due() {
                        self.sweep_stale_buffers();
                    }

                    let key = ConnectionKey {
                        direction: frame.direction,
                        address: frame.address,
                    };

                    let buf = match self.buffers.get_mut(&key) {
                        Some(buf) => buf,
                        None => self.buffers.entry(key.clone()).or_insert(ConnectionBuffer {
                            transport: frame.transport,
                            timestamp: frame.timestamp,
                            offset: frame.offset,
                            content: Vec::new(),
                            frame_count: 0,
                            last_seen: now,
                        }),
                    };

                    buf.last_seen = now;

                    if buf.content.is_empty() {
                        buf.timestamp = frame.timestamp;
                        buf.offset = frame.offset;
                    }

                    trace!(
                        frame = buf.frame_count + 1,
                        bytes = frame.content.len(),
                        address = %key.address,
                        "buffering TCP frame"
                    );

                    buf.content.extend_from_slice(&frame.content);
                    buf.frame_count += 1;

                    let mut loss = ResyncLoss::default();
                    extract_complete(buf, &key, &mut self.ready, &mut loss);

                    if buf.content.is_empty() {
                        self.buffers.remove(&key);
                    }
                    self.record_resync_loss(loss);

                    if let Some(msg) = self.ready.pop_front() {
                        return Some(Ok(msg));
                    }
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.exhausted = true;
                    self.flush_all();
                    return self.ready.pop_front().map(Ok);
                }
            }
        }
    }
}

/// Where the buffer stands relative to the next SIP message start.
enum Resync {
    Ready,
    Retry,
    Wait,
}

/// Bytes dropped resyncing a buffer, tallied into [`ParseStats`] once the
/// caller is done borrowing the buffer map.
#[derive(Default)]
struct ResyncLoss {
    count: u64,
    bytes: u64,
}

/// Move every message the buffer already holds in full into `ready`.
fn extract_complete(
    buf: &mut ConnectionBuffer,
    key: &ConnectionKey,
    ready: &mut VecDeque<SipMessage>,
    loss: &mut ResyncLoss,
) {
    loop {
        if buf.content.is_empty() {
            return;
        }
        match resync_to_sip_start(buf, key, loss) {
            Resync::Ready => {}
            Resync::Retry => continue,
            Resync::Wait => return,
        }
        if !split_one_message(buf, key, ready) {
            return;
        }
    }
}

/// Drop whatever precedes the next SIP message start in the buffer.
fn resync_to_sip_start(
    buf: &mut ConnectionBuffer,
    key: &ConnectionKey,
    loss: &mut ResyncLoss,
) -> Resync {
    match sip_start(&buf.content) {
        SipStart::Yes => return Resync::Ready,
        SipStart::NeedMore => return Resync::Wait, // Start line incomplete, wait for more data
        SipStart::No => {}
    }

    // Drain leading whitespace (CRLF padding, bare LF keep-alives, etc.)
    let ws_len = buf
        .content
        .iter()
        .position(|&b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
        .unwrap_or(buf.content.len());

    if ws_len > 0 {
        if ws_len == buf.content.len() {
            trace!(
                bytes = ws_len,
                address = %key.address,
                "drained transport whitespace"
            );
            buf.content.clear();
            buf.frame_count = 0;
            return Resync::Wait;
        }
        match sip_start(&buf.content[ws_len..]) {
            SipStart::Yes => {
                trace!(bytes = ws_len, "drained inter-message whitespace padding");
                buf.content.drain(..ws_len);
                return Resync::Retry;
            }
            SipStart::NeedMore => {
                trace!(bytes = ws_len, "drained inter-message whitespace padding");
                buf.content.drain(..ws_len);
                return Resync::Wait;
            }
            SipStart::No => {}
        }
    }

    match find_sip_start(&buf.content) {
        Some(offset) if offset > 0 => {
            debug!(
                skipped_bytes = offset,
                address = %key.address,
                "skipped non-SIP prefix in TCP buffer"
            );
            loss.count += 1;
            loss.bytes += offset as u64;
            buf.content.drain(..offset);
            Resync::Retry
        }
        _ => Resync::Wait, // No SIP start found, wait for more data
    }
}

/// Split one complete message off the front of the buffer. False means the
/// message is still arriving and the buffer keeps its bytes.
fn split_one_message(
    buf: &mut ConnectionBuffer,
    key: &ConnectionKey,
    ready: &mut VecDeque<SipMessage>,
) -> bool {
    let header_end = match CRLFCRLF.find(&buf.content) {
        Some(offset) => offset,
        None => return false, // Headers incomplete, wait for more data
    };
    let body_start = header_end + 4;

    let msg_end = match find_content_length(&buf.content, header_end) {
        Some(cl) => {
            let end = body_start + cl;
            if end > buf.content.len() {
                return false; // Body incomplete, wait for more data
            }
            end
        }
        None => body_start, // No CL = no body (RFC 3261 Section 18.3)
    };

    let remaining = buf.content.split_off(msg_end);
    let msg_content = std::mem::replace(&mut buf.content, remaining);

    // Skip trailing CRLF between messages
    while buf.content.len() >= 2 && buf.content[0] == b'\r' && buf.content[1] == b'\n' {
        buf.content.drain(..2);
    }

    let frame_count = buf.frame_count;
    if frame_count > 1 {
        debug!(
            frame_count,
            bytes = msg_content.len(),
            address = %key.address,
            "extracted reassembled TCP message"
        );
    }

    ready.push_back(message(buf, key, msg_content, frame_count));
    buf.frame_count = 0;
    true
}

fn message(
    buf: &ConnectionBuffer,
    key: &ConnectionKey,
    content: Vec<u8>,
    frame_count: usize,
) -> SipMessage {
    SipMessage {
        direction: key.direction,
        transport: buf.transport,
        address: key.address.clone(),
        timestamp: buf.timestamp,
        offset: buf.offset,
        content,
        frame_count,
    }
}

/// Find Content-Length header value in the header block ending at `header_end`.
fn find_content_length(data: &[u8], header_end: usize) -> Option<usize> {
    let headers = &data[..header_end];

    let mut pos = 0;
    while pos < headers.len() {
        let line_end = CRLF.find(&headers[pos..]).unwrap_or(headers.len() - pos);
        let line = &headers[pos..pos + line_end];

        if let Some(value) = extract_header_value(line, b"Content-Length") {
            return parse_content_length(value);
        }
        if let Some(value) = extract_compact_header_value(line, b'l') {
            return parse_content_length(value);
        }

        pos += line_end + 2; // skip \r\n
    }
    None
}

/// RFC 3261 HCOLON allows SP/HTAB between the header name and the colon, and
/// `sip_header` accepts it, so Level 2 framing must see the same header.
fn extract_header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let rest = line.get(name.len()..)?;
    if !line[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }
    let pad = rest
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(rest.len());
    match rest.get(pad..)?.split_first() {
        Some((b':', value)) => Some(trim_bytes(value)),
        _ => None,
    }
}

fn extract_compact_header_value(line: &[u8], compact: u8) -> Option<&[u8]> {
    if line.len() < 2 {
        return None;
    }
    if line[0] != compact || line[1] != b':' {
        return None;
    }
    Some(trim_bytes(&line[2..]))
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(start, |p| p + 1);
    &b[start..end]
}

fn parse_content_length(value: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(value).ok()?;
    s.parse().ok()
}

/// Scan for the first SIP message start at a CRLF boundary within data. A
/// candidate whose start line is still arriving stops the scan there, so the
/// bytes before it are dropped and the line itself is waited for.
fn find_sip_start(data: &[u8]) -> Option<usize> {
    if !matches!(sip_start(data), SipStart::No) {
        return Some(0);
    }
    let mut pos = 0;
    while let Some(offset) = CRLF.find(&data[pos..]) {
        let candidate = pos + offset + 2;
        if candidate >= data.len() {
            break;
        }
        if !matches!(sip_start(&data[candidate..]), SipStart::No) {
            return Some(candidate);
        }
        pos = candidate;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;

    fn buffer_with(content: Vec<u8>) -> ConnectionBuffer {
        ConnectionBuffer {
            transport: Transport::Tcp,
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content,
            frame_count: 1,
            offset: 0,
            last_seen: 0,
        }
    }

    fn extracted(buf: &mut ConnectionBuffer) -> Vec<SipMessage> {
        let key = ConnectionKey {
            direction: Direction::Recv,
            address: "[::1]:5060".to_string(),
        };
        let mut ready = VecDeque::new();
        extract_complete(buf, &key, &mut ready, &mut ResyncLoss::default());
        ready.into()
    }

    fn content_length(data: &[u8]) -> Option<usize> {
        find_content_length(data, CRLFCRLF.find(data)?)
    }

    fn make_frame(
        direction: Direction,
        transport: Transport,
        addr: &str,
        content: &[u8],
    ) -> Vec<u8> {
        make_frame_at(direction, transport, addr, content, "00:00:00.000000")
    }

    #[test]
    fn single_udp_message() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, content);
        assert_eq!(msgs[0].frame_count, 1);
        assert_eq!(msgs[0].transport, Transport::Udp);
    }

    #[test]
    fn tcp_reassembly_two_frames() {
        let part1 = b"NOTIFY sip:user@host SIP/2.0\r\n";
        let part2 = b"Content-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", part1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            part2,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].frame_count, 2);
        let mut expected = Vec::new();
        expected.extend_from_slice(part1);
        expected.extend_from_slice(part2);
        assert_eq!(msgs[0].content, expected);
    }

    /// A reassembled message reports its first frame's position, the frame its
    /// timestamp also comes from.
    #[test]
    fn a_reassembled_message_reports_its_first_frame() {
        let lead = make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n",
        );
        let part1 = b"NOTIFY sip:user@host SIP/2.0\r\n";
        let part2 = b"Content-Length: 0\r\n\r\n";
        let mut data = lead.clone();
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            part1,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            part2,
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].offset, 0);
        assert_eq!(
            msgs[1].offset,
            lead.len() as u64,
            "the NOTIFY spans two frames and begins at the first of them"
        );
    }

    #[test]
    fn tcp_reassembly_across_interleaved_frames() {
        // Frame 1: recv from A (partial INVITE)
        // Frame 2: sent to A (response on same connection — interrupts)
        // Frame 3: recv from A (rest of INVITE)
        let part1 = b"INVITE sip:user@host SIP/2.0\r\n";
        let part2 = b"Content-Length: 3\r\n\r\nSDP";
        let response = b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, "10.0.0.1:5060", part1);
        data.extend_from_slice(&make_frame(
            Direction::Sent,
            Transport::Tcp,
            "10.0.0.1:5060",
            response,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "10.0.0.1:5060",
            part2,
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(msgs.len(), 2);

        // 100 Trying completes first (single frame)
        let trying = &msgs[0];
        assert_eq!(trying.direction, Direction::Sent);
        assert_eq!(trying.content, response);

        // INVITE completes when frame 3 arrives (reassembled from frames 1+3)
        let invite = &msgs[1];
        assert_eq!(invite.direction, Direction::Recv);
        let mut expected_invite = Vec::new();
        expected_invite.extend_from_slice(part1);
        expected_invite.extend_from_slice(part2);
        assert_eq!(invite.content, expected_invite);
    }

    #[test]
    fn tcp_reassembly_interleaved_different_addresses() {
        // Two different addresses both sending multi-frame messages,
        // frames arriving interleaved:
        //   Frame 1: recv from A (partial INVITE)
        //   Frame 2: recv from B (partial NOTIFY)
        //   Frame 3: recv from A (rest of INVITE — completes A)
        //   Frame 4: recv from B (rest of NOTIFY — completes B)
        let a_part1 = b"INVITE sip:user@host SIP/2.0\r\n";
        let a_part2 = b"Content-Length: 3\r\n\r\nSDP";
        let b_part1 = b"NOTIFY sip:user@host SIP/2.0\r\n";
        let b_part2 = b"Content-Length: 4\r\n\r\nBODY";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", a_part1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            b_part1,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            a_part2,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            b_part2,
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(msgs.len(), 2);

        // INVITE from [::1] completes first (frame 3 arrives before frame 4)
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(msgs[0].frame_count, 2);
        let mut expected_a = Vec::new();
        expected_a.extend_from_slice(a_part1);
        expected_a.extend_from_slice(a_part2);
        assert_eq!(msgs[0].content, expected_a);

        // NOTIFY from [::2] completes second
        assert_eq!(msgs[1].address, "[::2]:5060");
        assert_eq!(msgs[1].frame_count, 2);
        let mut expected_b = Vec::new();
        expected_b.extend_from_slice(b_part1);
        expected_b.extend_from_slice(b_part2);
        assert_eq!(msgs[1].content, expected_b);
    }

    #[test]
    fn direction_change_splits_messages() {
        let recv_content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let sent_content = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", recv_content);
        data.extend_from_slice(&make_frame(
            Direction::Sent,
            Transport::Tcp,
            "[::1]:5060",
            sent_content,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, Direction::Recv);
        assert_eq!(msgs[1].direction, Direction::Sent);
    }

    #[test]
    fn address_change_splits_messages() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", content);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            content,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(msgs[1].address, "[::2]:5060");
    }

    #[test]
    fn udp_no_reassembly() {
        let content1 = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let content2 = b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Udp,
            "1.1.1.1:5060",
            content2,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2, "UDP frames should not be reassembled");
        assert_eq!(msgs[0].frame_count, 1);
        assert_eq!(msgs[1].frame_count, 1);
    }

    #[test]
    fn aggregated_messages_split_by_content_length() {
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", &combined);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, msg1);
        assert_eq!(msgs[1].content, msg2);
    }

    #[test]
    fn find_content_length_standard() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(content_length(data), Some(42));
    }

    #[test]
    fn find_content_length_compact() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nl: 42\r\n\r\n";
        assert_eq!(content_length(data), Some(42));
    }

    #[test]
    fn find_content_length_padded_before_colon() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nContent-Length \t: 5\r\n\r\nhello";
        assert_eq!(content_length(data), Some(5));
    }

    #[test]
    fn padded_colon_splits_aggregated_messages() {
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length : 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", &combined);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, msg1);
        assert_eq!(msgs[1].content, msg2);
    }

    #[test]
    fn find_content_length_missing() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nCSeq: 1 NOTIFY\r\n\r\n";
        assert_eq!(content_length(data), None);
    }

    #[test]
    fn sip_start_request() {
        assert!(matches!(
            sip_start(b"INVITE sip:user@host SIP/2.0\r\n"),
            SipStart::Yes
        ));
        assert!(matches!(
            sip_start(b"XYZZY sip:user@host SIP/2.0\r\n"),
            SipStart::Yes
        ));
        assert!(matches!(
            sip_start(b"ACK sip:user@host SIP/2.0\r\n"),
            SipStart::Yes
        ));
    }

    #[test]
    fn sip_start_response() {
        assert!(matches!(sip_start(b"SIP/2.0 200 OK\r\n"), SipStart::Yes));
        assert!(matches!(
            sip_start(b"SIP/2.0 100 Trying\r\n"),
            SipStart::Yes
        ));
    }

    #[test]
    fn sip_start_not_sip() {
        assert!(matches!(sip_start(b"some random data\r\n"), SipStart::No));
        assert!(matches!(sip_start(b"HTTP/1.1 200 OK\r\n"), SipStart::No));
        assert!(matches!(
            sip_start(b"INVITE sip:user@host HTTP/1.1\r\n"),
            SipStart::No
        ));
    }

    #[test]
    fn sip_start_needs_more() {
        assert!(matches!(sip_start(b"INVI"), SipStart::NeedMore));
        assert!(matches!(sip_start(b"SIP/2."), SipStart::NeedMore));
        assert!(matches!(
            sip_start(b"INVITE sip:user@host SIP/2.0\r"),
            SipStart::NeedMore
        ));
    }

    #[test]
    fn find_sip_start_at_beginning() {
        let data = b"INVITE sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_sip_start(data), Some(0));
    }

    #[test]
    fn find_sip_start_after_prefix() {
        let data = b"</xml>\r\nNOTIFY sip:user@host SIP/2.0\r\n";
        assert_eq!(find_sip_start(data), Some(8));
    }

    #[test]
    fn find_sip_start_none() {
        let data = b"no SIP here\r\nat all\r\n";
        assert_eq!(find_sip_start(data), None);
    }

    #[test]
    fn message_preserves_metadata() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(
            Direction::Sent,
            Transport::Tls,
            "[2001:db8::1]:5061",
            content,
        );
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Sent);
        assert_eq!(msgs[0].transport, Transport::Tls);
        assert_eq!(msgs[0].address, "[2001:db8::1]:5061");
        assert_eq!(
            msgs[0].timestamp,
            Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0
            }
        );
    }

    #[test]
    fn extract_handles_crlf_between_messages() {
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(msg1);
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(msg2);

        let mut buf = buffer_with(content);
        let msgs = extracted(&mut buf);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, msg1);
        assert_eq!(msgs[1].content, msg2);
    }

    #[test]
    fn extract_skips_non_sip_prefix() {
        let prefix = b"</conference-info>\r\n";
        let msg = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(prefix);
        content.extend_from_slice(msg);

        let mut buf = buffer_with(content);
        let msgs = extracted(&mut buf);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, msg);
    }

    #[test]
    fn non_sip_prefix_counted_in_stats() {
        let prefix = b"</conference-info>\r\n";
        let msg = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(prefix);
        content.extend_from_slice(msg);
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", &content);

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1);
        let stats = iter.parse_stats();
        assert_eq!(stats.non_sip_prefixes(), 1);
        assert_eq!(stats.non_sip_prefix_bytes(), prefix.len() as u64);
    }

    #[test]
    fn extract_resyncs_on_extension_method() {
        let prefix = b"</conference-info>\r\n";
        let msg = b"XYZZY sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(prefix);
        content.extend_from_slice(msg);
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", &content);

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, msg);
    }

    #[test]
    fn extract_waits_for_half_received_request_line() {
        let mut content = Vec::new();
        content.extend_from_slice(b"</conference-info>\r\n");
        content.extend_from_slice(b"XYZZY sip:a SI");

        let mut buf = buffer_with(content);
        let msgs = extracted(&mut buf);
        assert!(msgs.is_empty());
        assert_eq!(
            buf.content, b"XYZZY sip:a SI",
            "an unterminated request line waits instead of being scanned past"
        );
    }

    #[test]
    fn extract_waits_for_incomplete_body() {
        // Headers complete but body is missing
        let content = b"INVITE sip:a SIP/2.0\r\nContent-Length: 100\r\n\r\npartial".to_vec();

        let mut buf = buffer_with(content);
        let msgs = extracted(&mut buf);
        assert!(msgs.is_empty(), "should wait for body to complete");
        assert!(!buf.content.is_empty(), "buffer should retain data");
    }

    #[test]
    fn extract_waits_for_incomplete_headers() {
        // Headers not complete (no \r\n\r\n)
        let content = b"INVITE sip:a SIP/2.0\r\nContent-Length: 0\r\n".to_vec();

        let mut buf = buffer_with(content);
        let msgs = extracted(&mut buf);
        assert!(msgs.is_empty(), "should wait for headers to complete");
    }

    #[test]
    fn tcp_body_split_across_five_frames() {
        // Simulate REQUEST.md scenario: NOTIFY with Content-Length: 6424
        // body split across 5 TCP frames (like NG9-1-1 abandoned call JSON)
        let body_len: usize = 6424;
        let body: Vec<u8> = (0..body_len).map(|i| b'A' + (i % 26) as u8).collect();

        let mut headers = Vec::new();
        headers.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        headers
            .extend_from_slice(b"Via: SIP/2.0/TCP [2001:4958:10:11::6]:45538;branch=z9hG4bK-1\r\n");
        headers.extend_from_slice(b"Call-ID: fragmented-notify@host\r\n");
        headers.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        headers.extend_from_slice(
            b"Content-Type: application/emergencyCallData.AbandonedCall+json\r\n",
        );
        headers.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        headers.extend_from_slice(b"\r\n");

        let mut full_content = headers.clone();
        full_content.extend_from_slice(&body);

        // Split into 5 frames like real TCP segments
        let frame1_len = 1500.min(full_content.len());
        let remaining = &full_content[frame1_len..];
        let frame2_len = 1428.min(remaining.len());
        let remaining = &remaining[frame2_len..];
        let frame3_len = 1428.min(remaining.len());
        let remaining = &remaining[frame3_len..];
        let frame4_len = 1428.min(remaining.len());
        let remaining = &remaining[frame4_len..];
        let frame5_len = remaining.len();

        let addr = "[2001:4958:10:11::6]:45538";
        let mut data = make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[..frame1_len],
        );
        let mut offset = frame1_len;
        for len in [frame2_len, frame3_len, frame4_len, frame5_len] {
            data.extend_from_slice(&make_frame(
                Direction::Recv,
                Transport::Tcp,
                addr,
                &full_content[offset..offset + len],
            ));
            offset += len;
        }
        assert_eq!(offset, full_content.len());

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            msgs.len(),
            1,
            "should produce exactly one reassembled message"
        );
        assert_eq!(msgs[0].frame_count, 5, "should track all 5 frames");
        assert_eq!(
            msgs[0].content, full_content,
            "content should be fully reassembled"
        );
        assert_eq!(msgs[0].direction, Direction::Recv);
        assert_eq!(msgs[0].address, addr);
    }

    #[test]
    fn parse_stats_delegates() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content);
        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<_> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1);
        let stats = iter.parse_stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
    }

    #[test]
    fn tcp_body_split_parsed_message() {
        // Same scenario but verified through Level 3 (ParsedSipMessage)
        let body_len: usize = 6424;
        let body: Vec<u8> = (0..body_len).map(|i| b'A' + (i % 26) as u8).collect();

        let mut headers = Vec::new();
        headers.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        headers.extend_from_slice(b"Call-ID: fragmented-parsed@host\r\n");
        headers.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        headers.extend_from_slice(
            b"Content-Type: application/emergencyCallData.AbandonedCall+json\r\n",
        );
        headers.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        headers.extend_from_slice(b"\r\n");

        let mut full_content = headers.clone();
        full_content.extend_from_slice(&body);

        // Split into 3 frames
        let split1 = 1500.min(full_content.len());
        let split2 = (split1 + 3000).min(full_content.len());

        let addr = "[2001:db8::1]:5060";
        let mut data = make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[..split1],
        );
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[split1..split2],
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[split2..],
        ));

        let parsed: Vec<crate::types::ParsedSipMessage> =
            crate::sip::ParsedMessageIterator::new(&data[..])
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        assert_eq!(parsed.len(), 1, "should produce one parsed message");
        assert_eq!(parsed[0].content_length(), Some(body_len));
        assert_eq!(parsed[0].body.len(), body_len, "body should be complete");
        assert_eq!(parsed[0].body, body, "body content should match");
        assert_eq!(parsed[0].frame_count, 3);
        assert_eq!(parsed[0].method(), Some("NOTIFY"));
    }

    #[test]
    fn tls_keepalive_single_lf_drained() {
        let data = make_frame(Direction::Recv, Transport::Tls, "[10.0.0.1]:5061", b"\n");
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 0, "keep-alive \\n should produce no messages");
    }

    #[test]
    fn tls_keepalive_multiple_lf_drained() {
        let addr = "[10.0.0.1]:5061";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, b"\n");
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            msgs.len(),
            0,
            "multiple keep-alive \\n should produce no messages"
        );
    }

    #[test]
    fn tls_keepalive_interleaved_with_sip() {
        let addr = "[10.0.0.1]:5061";
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, b"\n");
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, sip));
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1, "only the SIP message should be emitted");
        assert_eq!(msgs[0].content, sip);
        assert_eq!(
            msgs[0].frame_count, 1,
            "the drained keep-alive frame must not count toward the message"
        );
        assert!(
            iter.buffers.is_empty(),
            "a buffer drained to nothing must not be retained"
        );
    }

    #[test]
    fn tls_bare_lf_before_sip_start() {
        let addr = "[10.0.0.1]:5061";
        let sip_part1 = b"\nOPTIONS sip:host SIP/2.0\r\n";
        let sip_part2 = b"Content-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, sip_part1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tls,
            addr,
            sip_part2,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1, "SIP after bare LF should be extracted");
        assert!(
            msgs[0].content.starts_with(b"OPTIONS"),
            "message should start with SIP method, not \\n"
        );
    }

    fn make_frame_at(
        direction: Direction,
        transport: Transport,
        addr: &str,
        content: &[u8],
        timestamp: &str,
    ) -> Vec<u8> {
        let dir_str = match direction {
            Direction::Recv => "recv",
            Direction::Sent => "sent",
        };
        let prep = match direction {
            Direction::Recv => "from",
            Direction::Sent => "to",
        };
        let transport_str = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Tls => "tls",
            Transport::Wss => "wss",
        };
        let header = format!(
            "{dir_str} {} bytes {prep} {transport_str}/{addr} at {timestamp}:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");
        data
    }

    #[test]
    fn empty_buffer_removed_after_complete_message() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let addr_a = "[::1]:5060";
        let addr_b = "[::2]:5060";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, addr_a, sip);
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tcp, addr_b, sip));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(
            iter.buffers.is_empty(),
            "all buffers should be removed after complete messages are extracted"
        );
    }

    #[test]
    fn stale_buffer_evicted_after_timeout() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = Vec::new();
        // Partial frame from stale addr at 10:00:00
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::99]:44444",
            partial,
            "2026-02-16 10:00:00.000000",
        ));
        // Complete msg from another addr at 12:00:01 (>2h later, triggers sweep)
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::1]:5060",
            sip,
            "2026-02-16 12:00:01.000000",
        ));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(msgs.len(), 1, "should produce the complete message");
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert!(
            iter.buffers.is_empty(),
            "stale buffer for [::99]:44444 should have been evicted"
        );
        let stats = iter.parse_stats();
        assert_eq!(stats.stale_evictions(), 1);
        assert_eq!(stats.stale_evicted_bytes(), partial.len() as u64);
    }

    #[test]
    fn stale_buffer_evicted_across_dates() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::99]:44444",
            partial,
            "2026-02-16 10:00:00.000000",
        );
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::1]:5060",
            sip,
            "2026-02-19 10:00:01.000000",
        ));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(msgs.len(), 1, "the three-day-old buffer must be evicted");
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert!(iter.buffers.is_empty());
    }

    #[test]
    fn timestamp_format_change_evicts_nothing() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::99]:44444",
            partial,
            "10:00:00.000000",
        );
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::1]:5060",
            sip,
            "2026-02-16 12:00:01.000000",
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            msgs.len(),
            2,
            "the two timestamp formats share no epoch, so nothing is stale"
        );
        assert_eq!(msgs[1].address, "[::99]:44444");
        assert_eq!(msgs[1].content, partial);
    }

    #[test]
    fn day_rollover_detection_with_time_only() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = Vec::new();
        // Partial frame at 23:59:00
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tcp,
            "[::99]:44444",
            partial,
            "23:59:00.000000",
        ));
        // Complete msg at 02:00:01 (next day — rollover detected, >2h from 23:59)
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            sip,
            "02:00:01.000000",
        ));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(
            iter.clock.now(),
            86400 + 2 * 3600 + 1,
            "should have detected one day rollover"
        );
        assert!(
            iter.buffers.is_empty(),
            "stale buffer should have been evicted after day rollover"
        );
    }

    #[test]
    fn flush_all_clears_buffers() {
        let partial = b"INVITE sip:host SIP/2.0\r\n";
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", partial);

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1, "partial should be flushed at EOF");
        assert!(
            iter.buffers.is_empty(),
            "flush_all should clear the HashMap"
        );
    }
}
