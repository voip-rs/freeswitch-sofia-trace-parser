use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;

/// Canonical name of an RFC 3261 §7.3.3 compact form, `None` for any other
/// header name.
pub(crate) fn expand_compact(name: &str) -> Option<&'static str> {
    let [ch] = name.as_bytes() else {
        return None;
    };
    sip_header::SipHeader::from_compact(*ch).map(|header| header.as_str())
}

/// Value recorded under `name` or under the compact form that expands to it,
/// preferring the full name wherever the message carries both.
pub(crate) fn value_or_compact<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    let mut compact = None;
    for (key, value) in headers.iter() {
        if key.eq_ignore_ascii_case(name) {
            return Some(value);
        }
        if compact.is_none()
            && key.len() == 1
            && expand_compact(key).is_some_and(|full| full.eq_ignore_ascii_case(name))
        {
            compact = Some(value.as_str());
        }
    }
    compact
}

/// mod_sofia brackets IPv4 like IPv6 (`[198.51.100.7]:5060`); anything that
/// isn't an ip:port shape yields `None` rather than a guess.
fn parse_socket_addr(address: &str) -> Option<SocketAddr> {
    if let Ok(addr) = address.parse() {
        return Some(addr);
    }
    let (ip, port) = address.strip_prefix('[')?.split_once("]:")?;
    Some(SocketAddr::new(ip.parse().ok()?, port.parse().ok()?))
}

/// Why a region of the input stream was not parsed into a frame.
///
/// Every byte in the input is either parsed or classified with one of these
/// reasons, enabling byte-level coverage accounting via [`ParseStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// Truncated frame at the start of a file, typically from logrotate
    /// cutting mid-write. Capped at 65,537 bytes: the largest datagram plus
    /// the two-byte boundary.
    PartialFirstFrame,
    /// Skip region exceeds 65,537 bytes, at file start or mid-stream,
    /// indicating the input is not a dump file (e.g., compressed or binary
    /// data).
    OversizedFrame,
    /// Unrecoverable bytes skipped between valid frames mid-stream.
    MidStreamSkip,
    /// Logrotate wrote a partial frame tail at the start of the new file.
    /// Detected by the `\r\n\r\n\x0B\n` suffix pattern.
    ReplayedFrame,
    /// Frame at EOF with fewer content bytes than declared in the header.
    IncompleteFrame,
    /// Data starts with `recv`/`sent` but fails frame header parsing.
    InvalidHeader,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::PartialFirstFrame => f.write_str("partial first frame"),
            SkipReason::OversizedFrame => f.write_str("oversized frame"),
            SkipReason::MidStreamSkip => f.write_str("mid-stream skip"),
            SkipReason::ReplayedFrame => f.write_str("replayed frame (logrotate)"),
            SkipReason::IncompleteFrame => f.write_str("incomplete frame"),
            SkipReason::InvalidHeader => f.write_str("invalid header"),
        }
    }
}

/// Controls how much detail the parser records about unparsed regions.
///
/// Defaults to `CountOnly` for constant-memory operation. Higher levels
/// allocate per-region and should only be enabled for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipTracking {
    /// Track only `bytes_read` and `bytes_skipped` counters. No allocation.
    CountOnly,
    /// Record offset, length, and reason for each unparsed region.
    TrackRegions,
    /// Like `TrackRegions`, but also capture the skipped bytes themselves.
    CaptureData,
}

/// A contiguous region of the input that was not parsed into a frame.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnparsedRegion {
    /// Byte offset from the start of the input stream.
    pub offset: u64,
    /// Number of bytes in this region.
    pub length: u64,
    /// Why this region was skipped.
    pub reason: SkipReason,
    /// The raw bytes, populated only when [`SkipTracking::CaptureData`] is enabled.
    pub data: Option<Vec<u8>>,
}

/// Byte-level parse coverage statistics.
///
/// Available from all three iterator levels via `stats()` or `parse_stats()`.
/// Every byte consumed from the reader is accounted for as either parsed
/// (`bytes_read - bytes_skipped`) or skipped (`bytes_skipped`).
#[derive(Debug, Default, Clone)]
pub struct ParseStats {
    pub(crate) bytes_read: u64,
    pub(crate) bytes_skipped: u64,
    pub(crate) incomplete_frames: u64,
    pub(crate) incomplete_frame_bytes: u64,
    pub(crate) stale_evictions: u64,
    pub(crate) stale_evicted_bytes: u64,
    pub(crate) non_sip_prefixes: u64,
    pub(crate) non_sip_prefix_bytes: u64,
    pub(crate) unparsed_regions: Vec<UnparsedRegion>,
}

impl ParseStats {
    /// Total bytes consumed from the reader.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Bytes that were skipped (not parsed into frames).
    pub fn bytes_skipped(&self) -> u64 {
        self.bytes_skipped
    }

    /// Frames whose content ran out before `byte_count` at end of input.
    /// Maintained in every [`SkipTracking`] mode.
    pub fn incomplete_frames(&self) -> u64 {
        self.incomplete_frames
    }

    /// Total shortfall of those frames. A caller stitching rotated files
    /// together decides for itself whether a shortfall is a rotation cut.
    pub fn incomplete_frame_bytes(&self) -> u64 {
        self.incomplete_frame_bytes
    }

    /// Connection buffers dropped mid-stream while still holding a partial
    /// message. Unlike a frame cut at end of input, this content is never
    /// emitted, so it is lost from the output.
    pub fn stale_evictions(&self) -> u64 {
        self.stale_evictions
    }

    /// Bytes those buffers were holding.
    pub fn stale_evicted_bytes(&self) -> u64 {
        self.stale_evicted_bytes
    }

    /// Times a TCP buffer resynchronised past bytes that began no SIP message.
    pub fn non_sip_prefixes(&self) -> u64 {
        self.non_sip_prefixes
    }

    /// Bytes discarded by those resynchronisations.
    pub fn non_sip_prefix_bytes(&self) -> u64 {
        self.non_sip_prefix_bytes
    }

    /// Detailed unparsed region records. Only populated when
    /// [`SkipTracking`] is `TrackRegions` or `CaptureData`.
    pub fn unparsed_regions(&self) -> &[UnparsedRegion] {
        &self.unparsed_regions
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_regions(&mut self) -> Vec<UnparsedRegion> {
        std::mem::take(&mut self.unparsed_regions)
    }
}

/// The input named none of the keywords a [`Direction`] or [`Transport`]
/// is written as in a frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKeyword(String);

impl UnknownKeyword {
    /// The rejected input.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownKeyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown keyword: {}", self.0)
    }
}

impl std::error::Error for UnknownKeyword {}

/// Whether a frame was received or sent by FreeSWITCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Received from the network.
    Recv,
    /// Sent to the network.
    Sent,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Direction {
    type Err = UnknownKeyword;

    /// Accepts `recv` and `sent`, case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for candidate in [Direction::Recv, Direction::Sent] {
            if s.eq_ignore_ascii_case(candidate.as_str()) {
                return Ok(candidate);
            }
        }
        Err(UnknownKeyword(s.to_string()))
    }
}

impl Direction {
    /// The keyword a frame header spells this direction with.
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Recv => "recv",
            Direction::Sent => "sent",
        }
    }

    /// Returns `"from"` for `Recv`, `"to"` for `Sent`.
    pub fn preposition(&self) -> &'static str {
        match self {
            Direction::Recv => "from",
            Direction::Sent => "to",
        }
    }
}

/// SIP transport protocol as reported in the frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Transport Layer Security.
    Tls,
    /// WebSocket Secure (RFC 7118).
    Wss,
}

impl Transport {
    /// The keyword a frame header spells this transport with.
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Tls => "tls",
            Transport::Wss => "wss",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Transport {
    type Err = UnknownKeyword;

    /// Accepts `tcp`, `udp`, `tls` and `wss`, case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for candidate in [
            Transport::Tcp,
            Transport::Udp,
            Transport::Tls,
            Transport::Wss,
        ] {
            if s.eq_ignore_ascii_case(candidate.as_str()) {
                return Ok(candidate);
            }
        }
        Err(UnknownKeyword(s.to_string()))
    }
}

/// Frame timestamp, either time-only or full date+time.
///
/// Older FreeSWITCH versions write `HH:MM:SS.usec`, newer versions write
/// `YYYY-MM-DD HH:MM:SS.usec`. Both formats are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// `HH:MM:SS.usec` — no date component.
    TimeOnly {
        /// Hour (0-23).
        hour: u8,
        /// Minute (0-59).
        min: u8,
        /// Second (0-59).
        sec: u8,
        /// Microseconds (0-999999).
        usec: u32,
    },
    /// `YYYY-MM-DD HH:MM:SS.usec` — full date and time.
    DateTime {
        /// Year.
        year: u16,
        /// Month (1-12).
        month: u8,
        /// Day (1-31).
        day: u8,
        /// Hour (0-23).
        hour: u8,
        /// Minute (0-59).
        min: u8,
        /// Second (0-59).
        sec: u8,
        /// Microseconds (0-999999).
        usec: u32,
    },
}

impl Timestamp {
    /// Seconds since midnight, ignoring microseconds.
    pub fn time_of_day_secs(&self) -> u32 {
        let (h, m, s) = match self {
            Timestamp::TimeOnly { hour, min, sec, .. } => (*hour, *min, *sec),
            Timestamp::DateTime { hour, min, sec, .. } => (*hour, *min, *sec),
        };
        h as u32 * 3600 + m as u32 * 60 + s as u32
    }

    /// Tuple suitable for chronological ordering.
    /// `TimeOnly` timestamps sort before any `DateTime` (year/month/day = 0).
    pub fn sort_key(&self) -> (u16, u8, u8, u8, u8, u8, u32) {
        match self {
            Timestamp::TimeOnly {
                hour,
                min,
                sec,
                usec,
            } => (0, 0, 0, *hour, *min, *sec, *usec),
            Timestamp::DateTime {
                year,
                month,
                day,
                hour,
                min,
                sec,
                usec,
            } => (*year, *month, *day, *hour, *min, *sec, *usec),
        }
    }
}

/// Howard Hinnant's `days_from_civil` — proleptic Gregorian days since
/// 1970-01-01. Pure integer math, valid for the entire i64 range.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m_adj = if m > 2 { m as i64 - 3 } else { m as i64 + 9 } as u64;
    let doy = (153 * m_adj + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Elapsed time over a dump stream, for parsers that drop state a connection
/// or dialog has stopped feeding.
///
/// A dated timestamp gives absolute seconds from its own date. A time-only
/// timestamp has no date, so it gets a synthetic day counter that increments
/// when the clock wraps past midnight. The two carry no common epoch: a stream
/// that changes format resets the clock, and the sweep that would follow that
/// reset is skipped, since every recorded time then belongs to the other
/// domain.
#[derive(Debug, Default, Clone)]
pub struct StaleClock {
    day: u32,
    last_time_secs: u32,
    now: u64,
    last_sweep: u64,
    dated: Option<bool>,
    reset: bool,
}

impl StaleClock {
    /// How long a connection or dialog may stay silent before its pending
    /// state is dropped: the RFC 793 default TCP keepalive timeout, beyond
    /// which a VoIP connection is dead.
    pub const TIMEOUT_SECS: u64 = 7200;

    /// A clock that has seen no timestamp yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a timestamp and return the stream time it reads, in seconds.
    pub fn observe(&mut self, timestamp: Timestamp) -> u64 {
        let dated = matches!(timestamp, Timestamp::DateTime { .. });
        if self.dated != Some(dated) {
            self.dated = Some(dated);
            self.day = 0;
            self.last_time_secs = 0;
            self.reset = true;
        }

        let time_secs = timestamp.time_of_day_secs();
        self.now = match timestamp {
            Timestamp::DateTime {
                year, month, day, ..
            } => {
                let days = days_from_civil(year as i64, month as u32, day as u32).max(0) as u64;
                days * 86400 + time_secs as u64
            }
            Timestamp::TimeOnly { .. } => {
                if time_secs < self.last_time_secs && self.last_time_secs - time_secs > 43200 {
                    self.day += 1;
                }
                self.day as u64 * 86400 + time_secs as u64
            }
        };
        self.last_time_secs = time_secs;
        self.now
    }

    /// The stream time of the last observed timestamp, in seconds.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Whether a stale sweep is due, marking one as taken when it is. The
    /// first sweep after a format change is not due: no recorded time is
    /// comparable to the clock's new domain.
    pub fn sweep_due(&mut self) -> bool {
        if self.reset {
            self.reset = false;
            self.last_sweep = self.now;
            return false;
        }
        if self.now.saturating_sub(self.last_sweep) >= Self::TIMEOUT_SECS {
            self.last_sweep = self.now;
            return true;
        }
        false
    }

    /// Whether a time recorded from [`now`](Self::now) has gone stale.
    pub fn is_stale(&self, last_seen: u64) -> bool {
        self.now.saturating_sub(last_seen) > Self::TIMEOUT_SECS
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Timestamp::TimeOnly {
                hour,
                min,
                sec,
                usec,
            } => write!(f, "{hour:02}:{min:02}:{sec:02}.{usec:06}"),
            Timestamp::DateTime {
                year,
                month,
                day,
                hour,
                min,
                sec,
                usec,
            } => write!(
                f,
                "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}.{usec:06}"
            ),
        }
    }
}

/// The transport metadata every level carries: who the peer was, over what,
/// in which direction, and when.
///
/// Borrows the address from the frame or message it describes, so it costs no
/// allocation and cannot drift from its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMeta<'a> {
    /// Whether the frame was received or sent.
    pub direction: Direction,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as recorded in the frame header.
    pub address: &'a str,
    /// When the frame was logged.
    pub timestamp: Timestamp,
}

impl FrameMeta<'_> {
    /// The remote address as a typed [`SocketAddr`], preserving family and
    /// port. `None` when the recorded address is not `ip:port`; the raw string
    /// remains in [`address`](Self::address).
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        parse_socket_addr(self.address)
    }
}

impl fmt::Display for FrameMeta<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}/{} at {}",
            self.direction,
            self.direction.preposition(),
            self.transport,
            self.address,
            self.timestamp
        )
    }
}

/// A single frame from the dump file (Level 1 output).
///
/// Each frame corresponds to one `send()` or `recv()` call logged by
/// `mod_sofia`. The `byte_count` field is the value FreeSWITCH wrote in the
/// header; `content` is the actual payload between boundaries.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this frame was received or sent.
    pub direction: Direction,
    /// Byte count declared in the frame header.
    pub byte_count: usize,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port` (e.g., `"10.0.0.1:5060"`).
    pub address: String,
    /// When this frame was logged.
    pub timestamp: Timestamp,
    /// Raw frame payload.
    pub content: Vec<u8>,
    /// Byte position of this frame's header in the stream the iterator read.
    pub offset: u64,
}

impl Frame {
    /// Direction, transport, address and timestamp as one borrowed value.
    pub fn meta(&self) -> FrameMeta<'_> {
        FrameMeta {
            direction: self.direction,
            transport: self.transport,
            address: &self.address,
            timestamp: self.timestamp,
        }
    }

    /// The remote address as a typed [`SocketAddr`], preserving family and
    /// port. `None` when the recorded address is not `ip:port`; the raw string
    /// remains in [`address`](Self::address).
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.meta().socket_addr()
    }
}

/// A reassembled SIP message (Level 2 output).
///
/// For TCP, consecutive frames from the same connection are concatenated and
/// split by Content-Length. For UDP, each frame becomes one message (1:1).
#[derive(Debug, Clone)]
pub struct SipMessage {
    /// Whether this message was received or sent.
    pub direction: Direction,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port`.
    pub address: String,
    /// Timestamp of the first frame in this message.
    pub timestamp: Timestamp,
    /// Reassembled message bytes (headers + body).
    pub content: Vec<u8>,
    /// Number of Level 1 frames that were reassembled into this message.
    pub frame_count: usize,
    /// Byte position of this message's first frame, the frame `timestamp` also
    /// comes from.
    pub offset: u64,
}

impl SipMessage {
    /// Direction, transport, address and timestamp as one borrowed value.
    pub fn meta(&self) -> FrameMeta<'_> {
        FrameMeta {
            direction: self.direction,
            transport: self.transport,
            address: &self.address,
            timestamp: self.timestamp,
        }
    }

    /// The remote address as a typed [`SocketAddr`], preserving family and
    /// port. `None` when the recorded address is not `ip:port`; the raw string
    /// remains in [`address`](Self::address).
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.meta().socket_addr()
    }
}

/// SIP request or response first line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessageType {
    /// `METHOD uri SIP/2.0`
    Request {
        /// SIP method (e.g., `"INVITE"`, `"BYE"`).
        method: String,
        /// Request URI.
        uri: String,
    },
    /// `SIP/2.0 code reason`
    Response {
        /// Status code (e.g., 200, 404).
        code: u16,
        /// Reason phrase (e.g., `"OK"`, `"Not Found"`).
        reason: String,
    },
}

impl fmt::Display for SipMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipMessageType::Request { method, uri } => write!(f, "{method} {uri}"),
            SipMessageType::Response { code, reason } => write!(f, "{code} {reason}"),
        }
    }
}

impl SipMessageType {
    /// Short description: the method name for requests, `"code reason"` for responses.
    pub fn summary(&self) -> Cow<'_, str> {
        match self {
            SipMessageType::Request { method, .. } => Cow::Borrowed(method),
            SipMessageType::Response { code, reason } => Cow::Owned(format!("{code} {reason}")),
        }
    }
}

/// Headers in wire order as `(name, value)` pairs. Names preserve original
/// casing; [`value`](Self::value) is the case-insensitive lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Every value recorded under `name`, case-insensitively, in wire order.
    /// Compact forms are not resolved, as for [`value`](Self::value).
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Case-insensitive header lookup, first match in wire order. Compact
    /// forms are not resolved: ask for the name the message is expected to
    /// carry.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl std::ops::Deref for Headers {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Headers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<(String, String)>> for Headers {
    fn from(headers: Vec<(String, String)>) -> Self {
        Headers(headers)
    }
}

impl FromIterator<(String, String)> for Headers {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Headers(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a (String, String);
    type IntoIter = std::slice::Iter<'a, (String, String)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A fully parsed SIP message (Level 3 output).
///
/// Provides typed access to the request/response line, headers, and body.
/// For JSON content types, [`body_text()`](Self::body_text) unescapes RFC 8259
/// string sequences. For multipart bodies, [`body_parts()`](Self::body_parts)
/// splits into individual MIME parts.
#[derive(Debug, Clone)]
pub struct ParsedSipMessage {
    /// Whether this message was received or sent.
    pub direction: Direction,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port`.
    pub address: String,
    /// When this message was logged.
    pub timestamp: Timestamp,
    /// Parsed request or response first line.
    pub message_type: SipMessageType,
    /// Message headers in wire order.
    pub headers: Headers,
    /// Raw body bytes after the `\r\n\r\n` header terminator.
    pub body: Vec<u8>,
    /// Number of Level 1 frames that were reassembled into this message.
    pub frame_count: usize,
    /// Byte position of this message's first frame, the frame `timestamp` also
    /// comes from.
    pub offset: u64,
}

/// A `message/sipfrag` body (RFC 3420): any prefix of a SIP message.
///
/// Unlike [`ParsedSipMessage`], every element is optional — a fragment may
/// carry a start line, headers, a body, or any combination, and needs no
/// trailing CRLF. It has no transport metadata of its own; that belongs to
/// the message carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipFragment {
    /// Request or status line, when the fragment begins with one.
    pub message_type: Option<SipMessageType>,
    /// Fragment headers in wire order.
    pub headers: Headers,
    /// Body bytes after the `\r\n\r\n` terminator, empty when absent.
    pub body: Vec<u8>,
}

impl SipFragment {
    /// Case-insensitive header lookup, first match in wire order.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.value(name)
    }

    /// Returns the Content-Type header value. Checks both `Content-Type` and
    /// the compact form `c`.
    pub fn content_type(&self) -> Option<&str> {
        value_or_compact(&self.headers, "Content-Type")
    }
}

/// A single part from a multipart MIME body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimePart {
    /// Part headers in wire order (e.g., Content-Type, Content-ID).
    pub headers: Headers,
    /// Part body bytes.
    pub body: Vec<u8>,
}

impl MimePart {
    /// Returns the Content-Type header value. Checks both `Content-Type` and
    /// the compact form `c`.
    pub fn content_type(&self) -> Option<&str> {
        value_or_compact(&self.headers, "Content-Type")
    }

    /// Case-insensitive header lookup, first match in wire order.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.value(name)
    }

    /// Returns the Content-ID header value, if present.
    pub fn content_id(&self) -> Option<&str> {
        self.header_value("Content-ID")
    }

    /// Returns the Content-Disposition header value, if present.
    pub fn content_disposition(&self) -> Option<&str> {
        self.header_value("Content-Disposition")
    }

    /// Returns the Content-Transfer-Encoding header value, if present. A value
    /// the caller does not recognize means the part's bytes are not what its
    /// media type describes.
    pub fn content_transfer_encoding(&self) -> Option<&str> {
        self.header_value("Content-Transfer-Encoding")
    }
}

impl ParsedSipMessage {
    /// Direction, transport, address and timestamp as one borrowed value.
    pub fn meta(&self) -> FrameMeta<'_> {
        FrameMeta {
            direction: self.direction,
            transport: self.transport,
            address: &self.address,
            timestamp: self.timestamp,
        }
    }

    /// The remote address as a typed [`SocketAddr`], preserving family and
    /// port. `None` when the recorded address is not `ip:port`; the raw string
    /// remains in [`address`](Self::address).
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.meta().socket_addr()
    }

    /// Returns the Call-ID header value. Checks both `Call-ID` and
    /// the compact form `i`.
    pub fn call_id(&self) -> Option<&str> {
        value_or_compact(&self.headers, "Call-ID")
    }

    /// Returns the Content-Type header value. Checks both `Content-Type` and
    /// the compact form `c`.
    pub fn content_type(&self) -> Option<&str> {
        value_or_compact(&self.headers, "Content-Type")
    }

    /// Returns the Content-Length header value as `usize`. Checks both
    /// `Content-Length` and the compact form `l`.
    pub fn content_length(&self) -> Option<usize> {
        value_or_compact(&self.headers, "Content-Length").and_then(|v| v.trim().parse().ok())
    }

    /// Returns the CSeq header value (e.g., `"1 INVITE"`).
    pub fn cseq(&self) -> Option<&str> {
        self.header_value("CSeq")
    }

    /// Returns the SIP method: from the request line for requests,
    /// or from the CSeq header for responses.
    pub fn method(&self) -> Option<&str> {
        match &self.message_type {
            SipMessageType::Request { method, .. } => Some(method),
            SipMessageType::Response { .. } => {
                self.cseq().and_then(|cs| cs.split_whitespace().nth(1))
            }
        }
    }

    /// Raw body bytes interpreted as UTF-8 (lossy). No processing is applied
    /// regardless of Content-Type.
    pub fn body_data(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Reconstruct the SIP message as wire-format bytes (first line + headers + body).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.message_type {
            SipMessageType::Request { method, uri } => {
                out.extend_from_slice(format!("{method} {uri} SIP/2.0\r\n").as_bytes());
            }
            SipMessageType::Response { code, reason } => {
                out.extend_from_slice(format!("SIP/2.0 {code} {reason}\r\n").as_bytes());
            }
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// Case-insensitive header lookup, first match in wire order. Compact
    /// forms are not resolved; the typed accessors above check both names.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.value(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_parsed(
        msg_type: SipMessageType,
        headers: Vec<(&str, &str)>,
        body: &[u8],
    ) -> ParsedSipMessage {
        ParsedSipMessage {
            direction: Direction::Recv,
            transport: Transport::Tcp,
            address: "10.0.0.1:5060".into(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            message_type: msg_type,
            headers: Headers(
                headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            body: body.to_vec(),
            frame_count: 1,
            offset: 0,
        }
    }

    fn make_frame(address: &str) -> Frame {
        Frame {
            direction: Direction::Recv,
            byte_count: 0,
            transport: Transport::Tcp,
            address: address.into(),
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content: Vec::new(),
            offset: 0,
        }
    }

    fn make_message(address: &str) -> SipMessage {
        SipMessage {
            direction: Direction::Recv,
            transport: Transport::Tcp,
            address: address.into(),
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content: Vec::new(),
            frame_count: 1,
            offset: 0,
        }
    }

    fn parsed_with_address(address: &str) -> ParsedSipMessage {
        let mut msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"",
        );
        msg.address = address.into();
        msg
    }

    #[test]
    fn socket_addr_ipv4() {
        let addr = make_frame("10.0.0.1:5060").socket_addr().unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 5060);
        assert_eq!(addr.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn socket_addr_ipv6_bracketed() {
        let addr = make_message("[2001:db8::1]:5061").socket_addr().unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 5061);
        assert_eq!(addr.ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn socket_addr_ipv4_bracketed() {
        let addr = make_frame("[198.51.100.7]:5060").socket_addr().unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 5060);
        assert_eq!(addr.ip().to_string(), "198.51.100.7");
    }

    #[test]
    fn socket_addr_on_parsed_message() {
        let addr = parsed_with_address("192.0.2.4:5080").socket_addr().unwrap();
        assert_eq!(addr.port(), 5080);
    }

    #[test]
    fn socket_addr_rejects_non_addresses() {
        for bad in [
            "345.678.987.654:5060",
            "10.0.0.1",
            "host.example.test:5060",
            "2001:db8::1:5060",
            "",
        ] {
            assert!(
                make_frame(bad).socket_addr().is_none(),
                "should not parse: {bad}"
            );
            assert!(make_message(bad).socket_addr().is_none());
            assert!(parsed_with_address(bad).socket_addr().is_none());
        }
    }

    #[test]
    fn to_bytes_request_no_body() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![("Call-ID", "test")],
            b"",
        );
        let bytes = msg.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("OPTIONS sip:host SIP/2.0\r\n"));
        assert!(text.contains("Call-ID: test\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn to_bytes_request_with_body() {
        let body = b"v=0\r\ns=-\r\n";
        let msg = make_parsed(
            SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:host".into(),
            },
            vec![("Call-ID", "test")],
            body,
        );
        let bytes = msg.to_bytes();
        assert!(bytes.ends_with(body));
    }

    #[test]
    fn to_bytes_response() {
        let msg = make_parsed(
            SipMessageType::Response {
                code: 200,
                reason: "OK".into(),
            },
            vec![("Call-ID", "resp-test")],
            b"",
        );
        let bytes = msg.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
    }

    #[test]
    fn body_data_valid_utf8() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"hello world",
        );
        assert_eq!(&*msg.body_data(), "hello world");
    }

    #[test]
    fn body_data_empty() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"",
        );
        assert_eq!(&*msg.body_data(), "");
    }

    #[test]
    fn body_data_binary() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            &[0xFF, 0xFE],
        );
        assert!(msg.body_data().contains('\u{FFFD}'));
    }

    #[test]
    fn body_data_preserves_json_escapes() {
        let raw = br#"{"key":"value\nwith\\escapes"}"#;
        let msg = make_parsed(
            SipMessageType::Request {
                method: "NOTIFY".into(),
                uri: "sip:host".into(),
            },
            vec![("Content-Type", "application/json")],
            raw,
        );
        assert_eq!(
            msg.body_data().as_ref(),
            r#"{"key":"value\nwith\\escapes"}"#,
            "body_data() must preserve raw escapes"
        );
    }
}
