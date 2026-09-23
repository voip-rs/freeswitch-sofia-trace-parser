use std::fmt;
use std::io::Read;

use memchr::memmem;
use tracing::{debug, trace};

use crate::finders::BOUNDARY;
use crate::types::{
    Direction, Frame, ParseStats, SkipReason, SkipTracking, Timestamp, Transport, UnparsedRegion,
};

const RECV_PREFIX: &[u8] = b"recv ";
const SENT_PREFIX: &[u8] = b"sent ";
/// Maximum skip size classified as a partial first frame.
/// Based on IP max datagram size (65535) plus the `\x0B\n` boundary (2 bytes).
const MAX_PARTIAL_FRAME: usize = 65537;

/// Errors produced during frame parsing (Level 1) and SIP parsing (Level 3).
///
/// Returned as `Iterator::Item = Result<T, ParseError>`. The caller decides
/// whether to skip, log, or fail on each error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// Frame header is malformed (e.g., missing colon, bad timestamp).
    InvalidHeader(String),
    /// Reassembled content is not a valid SIP message.
    InvalidMessage(String),
    /// Whitespace-only content from TLS/TCP keep-alive probes (RFC 5626).
    /// Not a parse failure; can be safely ignored.
    TransportNoise {
        /// Number of whitespace bytes.
        bytes: usize,
        /// Transport of the connection that produced the noise.
        transport: Transport,
        /// Remote address of the connection.
        address: String,
    },
    /// Underlying reader returned an I/O error.
    Io(std::io::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidHeader(msg) => write!(f, "invalid frame header: {msg}"),
            ParseError::InvalidMessage(msg) => write!(f, "invalid SIP message: {msg}"),
            ParseError::TransportNoise {
                bytes,
                transport,
                address,
            } => write!(
                f,
                "transport noise: {bytes} bytes of non-SIP data from {transport}/{address}"
            ),
            ParseError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

fn digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        _ => None,
    }
}

/// Parse up to `MAX_DIGITS` ASCII digits; a value the target type cannot hold
/// is `None`, as is any non-digit byte.
fn parse_digits<const MAX_DIGITS: usize, T: TryFrom<u64>>(bytes: &[u8]) -> Option<T> {
    if bytes.is_empty() || bytes.len() > MAX_DIGITS {
        return None;
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = val.checked_mul(10)?.checked_add(u64::from(digit(b)?))?;
    }
    T::try_from(val).ok()
}

/// Parse timestamp from bytes: either `HH:MM:SS.usec` or `YYYY-MM-DD HH:MM:SS.usec`
fn parse_timestamp(bytes: &[u8]) -> Option<Timestamp> {
    // Try full datetime first: YYYY-MM-DD HH:MM:SS.usec (min 26 bytes)
    if bytes.len() >= 26 && bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b' ' {
        let year = parse_digits::<5, u16>(&bytes[0..4])?;
        let month = parse_digits::<3, u8>(&bytes[5..7])?;
        let day = parse_digits::<3, u8>(&bytes[8..10])?;
        let ts = parse_time_part(&bytes[11..])?;
        return Some(Timestamp::DateTime {
            year,
            month,
            day,
            hour: ts.0,
            min: ts.1,
            sec: ts.2,
            usec: ts.3,
        });
    }
    // Time-only: HH:MM:SS.usec (min 15 bytes)
    let (hour, min, sec, usec) = parse_time_part(bytes)?;
    Some(Timestamp::TimeOnly {
        hour,
        min,
        sec,
        usec,
    })
}

/// Parse `HH:MM:SS.usec` from bytes, returns (hour, min, sec, usec)
fn parse_time_part(bytes: &[u8]) -> Option<(u8, u8, u8, u32)> {
    if bytes.len() < 15 {
        return None;
    }
    if bytes[2] != b':' || bytes[5] != b':' || bytes[8] != b'.' {
        return None;
    }
    let hour = parse_digits::<3, u8>(&bytes[0..2])?;
    let min = parse_digits::<3, u8>(&bytes[3..5])?;
    let sec = parse_digits::<3, u8>(&bytes[6..8])?;
    let usec = parse_digits::<10, u32>(&bytes[9..15])?;
    Some((hour, min, sec, usec))
}

/// Fields of one frame header line.
#[derive(Debug)]
pub struct FrameHeader {
    /// Whether FreeSWITCH received or sent the frame.
    pub direction: Direction,
    /// Content length declared by the header.
    pub byte_count: usize,
    /// Transport the frame travelled over.
    pub transport: Transport,
    /// Remote address, as written in the header.
    pub address: String,
    /// Time the frame was written.
    pub timestamp: Timestamp,
    /// Header length in bytes, including the trailing `\n`.
    pub header_len: usize,
}

/// Parse a frame header line from `&[u8]`.
///
/// Expected format:
/// `(recv|sent) <N> bytes (from|to) <transport>/<address> at <timestamp>:\n`
pub fn parse_frame_header(data: &[u8]) -> Result<FrameHeader, ParseError> {
    let newline_pos = memchr::memchr(b'\n', data)
        .ok_or_else(|| ParseError::InvalidHeader("no newline in header".into()))?;
    let line = &data[..newline_pos];
    // Strip trailing \r if present
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    // Must end with ':'
    let line = line
        .strip_suffix(b":")
        .ok_or_else(|| ParseError::InvalidHeader("header does not end with ':'".into()))?;

    // Direction — both "recv " and "sent " are 5 bytes
    let direction = if line.starts_with(RECV_PREFIX) {
        Direction::Recv
    } else if line.starts_with(SENT_PREFIX) {
        Direction::Sent
    } else {
        return Err(ParseError::InvalidHeader(
            "expected 'recv' or 'sent'".into(),
        ));
    };
    let mut pos = 5;

    // Byte count: digits until ' '
    let space = memchr::memchr(b' ', &line[pos..])
        .ok_or_else(|| ParseError::InvalidHeader("no space after byte count".into()))?;
    let byte_count = parse_digits::<10, usize>(&line[pos..pos + space])
        .ok_or_else(|| ParseError::InvalidHeader("invalid byte count".into()))?;
    pos += space + 1;

    // " bytes from/to "
    let expected_recv = b"bytes from ";
    let expected_sent = b"bytes to ";
    if direction == Direction::Recv {
        if !line[pos..].starts_with(expected_recv) {
            return Err(ParseError::InvalidHeader("expected 'bytes from '".into()));
        }
        pos += expected_recv.len();
    } else {
        if !line[pos..].starts_with(expected_sent) {
            return Err(ParseError::InvalidHeader("expected 'bytes to '".into()));
        }
        pos += expected_sent.len();
    }

    // Transport: tcp/ udp/ tls/ wss/
    let transport = if line[pos..].starts_with(b"tcp/") {
        pos += 4;
        Transport::Tcp
    } else if line[pos..].starts_with(b"udp/") {
        pos += 4;
        Transport::Udp
    } else if line[pos..].starts_with(b"tls/") {
        pos += 4;
        Transport::Tls
    } else if line[pos..].starts_with(b"wss/") {
        pos += 4;
        Transport::Wss
    } else {
        return Err(ParseError::InvalidHeader("unknown transport".into()));
    };

    // Address: until " at "
    let at_marker = b" at ";
    let at_pos = memmem::find(&line[pos..], at_marker)
        .ok_or_else(|| ParseError::InvalidHeader("no ' at ' in header".into()))?;
    let address = String::from_utf8_lossy(&line[pos..pos + at_pos]).into_owned();
    pos += at_pos + at_marker.len();

    // Timestamp: rest of line (after stripping trailing ':' already done)
    let timestamp = parse_timestamp(&line[pos..])
        .ok_or_else(|| ParseError::InvalidHeader("invalid timestamp".into()))?;

    Ok(FrameHeader {
        direction,
        byte_count,
        transport,
        address,
        timestamp,
        header_len: newline_pos + 1,
    })
}

enum HeaderParse {
    Ok(FrameHeader),
    NeedMore,
    Invalid(ParseError),
}

enum SyncStep {
    Ready,
    End,
    Failed(ParseError),
}

enum HeaderStep {
    Got(FrameHeader),
    Restart,
    End,
    Failed(ParseError),
}

/// Distinguish a header still arriving from one the parser rejects.
fn classify_header(data: &[u8]) -> HeaderParse {
    match parse_frame_header(data) {
        Ok(header) => HeaderParse::Ok(header),
        Err(e) => {
            if memchr::memchr(b'\n', data).is_none() {
                HeaderParse::NeedMore
            } else {
                HeaderParse::Invalid(e)
            }
        }
    }
}

/// Check if data at given position looks like a valid frame header start.
/// Used to validate `\x0B\n` boundaries.
pub fn is_frame_header(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let starts_valid = data.starts_with(RECV_PREFIX) || data.starts_with(SENT_PREFIX);
    if !starts_valid {
        return false;
    }
    // Check that after direction there are digits followed by " bytes "
    let rest = &data[5..];
    let space = match memchr::memchr(b' ', rest) {
        Some(p) => p,
        None => return false,
    };
    if space == 0 || space > 10 {
        return false;
    }
    for &b in &rest[..space] {
        if !b.is_ascii_digit() {
            return false;
        }
    }
    rest[space..].starts_with(b" bytes ")
}

const READ_BUF_SIZE: usize = 32 * 1024;

/// Level 1 streaming parser: splits raw dump bytes into [`Frame`]s.
///
/// Reads from any [`Read`] source and yields frames delimited by `\x0B\n`
/// boundaries. Handles truncated first/last frames, file concatenation,
/// and garbage recovery.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::FrameIterator;
///
/// let file = File::open("profile.dump").unwrap();
/// for frame in FrameIterator::new(file) {
///     let frame = frame.unwrap();
///     println!("{} {} bytes {} {}",
///         frame.timestamp, frame.byte_count, frame.direction, frame.address);
/// }
/// ```
pub struct FrameIterator<R> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    frame_count: u64,
    offset: u64,
    stats: ParseStats,
    skip_tracking: SkipTracking,
}

impl<R: Read> FrameIterator<R> {
    /// Create a new frame iterator reading from the given source.
    pub fn new(reader: R) -> Self {
        FrameIterator {
            reader,
            buf: Vec::with_capacity(READ_BUF_SIZE * 2),
            eof: false,
            frame_count: 0,
            offset: 0,
            stats: ParseStats::default(),
            skip_tracking: SkipTracking::CountOnly,
        }
    }

    /// Enable capturing of skipped bytes (shorthand for
    /// [`SkipTracking::CaptureData`]); `false` selects
    /// [`SkipTracking::CountOnly`]. Whichever of this and
    /// [`skip_tracking`](Self::skip_tracking) is called last wins.
    pub fn capture_skipped(mut self, enable: bool) -> Self {
        self.skip_tracking = if enable {
            SkipTracking::CaptureData
        } else {
            SkipTracking::CountOnly
        };
        self
    }

    /// Set the level of detail for unparsed region tracking.
    pub fn skip_tracking(mut self, tracking: SkipTracking) -> Self {
        self.skip_tracking = tracking;
        self
    }

    /// Borrow the accumulated parse statistics.
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Level 2 records its own losses in the same accounting.
    pub(crate) fn stats_mut(&mut self) -> &mut ParseStats {
        &mut self.stats
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_unparsed(&mut self) -> Vec<UnparsedRegion> {
        self.stats.drain_regions()
    }

    fn consume(&mut self, n: usize) {
        self.buf.drain(..n);
        self.offset += n as u64;
    }

    fn consume_skipped(&mut self, n: usize, reason: SkipReason) {
        if self.skip_tracking != SkipTracking::CountOnly {
            let data = if self.skip_tracking == SkipTracking::CaptureData {
                Some(self.buf[..n].to_vec())
            } else {
                None
            };
            self.stats.unparsed_regions.push(UnparsedRegion {
                offset: self.offset,
                length: n as u64,
                reason,
                data,
            });
        }
        self.stats.bytes_skipped += n as u64;
        self.consume(n);
    }

    fn fill_buf(&mut self) -> Result<bool, std::io::Error> {
        if self.eof {
            return Ok(false);
        }
        let old_len = self.buf.len();
        self.buf.resize(old_len + READ_BUF_SIZE, 0);
        let n = self.reader.read(&mut self.buf[old_len..])?;
        self.buf.truncate(old_len + n);
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.stats.bytes_read += n as u64;
        Ok(true)
    }

    /// A SIP header terminator right before a frame boundary is the tail of a
    /// frame logrotate copied into both files.
    fn is_replay(&self, skipped: &[u8]) -> bool {
        if self.frame_count == 0 {
            return false;
        }
        skipped.ends_with(b"\r\n\r\n\x0B\n")
    }

    /// Find the next `\x0B\n` boundary that is followed by a valid frame header.
    fn find_boundary(&self, start: usize) -> Option<usize> {
        let mut search_from = start;
        loop {
            let pos = BOUNDARY.find(&self.buf[search_from..])?;
            let abs_pos = search_from + pos;
            let after = abs_pos + 2;
            if after >= self.buf.len() {
                // Boundary at very end — could be real, but we can't validate header yet
                // If EOF, accept it as boundary (content ends at \x0B)
                if self.eof {
                    return Some(abs_pos);
                }
                return None; // Need more data
            }
            if is_frame_header(&self.buf[after..]) {
                return Some(abs_pos);
            }
            // \x0B\n in content, not a boundary — skip past it
            trace!(
                offset = abs_pos,
                "found \\x0B\\n in content (not a boundary), skipping"
            );
            search_from = abs_pos + 2;
        }
    }

    /// Skip to the first valid frame header in the buffer (for partial first frames).
    fn skip_to_first_header(&mut self) -> Option<usize> {
        if is_frame_header(&self.buf) {
            return Some(0);
        }
        // Look for \x0B\n followed by a valid header
        let mut search_from = 0;
        loop {
            let pos = BOUNDARY.find(&self.buf[search_from..])?;
            let abs_pos = search_from + pos;
            let after = abs_pos + 2;
            if after < self.buf.len() && is_frame_header(&self.buf[after..]) {
                debug!(skipped_bytes = after, "skipped partial first frame");
                return Some(after);
            }
            search_from = abs_pos + 2;
        }
    }

    /// Drop a partial first frame so the buffer starts at a frame header.
    fn sync_to_first_header(&mut self) -> SyncStep {
        loop {
            match self.skip_to_first_header() {
                Some(offset) => {
                    if offset > 0 {
                        let reason = if offset <= MAX_PARTIAL_FRAME {
                            SkipReason::PartialFirstFrame
                        } else {
                            SkipReason::OversizedFrame
                        };
                        self.consume_skipped(offset, reason);
                    }
                    return SyncStep::Ready;
                }
                None => {
                    if self.eof {
                        debug!("no valid frame header found in entire input");
                        let remaining = self.buf.len();
                        if remaining > 0 {
                            self.consume_skipped(remaining, SkipReason::InvalidHeader);
                        }
                        return SyncStep::End;
                    }
                    if let Err(e) = self.fill_buf() {
                        return SyncStep::Failed(ParseError::Io(e));
                    }
                }
            }
        }
    }

    /// Drop `\n` and `\r\n` padding between frames.
    fn strip_padding(&mut self) {
        let mut strip = 0;
        while strip < self.buf.len() {
            if self.buf[strip] == b'\n' {
                strip += 1;
            } else if strip + 1 < self.buf.len()
                && self.buf[strip] == b'\r'
                && self.buf[strip + 1] == b'\n'
            {
                strip += 2;
            } else {
                break;
            }
        }
        if strip > 0 {
            self.consume(strip);
        }
    }

    /// Parse the header at the head of the buffer, reading more as it needs.
    fn read_header(&mut self) -> HeaderStep {
        loop {
            match classify_header(&self.buf) {
                HeaderParse::Ok(h) => return HeaderStep::Got(h),
                HeaderParse::NeedMore => {
                    if self.eof {
                        debug!("truncated frame header at EOF");
                        let remaining = self.buf.len();
                        if remaining > 0 {
                            self.consume_skipped(remaining, SkipReason::InvalidHeader);
                        }
                        return HeaderStep::End;
                    }
                    if let Err(e) = self.fill_buf() {
                        return HeaderStep::Failed(ParseError::Io(e));
                    }
                }
                HeaderParse::Invalid(e) => {
                    let header_preview: String = self
                        .buf
                        .iter()
                        .take(200)
                        .take_while(|&&b| b != b'\n')
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    if header_preview.starts_with("dump started at ") {
                        let skip = memchr::memchr(b'\n', &self.buf)
                            .map(|p| {
                                let mut end = p + 1;
                                while end < self.buf.len() && self.buf[end] == b'\n' {
                                    end += 1;
                                }
                                end
                            })
                            .unwrap_or(self.buf.len());
                        debug!(
                            header = %header_preview,
                            skipped_bytes = skip,
                            "skipped dump restart marker",
                        );
                        self.consume(skip);
                        return HeaderStep::Restart;
                    }
                    let skip = if let Some(b) = self.find_boundary(0) {
                        b + 2
                    } else {
                        memchr::memchr(b'\n', &self.buf)
                            .map(|p| p + 1)
                            .unwrap_or(self.buf.len())
                    };
                    let reason = self.classify_skip(skip);
                    self.consume_skipped(skip, reason);
                    return HeaderStep::Failed(e);
                }
            }
        }
    }

    /// Reason for dropping `skip` bytes that failed header parsing.
    fn classify_skip(&self, skip: usize) -> SkipReason {
        if self.buf.starts_with(RECV_PREFIX) || self.buf.starts_with(SENT_PREFIX) {
            SkipReason::InvalidHeader
        } else if skip > MAX_PARTIAL_FRAME {
            SkipReason::OversizedFrame
        } else if self.frame_count == 0 {
            SkipReason::PartialFirstFrame
        } else if self.is_replay(&self.buf[..skip]) {
            SkipReason::ReplayedFrame
        } else {
            SkipReason::MidStreamSkip
        }
    }

    /// Read one frame's content, from the header's end to the frame boundary.
    fn read_content(
        &mut self,
        header: FrameHeader,
        offset: u64,
    ) -> Option<Result<Frame, ParseError>> {
        let FrameHeader {
            direction,
            byte_count,
            transport,
            address,
            timestamp,
            header_len,
        } = header;
        let content_start = header_len;
        let expected_end = content_start + byte_count;

        // Find the boundary for this frame.
        // Strategy: first check at the expected position (content_start + byte_count),
        // then fall back to scanning. This handles file concatenation where \x0B\n
        // is followed by garbage from the next file's truncated first frame.
        let content = loop {
            // Ensure we have enough data to check the expected position, but
            // never buffer a declared count further than a frame can reach:
            // past that, boundary scanning takes over.
            let fill_to = (expected_end + 1).min(content_start + MAX_PARTIAL_FRAME);
            while self.buf.len() <= fill_to && !self.eof {
                if let Err(e) = self.fill_buf() {
                    return Some(Err(ParseError::Io(e)));
                }
            }

            // Check at expected position first (byte_count hint)
            if expected_end < self.buf.len() && self.buf[expected_end] == 0x0B {
                let has_newline =
                    expected_end + 1 < self.buf.len() && self.buf[expected_end + 1] == b'\n';
                let at_eof = expected_end + 1 >= self.buf.len() && self.eof;

                if has_newline || at_eof {
                    let content = self.buf[content_start..expected_end].to_vec();
                    let drain_to = if has_newline {
                        expected_end + 2
                    } else {
                        expected_end + 1
                    };
                    self.consume(drain_to);
                    self.frame_count += 1;
                    break content;
                }
            }

            // Fall back to scanning for \x0B\n + valid header
            if let Some(boundary_pos) = self.find_boundary(content_start) {
                let content = self.buf[content_start..boundary_pos].to_vec();
                let drain_to = boundary_pos + 2;
                self.consume(drain_to);
                self.frame_count += 1;

                if content.len() != byte_count {
                    debug!(
                        frame = self.frame_count,
                        expected = byte_count,
                        actual = content.len(),
                        "frame content size mismatch"
                    );
                }

                break content;
            }

            if self.eof {
                // Last frame — no trailing \x0B\n
                let end = if self.buf.last() == Some(&0x0B) {
                    self.buf.len() - 1
                } else {
                    self.buf.len()
                };
                let content = self.buf[content_start..end].to_vec();
                let len = self.buf.len();
                self.consume(len);
                self.frame_count += 1;

                if content.len() < byte_count {
                    let missing = byte_count - content.len();
                    debug!(
                        frame = self.frame_count,
                        expected = byte_count,
                        actual = content.len(),
                        missing,
                        "incomplete frame at EOF"
                    );
                    self.stats.incomplete_frames += 1;
                    self.stats.incomplete_frame_bytes += missing as u64;
                    if self.skip_tracking != SkipTracking::CountOnly {
                        self.stats.unparsed_regions.push(UnparsedRegion {
                            offset: self.offset,
                            length: missing as u64,
                            reason: SkipReason::IncompleteFrame,
                            data: None,
                        });
                    }
                } else if content.len() != byte_count {
                    debug!(
                        frame = self.frame_count,
                        expected = byte_count,
                        actual = content.len(),
                        "last frame content size mismatch"
                    );
                }

                break content;
            }

            if let Err(e) = self.fill_buf() {
                return Some(Err(ParseError::Io(e)));
            }
        };

        Some(Ok(Frame {
            direction,
            byte_count,
            transport,
            address,
            timestamp,
            content,
            offset,
        }))
    }
}

impl<R: Read> Iterator for FrameIterator<R> {
    type Item = Result<Frame, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let (header, start) = loop {
            if self.buf.is_empty() && !self.eof {
                if let Err(e) = self.fill_buf() {
                    return Some(Err(ParseError::Io(e)));
                }
            }
            if self.buf.is_empty() {
                return None;
            }

            if self.frame_count == 0 {
                match self.sync_to_first_header() {
                    SyncStep::Ready => {}
                    SyncStep::End => return None,
                    SyncStep::Failed(e) => return Some(Err(e)),
                }
            }

            self.strip_padding();
            if self.buf.is_empty() {
                continue;
            }

            // Before the header is consumed: buf[0] sits at this offset, so a
            // frame's position is its header's, not its content's.
            let start = self.offset;
            match self.read_header() {
                HeaderStep::Got(header) => break (header, start),
                HeaderStep::Restart => continue,
                HeaderStep::End => return None,
                HeaderStep::Failed(e) => return Some(Err(e)),
            }
        };

        self.read_content(header, start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SkipTracking;

    #[test]
    fn parse_recv_ipv4_tcp() {
        let header = b"recv 100 bytes from tcp/192.168.1.1:5060 at 00:00:01.350874:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(h.direction, Direction::Recv);
        assert_eq!(h.byte_count, 100);
        assert_eq!(h.transport, Transport::Tcp);
        assert_eq!(h.address, "192.168.1.1:5060");
        assert_eq!(
            h.timestamp,
            Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 1,
                usec: 350874
            }
        );
        assert_eq!(h.header_len, header.len());
    }

    #[test]
    fn parse_recv_ipv6_tcp() {
        let header = b"recv 1440 bytes from tcp/[2001:4958:10:14::4]:30046 at 13:03:21.674883:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(h.direction, Direction::Recv);
        assert_eq!(h.byte_count, 1440);
        assert_eq!(h.transport, Transport::Tcp);
        assert_eq!(h.address, "[2001:4958:10:14::4]:30046");
        assert_eq!(
            h.timestamp,
            Timestamp::TimeOnly {
                hour: 13,
                min: 3,
                sec: 21,
                usec: 674883
            }
        );
    }

    #[test]
    fn parse_sent_ipv6_tcp() {
        let header = b"sent 681 bytes to tcp/[2001:4958:10:14::4]:30046 at 13:03:21.675500:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(h.direction, Direction::Sent);
        assert_eq!(h.byte_count, 681);
        assert_eq!(h.transport, Transport::Tcp);
        assert_eq!(h.address, "[2001:4958:10:14::4]:30046");
    }

    #[test]
    fn parse_recv_udp() {
        let header = b"recv 457 bytes from udp/10.0.0.1:5060 at 00:19:47.123456:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(h.direction, Direction::Recv);
        assert_eq!(h.transport, Transport::Udp);
    }

    #[test]
    fn parse_sent_tls() {
        let header = b"sent 500 bytes to tls/10.0.0.1:5061 at 12:00:00.000000:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(h.direction, Direction::Sent);
        assert_eq!(h.byte_count, 500);
        assert_eq!(h.transport, Transport::Tls);
    }

    #[test]
    fn parse_full_datetime_timestamp() {
        let header = b"recv 100 bytes from tcp/192.168.1.1:5060 at 2026-02-01 10:00:00.000000:\n";
        let h = parse_frame_header(header).unwrap();
        assert_eq!(
            h.timestamp,
            Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 1,
                hour: 10,
                min: 0,
                sec: 0,
                usec: 0
            }
        );
    }

    #[test]
    fn parse_invalid_header() {
        assert!(parse_frame_header(b"invalid header\n").is_err());
        assert!(
            parse_frame_header(b"recv abc bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n")
                .is_err()
        );
    }

    #[test]
    fn is_frame_header_valid() {
        assert!(is_frame_header(
            b"recv 100 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n"
        ));
        assert!(is_frame_header(
            b"sent 681 bytes to tcp/[::1]:5060 at 00:00:00.000000:\n"
        ));
        assert!(!is_frame_header(b"not a header"));
        assert!(!is_frame_header(b"recv abc bytes"));
        assert!(!is_frame_header(b""));
    }

    #[test]
    fn frame_iterator_single_frame() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[0].byte_count, 5);
    }

    #[test]
    fn frame_iterator_multiple_frames() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\nsent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[0].direction, Direction::Recv);
        assert_eq!(frames[1].content, b"world");
        assert_eq!(frames[1].direction, Direction::Sent);
    }

    /// A frame's offset is where its header begins, so a caller chaining two
    /// sources can say which one a frame came out of.
    #[test]
    fn frame_iterator_states_where_each_frame_began() {
        let first = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let second = b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n";
        let mut data = first.to_vec();
        data.extend_from_slice(second);

        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[1].offset, first.len() as u64);
    }

    /// The reader's chunking is not the frame's: a source handing back one byte
    /// per call must not move where a frame is reported to start.
    #[test]
    fn a_short_reader_does_not_move_a_frame_offset() {
        struct OneByteAtATime<'a>(&'a [u8]);
        impl std::io::Read for OneByteAtATime<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match (self.0.first(), buf.is_empty()) {
                    (Some(&b), false) => {
                        buf[0] = b;
                        self.0 = &self.0[1..];
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }

        let first = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let mut data = first.to_vec();
        data.extend_from_slice(
            b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n",
        );

        let frames: Vec<Frame> = FrameIterator::new(OneByteAtATime(&data))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[1].offset, first.len() as u64);
    }

    #[test]
    fn frame_iterator_vt_in_content() {
        // \x0B in content but not followed by valid header — should NOT split
        let mut data = Vec::new();
        data.extend_from_slice(b"recv 15 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n");
        data.extend_from_slice(b"he\x0B\nllo world!!");
        data.extend_from_slice(b"\x0B\n");
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"he\x0B\nllo world!!");
    }

    #[test]
    fn frame_iterator_eof_without_boundary() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }

    #[test]
    fn frame_iterator_eof_with_lone_vt() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }

    #[test]
    fn frame_iterator_partial_first_frame() {
        // Data starts with garbage, then a valid boundary + frame
        let mut data = Vec::new();
        data.extend_from_slice(b"partial garbage data");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }

    #[test]
    fn frame_iterator_truncated_last_frame() {
        // Complete frame followed by truncated frame at EOF (no \x0B\n)
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"sent 3 bytes to tcp/1.1.1.1:5060 at 00:00:01.000000:\nbye");
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"bye");
    }

    #[test]
    fn frame_iterator_file_concatenation() {
        // Simulates `cat dump.20 dump.21 | parser`
        // File 1: truncated start + valid frame + complete end
        // File 2: truncated start (no header) + valid frame
        let mut data = Vec::new();

        // File 1: starts with valid header
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(
            b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n",
        );

        // File 2: starts with truncated frame data (no header), then boundary, then valid frame
        data.extend_from_slice(b"some truncated SIP content from previous rotation\r\n\r\n");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 3 bytes from tcp/2.2.2.2:5060 at 01:00:00.000000:\nfoo\x0B\n",
        );

        let items: Vec<Result<Frame, ParseError>> = FrameIterator::new(&data[..]).collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"world");
        assert_eq!(frames[2].content, b"foo");
        assert_eq!(frames[2].address, "2.2.2.2:5060");
    }

    #[test]
    fn frame_iterator_file_concatenation_mid_stream_garbage() {
        // The join point between files produces garbage that looks like:
        // ...last_content\x0B\ntruncated_first_of_next_file\x0B\nvalid_header...
        // The truncated part is NOT a valid header, so recovery should skip it
        let mut data = Vec::new();

        // Last frame of file 1
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );

        // Truncated first frame of file 2 (mid-SIP content, no frame header)
        data.extend_from_slice(b"Content-Type: application/sdp\r\n\r\nv=0\r\n");
        data.extend_from_slice(b"\x0B\n");

        // Valid second frame of file 2
        data.extend_from_slice(b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n");

        let items: Vec<Result<Frame, ParseError>> = FrameIterator::new(&data[..]).collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"bar");
    }

    #[test]
    fn frame_iterator_empty_input() {
        let data: &[u8] = b"";
        let frames: Vec<Result<Frame, ParseError>> = FrameIterator::new(data).collect();
        assert!(frames.is_empty());
    }

    #[test]
    fn frame_iterator_only_garbage() {
        let data = b"this is not a SIP trace dump at all, just garbage text";
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let frames: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        assert!(frames.is_empty());
        let stats = iter.stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, data.len() as u64);
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(stats.unparsed_regions[0].reason, SkipReason::InvalidHeader);
    }

    #[test]
    fn frame_iterator_truncated_header_at_eof() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060";
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let frames: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        assert!(frames.is_empty());
        let stats = iter.stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, data.len() as u64);
    }

    #[test]
    fn frame_iterator_dump_marker_at_eof() {
        // A dump restart marker at the end of input (with trailing \n\n as in real dumps)
        // should be silently consumed, not returned as an error.
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"dump started at Thu Aug 22 11:38:11 2024\n\n\n");

        let frames: Vec<Result<Frame, ParseError>> = FrameIterator::new(&data[..]).collect();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_ok());
        assert_eq!(frames[0].as_ref().unwrap().content, b"hello");
    }

    #[test]
    fn frame_iterator_dump_marker_mid_stream() {
        // A dump restart marker between two valid frames (with trailing \n\n as in real dumps)
        // should be skipped, and both frames should parse successfully.
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"dump started at Thu Aug 22 11:38:11 2024\n\n\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/2.2.2.2:5060 at 00:00:01.000000:\nbye\x0B\n");

        let frames: Vec<Result<Frame, ParseError>> = FrameIterator::new(&data[..]).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_ref().unwrap().content, b"hello");
        assert_eq!(frames[1].as_ref().unwrap().content, b"bye");
    }

    #[test]
    fn frame_iterator_multiple_newlines_after_boundary() {
        // Multiple \n and \r\n between frames should all be stripped.
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"\n\r\n\n");
        data.extend_from_slice(
            b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n",
        );

        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"world");
    }

    #[test]
    fn stats_clean_input() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let mut iter = FrameIterator::new(&data[..]);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
        assert!(stats.unparsed_regions.is_empty());
    }

    #[test]
    fn stats_multiple_frames() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\nsent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n";
        let mut iter = FrameIterator::new(&data[..]);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
        assert!(stats.unparsed_regions.is_empty());
    }

    #[test]
    fn stats_partial_first_frame() {
        let mut data = Vec::new();
        data.extend_from_slice(b"partial garbage data");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        // "partial garbage data" + "\x0B\n" = 21 bytes skipped
        let skipped = b"partial garbage data\x0B\n".len() as u64;
        assert_eq!(stats.bytes_skipped, skipped);
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(stats.unparsed_regions[0].offset, 0);
        assert_eq!(stats.unparsed_regions[0].length, skipped);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::PartialFirstFrame
        );
        assert!(stats.unparsed_regions[0].data.is_none());
    }

    #[test]
    fn stats_partial_first_frame_capture() {
        let mut data = Vec::new();
        data.extend_from_slice(b"partial garbage data");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let mut iter = FrameIterator::new(&data[..]).capture_skipped(true);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        let region = &stats.unparsed_regions[0];
        assert_eq!(
            region.data.as_deref(),
            Some(b"partial garbage data\x0B\n".as_slice())
        );
    }

    #[test]
    fn stats_mid_stream_partial_frame() {
        // SIP content between valid frames (file concatenation scenario)
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"Content-Type: application/sdp\r\n\r\nv=0\r\n");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n");

        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        assert!(stats.bytes_skipped > 0);
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::MidStreamSkip
        );
    }

    #[test]
    fn stats_replayed_frame() {
        // Simulate logrotate: a frame's tail (SIP headers ending with \r\n\r\n\x0B\n)
        // appears between two valid frames at a file boundary.
        let frame1 = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let replay = b"Route: <sip:10.0.0.1:5060;lr>\r\nContent-Length: 0\r\n\r\n\x0B\n";
        let frame2 = b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n";

        let mut data = Vec::new();
        data.extend_from_slice(frame1);
        data.extend_from_slice(replay);
        data.extend_from_slice(frame2);

        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::ReplayedFrame
        );
    }

    #[test]
    fn stats_incomplete_frame_at_eof() {
        // Frame header says 100 bytes but only 20 bytes available before EOF
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"recv 100 bytes from tcp/2.2.2.2:5060 at 01:00:00.000000:\n");
        data.extend_from_slice(b"partial content only");
        // No \x0B\n boundary — EOF truncation

        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2, "truncated frame should still be returned");
        assert_eq!(frames[1].content, b"partial content only");
        assert_eq!(frames[1].byte_count, 100);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::IncompleteFrame
        );
    }

    #[test]
    fn stats_incomplete_frame_counted_under_count_only() {
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"recv 100 bytes from tcp/2.2.2.2:5060 at 01:00:00.000000:\n");
        data.extend_from_slice(b"partial content only");

        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::CountOnly);
        let _: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let stats = iter.stats();
        assert!(stats.unparsed_regions.is_empty());
        assert_eq!(stats.incomplete_frames, 1);
        assert_eq!(stats.incomplete_frame_bytes, 80);
    }

    #[test]
    fn stats_invalid_header_skip() {
        // Malformed frame header (starts with recv/sent but unparseable)
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"recv CORRUPT HEADER garbage\n");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n");

        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        assert!(stats.bytes_skipped > 0);
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::InvalidHeader
        );
    }

    #[test]
    fn stats_oversized_frame_at_start() {
        let mut data = Vec::new();
        data.resize(MAX_PARTIAL_FRAME + 1, b'x');
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::OversizedFrame
        );
    }

    #[test]
    fn stats_oversized_frame_mid_stream() {
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let garbage_len = MAX_PARTIAL_FRAME + 1;
        data.resize(data.len() + garbage_len, b'x');
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n");
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let items: Vec<Result<Frame, ParseError>> = iter.by_ref().collect();
        let frames: Vec<Frame> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::OversizedFrame
        );
    }

    #[test]
    fn overlong_byte_count_does_not_buffer_ahead() {
        let mut data = Vec::new();
        data.extend_from_slice(
            format!(
                "recv {} bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n",
                MAX_PARTIAL_FRAME * 10
            )
            .as_bytes(),
        );
        data.extend_from_slice(b"hello\x0B\n");
        while data.len() < MAX_PARTIAL_FRAME * 10 {
            data.extend_from_slice(
                b"sent 3 bytes to tcp/3.3.3.3:5060 at 02:00:00.000000:\nbar\x0B\n",
            );
        }

        let mut iter = FrameIterator::new(&data[..]);
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.content, b"hello");
        assert!(
            iter.buf.len() <= MAX_PARTIAL_FRAME + READ_BUF_SIZE,
            "buffered {} bytes on a byte_count ten times the frame",
            iter.buf.len()
        );
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.content, b"bar");
    }

    #[test]
    fn stats_partial_first_frame_within_limit() {
        // Content + \x0B\n boundary = MAX_PARTIAL_FRAME, should still be PartialFirstFrame
        let mut data = Vec::new();
        data.resize(MAX_PARTIAL_FRAME - 2, b'x');
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let mut iter = FrameIterator::new(&data[..]).skip_tracking(SkipTracking::TrackRegions);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        assert_eq!(stats.unparsed_regions.len(), 1);
        assert_eq!(
            stats.unparsed_regions[0].reason,
            crate::types::SkipReason::PartialFirstFrame
        );
    }

    #[test]
    fn stats_dump_restart_marker() {
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"dump started at Thu Aug 22 11:38:11 2024\n\n\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/2.2.2.2:5060 at 00:00:01.000000:\nbye\x0B\n");

        let mut iter = FrameIterator::new(&data[..]);
        let frames: Vec<Frame> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 2);
        let stats = iter.stats();
        // Dump restart marker is structural, not skipped
        assert_eq!(stats.bytes_skipped, 0);
        assert!(stats.unparsed_regions.is_empty());
    }

    #[test]
    fn stats_count_only_no_regions() {
        let mut data = Vec::new();
        data.extend_from_slice(b"partial garbage data");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        let mut iter = FrameIterator::new(&data[..]);
        let frames: Vec<_> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(frames.len(), 1);
        let stats = iter.stats();
        let skipped = b"partial garbage data\x0B\n".len() as u64;
        assert_eq!(stats.bytes_skipped, skipped);
        assert!(
            stats.unparsed_regions.is_empty(),
            "CountOnly should not accumulate regions"
        );
    }

    #[test]
    fn frame_iterator_trailing_newlines_at_eof() {
        // Trailing newlines after the last boundary at EOF should not cause errors.
        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"\n\n");

        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }
}
