use std::borrow::Cow;

use sip_header::extract_all_headers;

use crate::finders::CRLF;
use crate::frame::ParseError;
use crate::message::MessageIterator;
use crate::sip::content_type::{extract_boundary, normalize_media_type};
use crate::sip::json::unescape_json_body;
use crate::sip::multipart::{is_multipart_type, split_multipart};
use crate::startline::{bytes_to_str, parse_first_line, parse_first_line_ref, StartLineRef};
use crate::types::{
    value_or_compact, Headers, MimePart, ParseStats, ParsedSipMessage, SipFragment, SipMessage,
    SkipTracking, UnparsedRegion,
};

pub(crate) mod content_type;
mod fragment;
mod json;
mod multipart;
#[cfg(test)]
pub(crate) mod test_support;

pub use content_type::is_json_content_type;
pub use fragment::parse_sipfrag;

/// Everything a SIP header block plus a body answers, written once. The three
/// carriers each expose these as inherent methods that delegate here, so a
/// per-part loop cannot meet a carrier that answers one of them differently.
pub(crate) trait HasHeaders {
    fn headers(&self) -> &Headers;

    fn body(&self) -> &[u8];

    fn content_type(&self) -> Option<&str> {
        value_or_compact(self.headers(), "Content-Type")
    }

    fn media_type(&self) -> Option<Cow<'_, str>> {
        self.content_type().map(normalize_media_type)
    }

    fn is_multipart(&self) -> bool {
        is_multipart_type(self.content_type())
    }

    fn multipart_boundary(&self) -> Option<&str> {
        extract_boundary(self.content_type()?)
    }

    fn body_parts(&self) -> Option<Vec<MimePart>> {
        split_multipart(self.content_type(), self.body())
    }

    fn body_text(&self) -> Cow<'_, str> {
        match self.content_type() {
            Some(ct) if is_json_content_type(ct) => Cow::Owned(unescape_json_body(self.body())),
            _ => String::from_utf8_lossy(self.body()),
        }
    }

    fn json_field(&self, key: &str) -> Option<String> {
        let ct = self.content_type()?;
        if !is_json_content_type(ct) {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(self.body()).ok()?;
        let obj = value.as_object()?;
        obj.get(key)?.as_str().map(|s| s.to_string())
    }
}

impl HasHeaders for ParsedSipMessage {
    fn headers(&self) -> &Headers {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl HasHeaders for MimePart {
    fn headers(&self) -> &Headers {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl HasHeaders for SipFragment {
    fn headers(&self) -> &Headers {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl SipMessage {
    /// Parse this reassembled message into a [`ParsedSipMessage`] with typed
    /// access to the request/status line, headers, and body.
    pub fn parse(&self) -> Result<ParsedSipMessage, ParseError> {
        parse_sip_message(self)
    }

    /// The SIP method read straight from the reassembled bytes: the request
    /// line for requests, the CSeq header for responses. This is the answer
    /// [`ParsedSipMessage::method`] gives, without parsing the message.
    ///
    /// `None` whenever the bytes leave it in doubt — an invalid start line, a
    /// response carrying no CSeq, or a CSeq value that is folded or not plain
    /// ASCII. Filtering on this therefore drops only what it has classified,
    /// and a message it does classify is one [`parse`](Self::parse) accepts.
    pub fn method(&self) -> Option<&str> {
        let first_line_end = CRLF.find(&self.content)?;
        match parse_first_line_ref(&self.content[..first_line_end]).ok()? {
            StartLineRef::Request { method, .. } => std::str::from_utf8(method).ok(),
            StartLineRef::Response { .. } => {
                let (headers, _) = split_headers_body(&self.content, first_line_end + 2);
                cseq_method(headers)
            }
        }
    }
}

/// Read the CSeq method the way `sip_header::extract_all_headers` reads
/// headers, so the two cannot disagree: LF-separated lines, one optional
/// trailing CR, stopping at the first blank line — which a bare LF pair can
/// produce well before the `\r\n\r\n` that bounds the block.
fn cseq_method(headers: &[u8]) -> Option<&str> {
    let mut lines = headers.split(|&b| b == b'\n').peekable();

    while let Some(line) = lines.next() {
        let line = match line {
            [rest @ .., b'\r'] => rest,
            rest => rest,
        };
        if line.is_empty() {
            return None;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            continue;
        }
        let Some(colon) = memchr::memchr(b':', line) else {
            continue;
        };
        let mut name = &line[..colon];
        while let [rest @ .., b' ' | b'\t'] = name {
            name = rest;
        }
        if name.contains(&b' ') || !name.eq_ignore_ascii_case(b"CSeq") {
            continue;
        }

        if matches!(lines.peek(), Some([b' ' | b'\t', ..])) {
            return None;
        }
        let value = &line[colon + 1..];
        if !value.is_ascii() {
            return None;
        }
        return std::str::from_utf8(value)
            .ok()?
            .split_ascii_whitespace()
            .nth(1);
    }

    None
}

/// Level 3 streaming parser: wraps [`MessageIterator`] and parses each
/// reassembled message into a [`ParsedSipMessage`].
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::ParsedMessageIterator;
///
/// let file = File::open("profile.dump").unwrap();
/// for result in ParsedMessageIterator::new(file) {
///     let msg = result.unwrap();
///     if let Some(parts) = msg.body_parts() {
///         for part in &parts {
///             println!("  {} ({} bytes)",
///                 part.content_type().unwrap_or("unknown"), part.body.len());
///         }
///     }
/// }
/// ```
pub struct ParsedMessageIterator<R> {
    inner: MessageIterator<R>,
}

impl<R: std::io::Read> ParsedMessageIterator<R> {
    /// Create a new parsed message iterator reading from the given source.
    pub fn new(reader: R) -> Self {
        ParsedMessageIterator {
            inner: MessageIterator::new(reader),
        }
    }

    /// Enable capturing of skipped bytes in the underlying frame parser;
    /// `false` selects [`SkipTracking::CountOnly`]. Whichever of this and
    /// [`skip_tracking`](Self::skip_tracking) is called last wins.
    pub fn capture_skipped(mut self, enable: bool) -> Self {
        self.inner = self.inner.capture_skipped(enable);
        self
    }

    /// Set the level of detail for unparsed region tracking.
    pub fn skip_tracking(mut self, tracking: SkipTracking) -> Self {
        self.inner = self.inner.skip_tracking(tracking);
        self
    }

    /// Borrow the accumulated parse statistics.
    pub fn parse_stats(&self) -> &ParseStats {
        self.inner.parse_stats()
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_unparsed(&mut self) -> Vec<UnparsedRegion> {
        self.inner.drain_unparsed()
    }
}

impl<R: std::io::Read> Iterator for ParsedMessageIterator<R> {
    type Item = Result<ParsedSipMessage, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let msg = match self.inner.next()? {
            Ok(m) => m,
            Err(e) => return Some(Err(e)),
        };
        Some(msg.parse())
    }
}

fn content_preview(content: &[u8], max_len: usize) -> String {
    let len = content.len().min(max_len);
    let s = String::from_utf8_lossy(&content[..len]);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    if content.len() > max_len {
        out.push_str("...");
    }
    out
}

fn parse_sip_message(msg: &SipMessage) -> Result<ParsedSipMessage, ParseError> {
    let content = &msg.content;

    if content
        .iter()
        .all(|&b| matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
    {
        return Err(ParseError::TransportNoise {
            bytes: content.len(),
            transport: msg.transport,
            address: msg.address.clone(),
        });
    }

    parse_sip_content(msg, content).map_err(|e| {
        let reason = match e {
            ParseError::InvalidMessage(reason) => reason,
            other => return other,
        };
        let preview = content_preview(content, 200);
        ParseError::InvalidMessage(format!(
            "{} {}/{} at {} ({} frames, {} bytes): {reason}\n  {preview}",
            msg.direction,
            msg.transport,
            msg.address,
            msg.timestamp,
            msg.frame_count,
            content.len(),
        ))
    })
}

fn parse_sip_content(msg: &SipMessage, content: &[u8]) -> Result<ParsedSipMessage, ParseError> {
    // Find end of first line
    let first_line_end = CRLF
        .find(content)
        .ok_or_else(|| ParseError::InvalidMessage("no CRLF found".into()))?;
    let first_line = &content[..first_line_end];

    let message_type = parse_first_line(first_line)?;

    let (header_bytes, body) = split_headers_body(content, first_line_end + 2);
    let headers = parse_headers(header_bytes);

    Ok(ParsedSipMessage {
        direction: msg.direction,
        transport: msg.transport,
        address: msg.address.clone(),
        timestamp: msg.timestamp,
        offset: msg.offset,
        message_type,
        headers,
        body: body.to_vec(),
        frame_count: msg.frame_count,
    })
}

pub(crate) fn parse_headers(data: &[u8]) -> Headers {
    Headers::from(extract_all_headers(&bytes_to_str(data)))
}

/// Split at the first blank line, under the rule `sip_header` reads headers by:
/// lines end at LF, one trailing CR is stripped, the first empty line ends the
/// block. No blank line means headers run to the end, no body.
pub(crate) fn split_headers_body(data: &[u8], headers_start: usize) -> (&[u8], &[u8]) {
    let start = headers_start.min(data.len());
    let mut pos = start;
    while let Some(rel) = memchr::memchr(b'\n', &data[pos..]) {
        let line = match &data[pos..pos + rel] {
            [rest @ .., b'\r'] => rest,
            rest => rest,
        };
        if line.is_empty() {
            return (&data[start..pos], &data[pos + rel + 1..]);
        }
        pos += rel + 1;
    }
    (&data[start..], &[][..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::test_support::make_sip_message;
    use crate::types::{Direction, SipMessage, SipMessageType, Timestamp, Transport};

    /// `method()` may answer `None` for anything, but never a method the full
    /// parse disagrees with.
    fn assert_agrees_with_parse(content: &[u8]) {
        let msg = make_sip_message(content);
        if let Some(cheap) = msg.method() {
            let parsed = msg.parse().expect("classified message must parse");
            assert_eq!(Some(cheap), parsed.method());
        }
    }

    #[test]
    fn method_from_request_line() {
        let msg = make_sip_message(b"INVITE sip:user@host SIP/2.0\r\nCSeq: 1 INVITE\r\n\r\n");
        assert_eq!(msg.method(), Some("INVITE"));
    }

    #[test]
    fn method_from_response_cseq() {
        let msg = make_sip_message(b"SIP/2.0 200 OK\r\nVia: x\r\nCSeq: 42 OPTIONS\r\n\r\n");
        assert_eq!(msg.method(), Some("OPTIONS"));
    }

    #[test]
    fn method_from_response_cseq_name_variants() {
        let lower = make_sip_message(b"SIP/2.0 200 OK\r\ncseq: 1 BYE\r\n\r\n");
        assert_eq!(lower.method(), Some("BYE"));

        let padded = make_sip_message(b"SIP/2.0 200 OK\r\nCSeq \t: 1 BYE\r\n\r\n");
        assert_eq!(padded.method(), Some("BYE"));

        let tabbed = make_sip_message(b"SIP/2.0 200 OK\r\nCSeq:\t1\tBYE\r\n\r\n");
        assert_eq!(tabbed.method(), Some("BYE"));
    }

    #[test]
    fn method_takes_first_cseq_in_wire_order() {
        let msg = make_sip_message(b"SIP/2.0 200 OK\r\nCSeq: 1 BYE\r\nCSeq: 2 INVITE\r\n\r\n");
        assert_eq!(msg.method(), Some("BYE"));
        assert_agrees_with_parse(b"SIP/2.0 200 OK\r\nCSeq: 1 BYE\r\nCSeq: 2 INVITE\r\n\r\n");
    }

    #[test]
    fn method_none_on_folded_cseq() {
        let content = b"SIP/2.0 200 OK\r\nCSeq: 1\r\n INVITE\r\n\r\n";
        assert_eq!(make_sip_message(content).method(), None);
        assert_agrees_with_parse(content);
    }

    #[test]
    fn method_none_without_cseq() {
        let msg = make_sip_message(b"SIP/2.0 200 OK\r\nVia: x\r\n\r\nCSeq: 1 INVITE\r\n");
        assert_eq!(msg.method(), None);
    }

    #[test]
    fn method_none_on_malformed_start_line() {
        assert_eq!(
            make_sip_message(b"INVITE sip:user@host SIP/3.0\r\nCSeq: 1 INVITE\r\n\r\n").method(),
            None
        );
        assert_eq!(
            make_sip_message(b"garbage\r\nCSeq: 1 INVITE\r\n\r\n").method(),
            None
        );
        assert_eq!(make_sip_message(b"\r\n\r\n").method(), None);
    }

    /// The header crate stops at the first blank line as it splits on LF, so a
    /// bare LF pair ends the header block earlier than `\r\n\r\n` does.
    #[test]
    fn method_none_when_cseq_follows_lf_blank_line() {
        let content = b"SIP/2.0 200 OK\r\nVia: x\n\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let parsed = make_sip_message(content).parse().unwrap();
        assert_eq!(
            parsed.method(),
            None,
            "precondition: the parsed side cannot see this CSeq"
        );
        assert_eq!(make_sip_message(content).method(), None);

        assert_eq!(parsed.headers.len(), 1);
        assert_eq!(parsed.header_value("Via"), Some("x"));
        assert_eq!(parsed.body, b"CSeq: 1 OPTIONS\r\n\r\n");

        let start_line = b"SIP/2.0 200 OK\r\n".len();
        let (headers, body) = split_headers_body(content, start_line);
        assert_eq!(headers, b"Via: x\n");
        assert_eq!(
            start_line + headers.len() + b"\r\n".len() + body.len(),
            content.len(),
            "every byte lands in the start line, the headers, the blank line or the body"
        );
    }

    /// `ParsedSipMessage::method` splits the CSeq value on Unicode whitespace.
    #[test]
    fn method_none_on_non_ascii_cseq_value() {
        let content = "SIP/2.0 200 OK\r\nCSeq: 1\u{a0}2 OPTIONS\r\n\r\n".as_bytes();
        assert_eq!(make_sip_message(content).method(), None);
        assert_agrees_with_parse(content);
    }

    #[test]
    fn method_none_on_transport_noise() {
        assert_eq!(make_sip_message(b"\r\n\r\n\r\n").method(), None);
        assert_eq!(make_sip_message(b"").method(), None);
    }

    #[test]
    fn non_utf8_header_value_falls_back_to_lossy() {
        let mut content = b"OPTIONS sip:host SIP/2.0\r\nSubject: caf".to_vec();
        content.push(0xE9);
        content.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");

        let parsed = make_sip_message(&content).parse().unwrap();
        assert_eq!(parsed.header_value("Subject"), Some("caf\u{fffd}"));
    }

    #[test]
    fn parse_stats_delegates() {
        let content =
            b"OPTIONS sip:host SIP/2.0\r\nCall-ID: stats-test\r\nContent-Length: 0\r\n\r\n";
        let header = format!(
            "recv {} bytes from udp/10.0.0.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");

        let mut iter = ParsedMessageIterator::new(&data[..]);
        let parsed: Vec<_> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(parsed.len(), 1);
        let stats = iter.parse_stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
    }

    #[test]
    fn parse_options_request() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
            From: <sip:user@host>;tag=abc\r\n\
            To: <sip:user@host>\r\n\
            Call-ID: test-call-id@host\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:user@host".into()
            }
        );
        assert_eq!(parsed.call_id(), Some("test-call-id@host"));
        assert_eq!(parsed.cseq(), Some("1 OPTIONS"));
        assert_eq!(parsed.content_length(), Some(0));
        assert_eq!(parsed.method(), Some("OPTIONS"));
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_200_ok_response() {
        let content = b"SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060\r\n\
            Call-ID: resp-id@host\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            }
        );
        assert_eq!(parsed.method(), Some("INVITE"));
    }

    #[test]
    fn parse_100_trying() {
        let content = b"SIP/2.0 100 Trying\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060\r\n\
            Call-ID: trying-id\r\n\
            CSeq: 42 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 100,
                reason: "Trying".into()
            }
        );
        assert_eq!(parsed.method(), Some("INVITE"));
    }

    #[test]
    fn parse_invite_with_sdp_body() {
        let body = b"v=0\r\no=- 123 456 IN IP4 10.0.0.1\r\ns=-\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:user@host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: invite-body@host\r\n");
        content.extend_from_slice(b"CSeq: 1 INVITE\r\n");
        content.extend_from_slice(b"Content-Type: application/sdp\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.method(), Some("INVITE"));
        assert_eq!(parsed.content_type(), Some("application/sdp"));
        assert_eq!(parsed.content_length(), Some(body.len()));
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn parse_notify_with_json_body() {
        let body = br#"{"event":"AbandonedCall","id":"123"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: notify-json@host\r\n");
        content.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.method(), Some("NOTIFY"));
        assert_eq!(parsed.content_type(), Some("application/json"));
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn compact_headers() {
        let content = b"NOTIFY sip:user@host SIP/2.0\r\n\
            i: compact-call-id\r\n\
            l: 0\r\n\
            c: text/plain\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.call_id(), Some("compact-call-id"));
        assert_eq!(parsed.content_length(), Some(0));
        assert_eq!(parsed.content_type(), Some("text/plain"));
    }

    #[test]
    fn header_folding() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060\r\n\
            Subject: this is a long\r\n \
            folded header value\r\n\
            Call-ID: fold-test\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let subject = parsed
            .headers
            .iter()
            .find(|(k, _)| k == "Subject")
            .map(|(_, v)| v.as_str());
        assert_eq!(subject, Some("this is a long folded header value"));
        assert_eq!(parsed.call_id(), Some("fold-test"));
    }

    #[test]
    fn folded_header_no_crlf_leak() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Subject: line1\r\n \
            line2\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        let subject = parsed.headers.iter().find(|(k, _)| k == "Subject").unwrap();
        assert!(!subject.1.contains('\r'), "CRLF leaked: {:?}", subject.1);
        assert!(!subject.1.contains('\n'), "LF leaked: {:?}", subject.1);
        assert_eq!(subject.1, "line1 line2");
    }

    #[test]
    fn no_body() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID: nobody\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn no_blank_line_no_body() {
        // Malformed: no \r\n\r\n separator
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID: no-blank\r\n\
            Content-Length: 0";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert!(parsed.body.is_empty());
        assert_eq!(parsed.call_id(), Some("no-blank"));
    }

    #[test]
    fn preserves_metadata() {
        let content = b"REGISTER sip:host SIP/2.0\r\n\
            Call-ID: meta-test\r\n\
            \r\n";
        let msg = SipMessage {
            direction: Direction::Sent,
            transport: Transport::Tls,
            address: "[2001:db8::1]:5061".into(),
            timestamp: Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 12,
                hour: 10,
                min: 30,
                sec: 0,
                usec: 123456,
            },
            content: content.to_vec(),
            offset: 0,
            frame_count: 3,
        };
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.direction, Direction::Sent);
        assert_eq!(parsed.transport, Transport::Tls);
        assert_eq!(parsed.address, "[2001:db8::1]:5061");
        assert_eq!(parsed.frame_count, 3);
        assert_eq!(
            parsed.timestamp,
            Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 12,
                hour: 10,
                min: 30,
                sec: 0,
                usec: 123456,
            }
        );
    }

    #[test]
    fn multiple_same_name_headers() {
        let content = b"INVITE sip:host SIP/2.0\r\n\
            Via: SIP/2.0/UDP proxy1:5060\r\n\
            Via: SIP/2.0/UDP proxy2:5060\r\n\
            Record-Route: <sip:proxy1>\r\n\
            Record-Route: <sip:proxy2>\r\n\
            Call-ID: multi-hdr\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let via_count = parsed.headers.iter().filter(|(k, _)| k == "Via").count();
        assert_eq!(via_count, 2);

        let rr_count = parsed
            .headers
            .iter()
            .filter(|(k, _)| k == "Record-Route")
            .count();
        assert_eq!(rr_count, 2);
    }

    #[test]
    fn header_ordering_preserved() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Via: v1\r\n\
            From: f1\r\n\
            To: t1\r\n\
            Call-ID: order-test\r\n\
            CSeq: 1 OPTIONS\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let names: Vec<&str> = parsed.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Via", "From", "To", "Call-ID", "CSeq"]);
    }

    #[test]
    fn binary_body() {
        let body: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut content = Vec::new();
        content.extend_from_slice(b"MESSAGE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: binary-body\r\n");
        content.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.body, body);
    }

    #[test]
    fn error_no_crlf() {
        let content = b"garbage without any crlf";
        let msg = make_sip_message(content);
        let result = msg.parse();
        assert!(result.is_err());
    }

    #[test]
    fn header_value_with_colon() {
        // SIP URIs in header values contain colons
        let content = b"INVITE sip:host SIP/2.0\r\n\
            Contact: <sip:user@10.0.0.1:5060;transport=tcp>\r\n\
            Call-ID: colon-val\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let contact = parsed
            .headers
            .iter()
            .find(|(k, _)| k == "Contact")
            .map(|(_, v)| v.as_str());
        assert_eq!(contact, Some("<sip:user@10.0.0.1:5060;transport=tcp>"));
    }

    #[test]
    fn whitespace_around_header_value() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID:   spaces-around   \r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        // Leading whitespace should be trimmed, trailing kept (we only trim leading)
        assert_eq!(parsed.call_id(), Some("spaces-around   "));
    }

    #[test]
    fn parsed_message_iterator() {
        let content =
            b"OPTIONS sip:host SIP/2.0\r\nCall-ID: iter-test\r\nContent-Length: 0\r\n\r\n";
        let header = format!(
            "recv {} bytes from udp/10.0.0.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");

        let parsed: Vec<ParsedSipMessage> = ParsedMessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].call_id(), Some("iter-test"));
        assert_eq!(parsed[0].method(), Some("OPTIONS"));
    }

    #[test]
    fn whitespace_only_returns_transport_noise() {
        use crate::frame::ParseError;

        for content in [b"\n".as_slice(), b"\r\n", b"\n\n\n", b" \t\r\n"] {
            let msg = SipMessage {
                direction: Direction::Recv,
                transport: Transport::Tls,
                address: "[10.0.0.1]:5061".into(),
                timestamp: Timestamp::TimeOnly {
                    hour: 0,
                    min: 0,
                    sec: 0,
                    usec: 0,
                },
                content: content.to_vec(),
                offset: 0,
                frame_count: 1,
            };
            let err = msg.parse().unwrap_err();
            assert!(
                matches!(err, ParseError::TransportNoise { .. }),
                "whitespace-only content {:?} should produce TransportNoise, got: {err}",
                content,
            );
        }
    }
}
