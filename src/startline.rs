//! Grammar shared by every level: the start line, and the Content-Length a
//! message declares.
//!
//! Level 2 frames messages on Content-Length and Level 3 reports it, so both
//! read it here, from the same rows: every Content-Length row, compact forms
//! in any case included, read by sip-header. A length is used only when every
//! such row is clean and they all agree, since the value decides where the
//! next message starts: a guessed length desynchronises a TCP connection. A
//! row with an error or any warning, `318 bytes` included, makes the length
//! unusable, and the message then ends at its blank line.

use std::borrow::Cow;

use sip_header::{
    Field, HeaderParse, NameMatcher, ParseWarning, SipContentLength, SipHeader, Span, WarningCode,
};

use crate::frame::ParseError;
use crate::types::{warning_row, SipMessageType};

/// A start line still pointing into the message it came from.
pub(crate) enum StartLineRef<'a> {
    Request { method: &'a [u8], uri: &'a [u8] },
    Response { code: u16, reason: &'a [u8] },
}

pub(crate) fn parse_first_line(line: &[u8]) -> Result<SipMessageType, ParseError> {
    Ok(match parse_first_line_ref(line)? {
        StartLineRef::Request { method, uri } => SipMessageType::Request {
            method: bytes_to_string(method),
            uri: bytes_to_string(uri),
        },
        StartLineRef::Response { code, reason } => SipMessageType::Response {
            code,
            reason: bytes_to_string(reason),
        },
    })
}

pub(crate) fn parse_first_line_ref(line: &[u8]) -> Result<StartLineRef<'_>, ParseError> {
    if line.starts_with(b"SIP/2.0 ") {
        return parse_status_line(line);
    }
    parse_request_line(line)
}

fn parse_status_line(line: &[u8]) -> Result<StartLineRef<'_>, ParseError> {
    // SIP/2.0 <code> <reason>
    let after_version = &line[8..]; // skip "SIP/2.0 "

    let space = memchr::memchr(b' ', after_version)
        .ok_or_else(|| ParseError::InvalidMessage("no space after status code".into()))?;
    let code_bytes = &after_version[..space];
    let code: u16 = std::str::from_utf8(code_bytes)
        .map_err(|_| ParseError::InvalidMessage("non-UTF-8 status code".into()))?
        .parse()
        .map_err(|_| ParseError::InvalidMessage("invalid status code".into()))?;

    let reason = &after_version[space + 1..];

    Ok(StartLineRef::Response { code, reason })
}

fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-._!%*+`'~".contains(&c)
}

fn is_sip_token(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().copied().all(is_token_byte)
}

/// Whether a buffer opens on a SIP start line, for a reader that may not hold
/// the whole line yet.
pub(crate) enum SipStart {
    /// The first line is a request line or a status line.
    Yes,
    /// The first line cannot become either, however it continues.
    No,
    /// No CRLF yet, and what is buffered is still a possible prefix.
    NeedMore,
}

/// The start-line grammar [`parse_first_line_ref`] accepts, answered on bytes
/// that may still be arriving. Level 2 resynchronises on this, so anything it
/// accepts is a message Level 3 parses.
pub(crate) fn sip_start(buf: &[u8]) -> SipStart {
    if buf.starts_with(b"SIP/2.0 ") {
        return SipStart::Yes;
    }
    let mut method_end = 0;
    while method_end < buf.len() && is_token_byte(buf[method_end]) {
        method_end += 1;
    }
    if method_end == buf.len() {
        return SipStart::NeedMore;
    }
    if method_end == 0 || buf[method_end] != b' ' {
        return if b"SIP/2.0 ".starts_with(buf) {
            SipStart::NeedMore
        } else {
            SipStart::No
        };
    }

    // A start line holds no CR or LF of its own, so a lone one rules it out and
    // a trailing CR is the terminator still arriving.
    let rest = &buf[method_end + 1..];
    let mut last_space = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            b'\r' => match rest.get(i + 1) {
                Some(b'\n') => break,
                Some(_) => return SipStart::No,
                None => return SipStart::NeedMore,
            },
            b'\n' => return SipStart::No,
            b' ' => last_space = Some(i),
            _ => {}
        }
        i += 1;
    }
    if i == rest.len() {
        return SipStart::NeedMore;
    }
    match last_space {
        Some(space) if space > 0 && &rest[space + 1..i] == b"SIP/2.0" => SipStart::Yes,
        _ => SipStart::No,
    }
}

fn parse_request_line(line: &[u8]) -> Result<StartLineRef<'_>, ParseError> {
    // <METHOD> <URI> SIP/2.0
    let first_space = memchr::memchr(b' ', line)
        .ok_or_else(|| ParseError::InvalidMessage("no space in request line".into()))?;
    let method = &line[..first_space];

    if !is_sip_token(method) {
        return Err(ParseError::InvalidMessage(format!(
            "invalid SIP method: {:?}",
            String::from_utf8_lossy(method)
        )));
    }
    let rest = &line[first_space + 1..];

    let last_space = memchr::memrchr(b' ', rest)
        .ok_or_else(|| ParseError::InvalidMessage("no SIP version in request line".into()))?;
    let version = &rest[last_space + 1..];
    if version != b"SIP/2.0" {
        return Err(ParseError::InvalidMessage(format!(
            "expected SIP/2.0, got {:?}",
            String::from_utf8_lossy(version)
        )));
    }
    let uri = &rest[..last_space];

    Ok(StartLineRef::Request { method, uri })
}

/// What a message's Content-Length rows say about the length of its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentLength {
    /// No row is a Content-Length.
    Absent,
    /// Every Content-Length row is clean and they all carry this number.
    Length(usize),
    /// A row is malformed or warned, or two rows disagree.
    Unusable,
}

/// What a Content-Length row earns as a header warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowReport {
    /// One of several rows that are all clean and equal.
    Duplicate,
    /// A row the length cannot be taken from, or one of rows that disagree.
    Unusable,
}

pub(crate) struct ContentLengthReading {
    pub(crate) length: ContentLength,
    /// `(row index, report)` in row order.
    pub(crate) reports: Vec<(usize, RowReport)>,
    /// What the typed parse of a row said about its value, as `(row index,
    /// code)`, for rows the header reader had not already warned on.
    pub(crate) typed_warnings: Vec<(usize, WarningCode)>,
}

fn is_content_length_name(name: &str) -> bool {
    NameMatcher::from(SipHeader::ContentLength).matches(name)
}

/// A Content-Length value read as sip-header's typed parse reads it: the
/// number when it has nothing to say about it, and the warnings it raised.
/// An error is no number and no warning.
fn read_value(value: &str) -> (Option<usize>, Vec<WarningCode>) {
    match SipContentLength::parse_with_warnings(value) {
        Ok(parsed) => {
            let codes: Vec<WarningCode> = parsed.warnings.iter().map(|w| w.code).collect();
            (codes.is_empty().then(|| parsed.value.get()), codes)
        }
        Err(_) => (None, Vec::new()),
    }
}

/// Reads the Content-Length rows among `rows`, `(name, value)` in wire order;
/// `value_warned(i)` says whether the header reader warned inside row `i`'s
/// value.
pub(crate) fn read_content_length<'a>(
    rows: impl Iterator<Item = (&'a str, &'a str)>,
    value_warned: impl Fn(usize) -> bool,
) -> ContentLengthReading {
    let mut selected: Vec<(usize, Option<usize>)> = Vec::new();
    let mut typed_warnings = Vec::new();
    for (row, (name, value)) in rows.enumerate() {
        if !is_content_length_name(name) {
            continue;
        }
        if value_warned(row) {
            selected.push((row, None));
            continue;
        }
        let (length, codes) = read_value(value);
        typed_warnings.extend(codes.into_iter().map(|code| (row, code)));
        selected.push((row, length));
    }
    let (length, reports) = decide(&selected);
    ContentLengthReading {
        length,
        reports,
        typed_warnings,
    }
}

/// The outcome for rows `(index, clean number)`, and what each earns.
fn decide(selected: &[(usize, Option<usize>)]) -> (ContentLength, Vec<(usize, RowReport)>) {
    let Some(&(_, first)) = selected.first() else {
        return (ContentLength::Absent, Vec::new());
    };
    if let Some(n) = first.filter(|_| selected.iter().all(|&(_, len)| len == first)) {
        let report = (selected.len() > 1).then_some(RowReport::Duplicate);
        let reports = selected
            .iter()
            .filter_map(|&(row, _)| report.map(|r| (row, r)))
            .collect();
        return (ContentLength::Length(n), reports);
    }

    let mut numbers = selected.iter().filter_map(|&(_, len)| len);
    let disagree = numbers
        .next()
        .is_some_and(|one| numbers.any(|other| other != one));
    let reports = selected
        .iter()
        .filter(|&&(_, len)| disagree || len.is_none())
        .map(|&(row, _)| (row, RowReport::Unusable))
        .collect();
    (ContentLength::Unusable, reports)
}

/// `value_warned` for [`read_content_length`], taken from the reader's row
/// spans and warnings.
pub(crate) fn value_warned_in<'a>(
    row_spans: &'a [Span],
    warnings: &'a [ParseWarning],
) -> impl Fn(usize) -> bool + 'a {
    move |row| {
        warnings
            .iter()
            .any(|w| w.field == Field::Value && warning_row(row_spans, w) == row)
    }
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

pub(crate) fn bytes_to_str(b: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(b) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => String::from_utf8_lossy(b),
    }
}

fn bytes_to_string(b: &[u8]) -> String {
    bytes_to_str(b).into_owned()
}

#[cfg(test)]
mod tests {
    use crate::sip::test_support::make_sip_message;
    use crate::types::SipMessageType;

    #[test]
    fn status_line_with_long_reason() {
        let content = b"SIP/2.0 486 Busy Here\r\n\
            Call-ID: busy\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 486,
                reason: "Busy Here".into()
            }
        );
    }

    #[test]
    fn request_with_complex_uri() {
        let content = b"INVITE sip:+15551234567@gateway.example.com;transport=tcp SIP/2.0\r\n\
            Call-ID: complex-uri\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:+15551234567@gateway.example.com;transport=tcp".into()
            }
        );
    }

    #[test]
    fn error_no_space_in_request_line() {
        let content = b"INVALID\r\n\r\n";
        let msg = make_sip_message(content);
        let result = msg.parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_request_rejects_xml_method() {
        let content =
            b"</confInfo:conference-info>NOTIFY sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg = make_sip_message(content);
        assert!(msg.parse().is_err(), "should reject XML-prefixed method");
    }

    #[test]
    fn parse_request_rejects_method_with_angle_brackets() {
        let content = b"<xml>BYE sip:host SIP/2.0\r\n\r\n";
        let msg = make_sip_message(content);
        assert!(msg.parse().is_err());
    }

    #[test]
    fn parse_request_accepts_extension_method() {
        let content = b"CUSTOM-METHOD sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "CUSTOM-METHOD".into(),
                uri: "sip:host".into()
            }
        );
    }

    #[test]
    fn method_with_backtick_is_a_token() {
        let msg = make_sip_message(b"X-P`ING sip:host SIP/2.0\r\nCSeq: 1 X-P`ING\r\n\r\n");
        assert_eq!(msg.parse().unwrap().method(), Some("X-P`ING"));
    }
}
