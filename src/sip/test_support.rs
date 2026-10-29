use crate::types::{
    Direction, HeaderPart, HeaderWarningKind, Headers, ParsedSipMessage, SipMessage, Timestamp,
    Transport,
};

pub(crate) fn make_sip_message(content: &[u8]) -> SipMessage {
    SipMessage {
        direction: Direction::Recv,
        transport: Transport::Udp,
        address: "10.0.0.1:5060".into(),
        timestamp: Timestamp::TimeOnly {
            hour: 12,
            min: 0,
            sec: 0,
            usec: 0,
        },
        content: content.to_vec(),
        frame_count: 1,
        offset: 0,
    }
}

pub(crate) fn make_multipart_invite(boundary: &str, parts: &[(&str, &[u8])]) -> SipMessage {
    let mut body = Vec::new();
    for (ct, content) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--").as_bytes());

    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:urn:service:sos@esrp.example.com SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: multipart-test@host\r\n");
    content.extend_from_slice(b"CSeq: 1 INVITE\r\n");
    content.extend_from_slice(
        format!("Content-Type: multipart/mixed;boundary={boundary}\r\n").as_bytes(),
    );
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    make_sip_message(&content)
}

pub(super) fn parsed_with_headers(
    call_id: &str,
    headers: &[&str],
    body: &[u8],
) -> ParsedSipMessage {
    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(format!("Call-ID: {call_id}@host\r\n").as_bytes());
    for header in headers {
        content.extend_from_slice(header.as_bytes());
        content.extend_from_slice(b"\r\n");
    }
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(body);
    make_sip_message(&content).parse().unwrap()
}

/// A header block holding a skipped line, a name with whitespace, NBSP value
/// padding and VT value padding, around clean rows A (row 0) and C (row 3).
pub(crate) const MESSY_BLOCK: &[u8] =
    b"A: 1\r\nno colon\r\nIncident ID: x\r\nB: \xc2\xa01\r\nC: 1\x0b\r\n";

/// What [`MESSY_BLOCK`] must report, whichever carrier read it.
pub(crate) fn assert_messy_diagnostics(headers: &Headers) {
    let skipped: Vec<_> = headers
        .skipped_lines()
        .iter()
        .map(|s| (s.text(), s.before_row()))
        .collect();
    assert_eq!(skipped, [("no colon", 1)]);

    let warnings: Vec<_> = headers
        .warnings()
        .iter()
        .map(|w| (w.row(), w.part(), w.kind()))
        .collect();
    assert_eq!(
        warnings,
        [
            (1, HeaderPart::Name, HeaderWarningKind::Whitespace),
            (2, HeaderPart::Value, HeaderWarningKind::NonLwsWhitespace),
            (3, HeaderPart::Value, HeaderWarningKind::ControlChar),
        ]
    );
}

/// A SIP request whose header block, after the start line, is `block`.
pub(crate) fn request_with_block(block: &[u8]) -> ParsedSipMessage {
    let mut content = b"INVITE sip:host SIP/2.0\r\n".to_vec();
    content.extend_from_slice(block);
    content.extend_from_slice(b"\r\n");
    make_sip_message(&content).parse().unwrap()
}
