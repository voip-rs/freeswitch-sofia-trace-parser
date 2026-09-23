use crate::types::{Direction, ParsedSipMessage, SipMessage, Timestamp, Transport};

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
