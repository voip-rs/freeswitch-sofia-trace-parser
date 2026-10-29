use std::borrow::Cow;

use crate::finders::CRLF;
use crate::frame::ParseError;
use crate::sip::{header_block, parse_headers, FirstLine, HasHeaders};
use crate::startline::parse_first_line;
use crate::startline::split_headers_body;
use crate::types::{MimePart, SipFragment};

/// Parse a `message/sipfrag` body (RFC 3420) — any prefix of a SIP message.
///
/// The start line is optional: a fragment that begins with a header is parsed
/// from the headers down. The trailing CRLF is optional too, so a bare status
/// line parses. Fails only when the first line is neither a start line nor a
/// clean header row, as the header reader judges one, or the input is empty.
pub fn parse_sipfrag(data: &[u8]) -> Result<SipFragment, ParseError> {
    if data.is_empty() {
        return Err(ParseError::InvalidMessage("empty sipfrag".into()));
    }

    let first_line_end = CRLF.find(data).unwrap_or(data.len());
    let mut first_line = &data[..first_line_end];
    // A bare trailing terminator from an LF-only writer is not part of the
    // start line; a full CRLF is already excluded by the find above.
    if let [rest @ .., b'\n'] = first_line {
        first_line = rest;
    }
    if let [rest @ .., b'\r'] = first_line {
        first_line = rest;
    }

    match parse_first_line(first_line) {
        Ok(mt) => {
            let (header_bytes, body) =
                split_headers_body(data, (first_line_end + 2).min(data.len()));
            Ok(SipFragment {
                message_type: Some(mt),
                headers: parse_headers(header_bytes),
                body: body.to_vec(),
            })
        }
        Err(e) => {
            let (header_bytes, body) = split_headers_body(data, 0);
            match header_block(header_bytes) {
                (headers, FirstLine::Header) => Ok(SipFragment {
                    message_type: None,
                    headers,
                    body: body.to_vec(),
                }),
                (_, FirstLine::Empty | FirstLine::NotHeader) => Err(e),
            }
        }
    }
}

impl SipFragment {
    /// Content-Type with parameters stripped and lowercased, e.g.
    /// `application/sdp` from `Application/SDP; charset=utf-8`. Use this to
    /// dispatch on the type rather than matching the raw header value.
    pub fn media_type(&self) -> Option<Cow<'_, str>> {
        HasHeaders::media_type(self)
    }
}

impl MimePart {
    /// Parse this part's body as a `message/sipfrag` (RFC 3420).
    ///
    /// Does not check the Content-Type: dispatch on [`media_type`](Self::media_type)
    /// first, then call this for the parts that claim to be fragments.
    pub fn parse_sipfrag(&self) -> Result<SipFragment, ParseError> {
        parse_sipfrag(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::test_support::{assert_messy_diagnostics, make_multipart_invite, MESSY_BLOCK};
    use crate::types::SipMessageType;

    #[test]
    fn sipfrag_status_line_with_crlf() {
        let frag = parse_sipfrag(b"SIP/2.0 200 OK\r\n").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            })
        );
        assert!(frag.headers.is_empty());
        assert!(frag.body.is_empty());
    }

    #[test]
    fn sipfrag_status_line_without_trailing_crlf() {
        let frag = parse_sipfrag(b"SIP/2.0 183 Session Progress").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 183,
                reason: "Session Progress".into()
            })
        );
    }

    #[test]
    fn sipfrag_headers_only() {
        let frag = parse_sipfrag(b"To: <sip:user@host>\r\nCSeq: 1 INVITE\r\n").unwrap();
        assert_eq!(frag.message_type, None);
        assert_eq!(frag.headers.len(), 2);
        assert_eq!(frag.headers[0].0, "To");
        assert_eq!(frag.headers[0].1, "<sip:user@host>");
        assert_eq!(frag.headers[1].1, "1 INVITE");
    }

    #[test]
    fn sipfrag_header_value_is_case_insensitive() {
        let frag = parse_sipfrag(b"To: <sip:user@host>\r\nCSeq: 1 INVITE\r\n").unwrap();
        assert_eq!(frag.header_value("cseq"), Some("1 INVITE"));
        assert_eq!(frag.header_value("To"), Some("<sip:user@host>"));
        assert_eq!(frag.header_value("Call-ID"), None);
    }

    #[test]
    fn sipfrag_headers_only_without_trailing_crlf() {
        let frag = parse_sipfrag(b"To: <sip:user@host>").unwrap();
        assert_eq!(frag.message_type, None);
        assert_eq!(frag.headers.len(), 1);
        assert_eq!(frag.headers[0].1, "<sip:user@host>");
    }

    #[test]
    fn sipfrag_start_line_headers_and_body() {
        let data = b"SIP/2.0 200 OK\r\n\
            Content-Type: application/sdp\r\n\
            \r\n\
            v=0\r\n";
        let frag = parse_sipfrag(data).unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            })
        );
        assert_eq!(frag.headers.len(), 1);
        assert_eq!(frag.body, b"v=0\r\n");
    }

    #[test]
    fn sipfrag_request_start_line() {
        let frag = parse_sipfrag(b"INVITE sip:user@host SIP/2.0\r\nCSeq: 2 INVITE\r\n").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:user@host".into()
            })
        );
        assert_eq!(frag.headers.len(), 1);
    }

    #[test]
    fn sipfrag_garbage_is_error() {
        assert!(parse_sipfrag(b"just some text without a colon").is_err());
        assert!(parse_sipfrag(b"").is_err());
    }

    #[test]
    fn sipfrag_content_type_and_media_type() {
        let frag = parse_sipfrag(
            b"SIP/2.0 200 OK\r\nContent-Type: Application/SDP; charset=utf-8\r\n\r\nv=0",
        )
        .unwrap();
        assert_eq!(frag.content_type(), Some("Application/SDP; charset=utf-8"));
        assert_eq!(frag.media_type().as_deref(), Some("application/sdp"));

        let compact = parse_sipfrag(b"SIP/2.0 200 OK\r\nc: text/plain\r\n\r\nhi").unwrap();
        assert_eq!(compact.content_type(), Some("text/plain"));
    }

    #[test]
    fn sipfrag_malformed_start_line_with_colon_is_error() {
        assert!(parse_sipfrag(b"INVITE sip:host SIP/1.0\r\n").is_err());
    }

    #[test]
    fn sipfrag_lf_only_status_line() {
        let frag = parse_sipfrag(b"SIP/2.0 200 OK\n").unwrap();
        assert!(matches!(
            frag.message_type,
            Some(SipMessageType::Response { code: 200, ref reason }) if reason == "OK"
        ));
        assert!(frag.headers.is_empty());
        assert!(frag.body.is_empty());
    }

    #[test]
    fn sipfrag_from_mime_part() {
        let body = b"SIP/2.0 100 Trying\r\n";
        let msg = make_multipart_invite("frag-boundary", &[("message/sipfrag", body)]);
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_as_parts();
        assert_eq!(parts[0].media_type().as_deref(), Some("message/sipfrag"));

        let frag = parts[0].parse_sipfrag().unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 100,
                reason: "Trying".into()
            })
        );
    }

    #[test]
    fn sipfrag_first_line_without_start_line() {
        let ok = |data: &[u8]| parse_sipfrag(data).is_ok();
        assert!(ok(b"To: <sip:a@b>\r\n"));
        assert!(ok(b"To : <sip:a@b>\r\n"));
        assert!(!ok(b"X\tY: 1\r\n"));
        assert!(ok(b"To: x\nCSeq: 1 INVITE\n"));
        assert!(!ok(b"<sip:a@b>\nTo: x\r\n"));
        assert!(ok(b"To: <sip:a@b>\n"));
        assert!(!ok(b"Incident ID: x\r\n"));
        assert!(!ok(b"<sip:a@b>\r\n"));
        assert!(!ok(b"\xff\xfeTo: x\r\n"));
        assert!(!ok(b""));
        assert!(!ok(b"\r\n"));
    }

    #[test]
    fn sipfrag_reports_skipped_lines_and_warnings() {
        let mut data = MESSY_BLOCK.to_vec();
        data.extend_from_slice(b"\r\n");
        let frag = parse_sipfrag(&data).unwrap();
        assert_messy_diagnostics(&frag.headers);
    }
}
