use crate::finders::CRLF;
use crate::sip::test_support::{make_multipart_invite, make_sip_message, parsed_with_headers};
use crate::types::{Headers, MimePart, SipMessage};

#[test]
fn multipart_sdp_and_pidf() {
    let sdp = b"v=0\r\no=- 123 456 IN IP4 10.0.0.1\r\ns=-\r\n";
    let pidf = b"<?xml version=\"1.0\"?>\r\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"/>";
    let msg = make_multipart_invite(
        "unique-boundary-1",
        &[("application/sdp", sdp), ("application/pidf+xml", pidf)],
    );
    let parsed = msg.parse().unwrap();

    assert!(parsed.is_multipart());
    assert_eq!(parsed.multipart_boundary(), Some("unique-boundary-1"));

    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 2);

    assert_eq!(parts[0].content_type(), Some("application/sdp"));
    assert_eq!(parts[0].body, sdp);

    assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
    assert_eq!(parts[1].body, pidf);
}

#[test]
fn multipart_sdp_and_eido() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n\
        c=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let eido = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
        <eido:EmergencyCallData xmlns:eido=\"urn:nena:xml:ns:EmergencyCallData\">\r\n\
        <eido:IncidentId>INC-2026-001</eido:IncidentId>\r\n\
        </eido:EmergencyCallData>";
    let msg = make_multipart_invite(
        "ng911-boundary",
        &[
            ("application/sdp", sdp),
            ("application/emergencyCallData.eido+xml", eido),
        ],
    );
    let parsed = msg.parse().unwrap();
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 2);

    let sdp_part = parts
        .iter()
        .find(|p| p.content_type() == Some("application/sdp"));
    assert!(sdp_part.is_some());
    assert_eq!(sdp_part.unwrap().body, sdp);

    let eido_part = parts
        .iter()
        .find(|p| p.content_type().is_some_and(|ct| ct.contains("eido")));
    assert!(eido_part.is_some());
    assert_eq!(eido_part.unwrap().body, eido);
}

#[test]
fn multipart_three_parts_sdp_pidf_eido() {
    let sdp = b"v=0\r\ns=-\r\n";
    let pidf = b"<presence/>";
    let eido = b"<EmergencyCallData/>";
    let msg = make_multipart_invite(
        "tri-part",
        &[
            ("application/sdp", sdp),
            ("application/pidf+xml", pidf),
            ("application/emergencyCallData.eido+xml", eido),
        ],
    );
    let parsed = msg.parse().unwrap();
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].content_type(), Some("application/sdp"));
    assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
    assert_eq!(
        parts[2].content_type(),
        Some("application/emergencyCallData.eido+xml")
    );
}

#[test]
fn multipart_quoted_boundary() {
    let sdp = b"v=0\r\n";
    let pidf = b"<presence/>";

    let mut body = Vec::new();
    body.extend_from_slice(b"--quoted-boundary\r\n");
    body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    body.extend_from_slice(sdp);
    body.extend_from_slice(b"\r\n--quoted-boundary\r\n");
    body.extend_from_slice(b"Content-Type: application/pidf+xml\r\n\r\n");
    body.extend_from_slice(pidf);
    body.extend_from_slice(b"\r\n--quoted-boundary--");

    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: quoted-bnd@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed; boundary=\"quoted-boundary\"\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    let msg = make_sip_message(&content);
    let parsed = msg.parse().unwrap();

    assert_eq!(parsed.multipart_boundary(), Some("quoted-boundary"));
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body, sdp);
    assert_eq!(parts[1].body, pidf);
}

#[test]
fn multipart_with_preamble() {
    let sdp = b"v=0\r\n";

    let mut body = Vec::new();
    body.extend_from_slice(b"This is the preamble. It should be ignored.\r\n");
    body.extend_from_slice(b"--boundary-pre\r\n");
    body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    body.extend_from_slice(sdp);
    body.extend_from_slice(b"\r\n--boundary-pre--");

    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: preamble@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=boundary-pre\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    let msg = make_sip_message(&content);
    let parsed = msg.parse().unwrap();
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].body, sdp);
}

#[test]
fn multipart_part_with_multiple_headers() {
    let eido = b"<EmergencyCallData/>";

    let mut body = Vec::new();
    body.extend_from_slice(b"--hdr-boundary\r\n");
    body.extend_from_slice(b"Content-Type: application/emergencyCallData.eido+xml\r\n");
    body.extend_from_slice(b"Content-ID: <eido@example.com>\r\n");
    body.extend_from_slice(b"Content-Disposition: by-reference\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(eido);
    body.extend_from_slice(b"\r\n--hdr-boundary--");

    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: multi-hdr-part@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=hdr-boundary\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    let msg = make_sip_message(&content);
    let parsed = msg.parse().unwrap();
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(
        parts[0].content_type(),
        Some("application/emergencyCallData.eido+xml")
    );
    assert_eq!(parts[0].content_id(), Some("<eido@example.com>"));
    assert_eq!(parts[0].content_disposition(), Some("by-reference"));
    assert_eq!(parts[0].body, eido);
}

#[test]
fn not_multipart_returns_none() {
    let content = b"INVITE sip:host SIP/2.0\r\n\
        Call-ID: not-multi@host\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 4\r\n\
        \r\n\
        v=0\n";
    let msg = make_sip_message(content);
    let parsed = msg.parse().unwrap();

    assert!(!parsed.is_multipart());
    assert!(parsed.multipart_boundary().is_none());
    assert!(parsed.body_parts().is_none());
}

#[test]
fn multipart_empty_body() {
    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: empty-multi@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=empty\r\n");
    content.extend_from_slice(b"Content-Length: 9\r\n");
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(b"--empty--");

    let msg = make_sip_message(&content);
    let parsed = msg.parse().unwrap();
    assert!(parsed.body_parts().is_none());

    let parts = parsed.body_as_parts();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].body, b"--empty--");
}

#[test]
fn nested_part_typed_with_compact_content_type() {
    let part = MimePart {
        headers: Headers::from(vec![(
            "c".to_string(),
            "multipart/mixed;boundary=inner".to_string(),
        )]),
        body: b"--inner\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--inner--".to_vec(),
    };
    assert_eq!(part.content_type(), Some("multipart/mixed;boundary=inner"));
    assert!(part.is_multipart());
    let children = part.body_parts().expect("compact type must still split");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].content_type(), Some("application/sdp"));
    assert_eq!(children[0].body, b"v=0");
}

#[test]
fn multipart_part_no_headers() {
    let raw_body = b"just raw content";

    let mut body = Vec::new();
    body.extend_from_slice(b"--no-hdr\r\n");
    body.extend_from_slice(raw_body);
    body.extend_from_slice(b"\r\n--no-hdr--");

    let mut content = Vec::new();
    content.extend_from_slice(b"MESSAGE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: no-hdr-part@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=no-hdr\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    let msg = make_sip_message(&content);
    let parsed = msg.parse().unwrap();
    let parts = parsed.body_parts().unwrap();
    assert_eq!(parts.len(), 1);
    assert!(parts[0].content_type().is_none());
    assert!(parts[0].headers.is_empty());
    assert_eq!(parts[0].body, raw_body);
}

// --- body_as_parts tests ---

#[test]
fn body_as_parts_wraps_non_multipart() {
    let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";
    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: abp-plain@host\r\n");
    content.extend_from_slice(b"Content-Type: application/sdp\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(body);

    let parsed = make_sip_message(&content).parse().unwrap();
    let parts = parsed.body_as_parts();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
    assert_eq!(parts[0].body, body);
}

#[test]
fn body_as_parts_matches_body_parts_for_multipart() {
    let msg = make_multipart_invite(
        "abp-multi",
        &[
            ("application/sdp", b"v=0\r\n"),
            ("application/pidf+xml", b"<presence/>"),
        ],
    );
    let parsed = msg.parse().unwrap();
    let all = parsed.body_as_parts();
    let split = parsed.body_parts().unwrap();
    assert_eq!(all.len(), split.len());
    for (a, b) in all.iter().zip(split.iter()) {
        assert_eq!(a.headers, b.headers);
        assert_eq!(a.body, b.body);
    }
}

#[test]
fn body_as_parts_empty_body() {
    let content = b"OPTIONS sip:host SIP/2.0\r\n\
        Call-ID: abp-empty@host\r\n\
        Content-Length: 0\r\n\
        \r\n";
    let parsed = make_sip_message(content).parse().unwrap();
    assert!(parsed.body_as_parts().is_empty());
}

#[test]
fn body_as_parts_multipart_without_boundary() {
    let body = b"--something\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n";
    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: abp-nobnd@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(body);

    let parsed = make_sip_message(&content).parse().unwrap();
    let parts = parsed.body_as_parts();
    assert_eq!(
        parts.len(),
        1,
        "unsplittable multipart must surface as one part"
    );
    assert_eq!(parts[0].media_type().as_deref(), Some("multipart/mixed"));
    assert_eq!(parts[0].body, body);
}

#[test]
fn body_as_parts_boundary_not_in_body() {
    let body = b"--other\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--other--";
    let parsed = parsed_with_headers(
        "abp-mismatch",
        &["Content-Type: multipart/mixed;boundary=declared"],
        body,
    );
    let parts = parsed.body_as_parts();
    assert_eq!(
        parts.len(),
        1,
        "a boundary absent from the body is not a split"
    );
    assert_eq!(parts[0].media_type().as_deref(), Some("multipart/mixed"));
    assert_eq!(parts[0].body, body);
    assert!(parsed.body_parts().is_none());
}

#[test]
fn body_as_parts_truncated_multipart() {
    let body = b"--trunc\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n";
    let parsed = parsed_with_headers(
        "abp-trunc",
        &["Content-Type: multipart/mixed;boundary=trunc"],
        body,
    );
    let parts = parsed.body_as_parts();
    assert_eq!(
        parts.len(),
        1,
        "a body cut off before the closing delimiter must not vanish"
    );
    assert_eq!(parts[0].content_type(), Some("application/sdp"));
    assert_eq!(parts[0].body, b"v=0\r\n");
    assert!(parsed.body_parts().is_some());
}

fn split_on_b(call_id: &str, body: &[u8]) -> Vec<MimePart> {
    parsed_with_headers(call_id, &["Content-Type: multipart/mixed;boundary=b"], body)
        .body_parts()
        .expect("boundary b must split this body")
}

#[test]
fn multipart_truncated_trailing_part() {
    let parts = split_on_b(
        "trunc-trailing",
        b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\
            --b\r\nContent-Type: application/pidf+xml\r\n\r\n<presence",
    );
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body, b"v=0");
    assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
    assert_eq!(parts[1].body, b"<presence");
}

#[test]
fn headerless_part_with_colon_keeps_its_bytes() {
    for raw in [&b"<sip:a@example.com>"[..], b"{\"k\":1}"] {
        let mut body = b"--b\r\n".to_vec();
        body.extend_from_slice(raw);
        body.extend_from_slice(b"\r\n--b--");
        let parts = split_on_b("hdrless-colon", &body);
        assert_eq!(parts.len(), 1);
        assert!(parts[0].headers.is_empty());
        assert_eq!(parts[0].body, raw);
    }
}

#[test]
fn headerless_part_with_blank_line_keeps_its_bytes() {
    let parts = split_on_b(
        "hdrless-blank",
        b"--b\r\n<sip:a@example.com>\r\n\r\nmore\r\n--b--",
    );
    assert_eq!(parts.len(), 1);
    assert!(parts[0].headers.is_empty());
    assert_eq!(parts[0].body, b"<sip:a@example.com>\r\n\r\nmore");
}

#[test]
fn multipart_truncated_inside_close_delimiter() {
    let parts = split_on_b(
        "trunc-close",
        b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b",
    );
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].body, b"v=0");
}

#[test]
fn multipart_preamble_substring_no_false_part() {
    let parts = split_on_b(
        "preamble-substring",
        b"preamble mentions --b in passing\r\n\
            --b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--",
    );
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].content_type(), Some("application/sdp"));
    assert_eq!(parts[0].body, b"v=0");
}

#[test]
fn multipart_boundary_prefix_collision() {
    let parts = split_on_b(
        "prefix-collision",
        b"--b\r\nContent-Type: text/plain\r\n\r\nouter\r\n--b2\r\ninner text\r\n--b2--\r\n--b--",
    );
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].body, b"outer\r\n--b2\r\ninner text\r\n--b2--");
}

#[test]
fn multipart_delimiter_transport_padding() {
    let parts = split_on_b(
        "transport-padding",
        b"--b \t\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\
            --b  \r\nContent-Type: application/pidf+xml\r\n\r\n<presence/>\r\n--b--",
    );
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body, b"v=0");
    assert_eq!(parts[1].body, b"<presence/>");
}

#[test]
fn multipart_no_preamble_delimiter_at_offset_zero() {
    let parts = split_on_b(
        "no-preamble",
        b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--",
    );
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].body, b"v=0");
}

// --- content headers copied onto the synthetic part ---

fn part_header<'a>(part: &'a MimePart, name: &str) -> Option<&'a str> {
    part.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
fn synthetic_part_carries_transfer_encoding() {
    let parsed = parsed_with_headers(
        "abp-cte",
        &[
            "Content-Type: application/pidf+xml",
            "Content-Transfer-Encoding: base64",
        ],
        b"PD94bWwgdmVyc2lvbj0iMS4wIj8+",
    );
    let parts = parsed.body_as_parts();
    assert_eq!(
        parts[0].content_transfer_encoding(),
        Some("base64"),
        "a per-part consumer must see the encoding the message declared"
    );
}

#[test]
fn synthetic_part_carries_disposition_and_id() {
    let parsed = parsed_with_headers(
        "abp-cd",
        &[
            "Content-Type: application/sdp",
            "Content-Disposition: session",
            "Content-ID: <sdp@host>",
        ],
        b"v=0\r\n",
    );
    let parts = parsed.body_as_parts();
    assert_eq!(parts[0].content_disposition(), Some("session"));
    assert_eq!(parts[0].content_id(), Some("<sdp@host>"));
}

#[test]
fn synthetic_part_canonicalizes_compact_content_encoding() {
    let parsed = parsed_with_headers(
        "abp-compact-e",
        &["Content-Type: application/sdp", "e: gzip"],
        b"v=0\r\n",
    );
    let parts = parsed.body_as_parts();
    assert_eq!(
        part_header(&parts[0], "Content-Encoding"),
        Some("gzip"),
        "compact form must arrive under the canonical name"
    );
}

#[test]
fn synthetic_part_canonicalizes_compact_content_type() {
    let parsed = parsed_with_headers("abp-compact-c", &["c: application/sdp"], b"v=0\r\n");
    let parts = parsed.body_as_parts();
    assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
    assert_eq!(
        parts[0]
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .count(),
        1
    );
}

#[test]
fn synthetic_part_content_type_matches_the_message() {
    let parsed = parsed_with_headers(
        "abp-both-ct",
        &["c: text/plain", "Content-Type: application/sdp"],
        b"v=0\r\n",
    );
    let parts = parsed.body_as_parts();
    assert_eq!(parts[0].content_type(), parsed.content_type());
    assert_eq!(
        parts[0]
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .count(),
        1
    );
}

#[test]
fn synthetic_part_omits_content_length() {
    let parsed = parsed_with_headers("abp-len", &["Content-Type: application/sdp"], b"v=0\r\n");
    let parts = parsed.body_as_parts();
    assert_eq!(part_header(&parts[0], "Content-Length"), None);
    assert_eq!(part_header(&parts[0], "l"), None);
}

#[test]
fn synthetic_part_copies_only_content_headers() {
    let parsed = parsed_with_headers(
        "abp-other",
        &[
            "Content-Type: application/sdp",
            "Subject: not a body header",
        ],
        b"v=0\r\n",
    );
    let parts = parsed.body_as_parts();
    assert_eq!(part_header(&parts[0], "Subject"), None);
    assert_eq!(part_header(&parts[0], "Call-ID"), None);
}

#[test]
fn wire_parts_get_no_fabricated_headers() {
    let msg = make_multipart_invite("wire-hdrs", &[("application/sdp", b"v=0\r\n")]);
    let mut content = msg.content.clone();
    let insert_at = CRLF.find(&content).unwrap() + 2;
    content.splice(
        insert_at..insert_at,
        b"Content-Transfer-Encoding: base64\r\n".iter().copied(),
    );
    let parsed = make_sip_message(&content).parse().unwrap();
    let parts = parsed.body_as_parts();
    assert_eq!(parts.len(), 1);
    assert_eq!(
        parts[0].content_transfer_encoding(),
        None,
        "a wire part carries what the sender wrote, nothing copied down"
    );
}

// --- nested multipart (caller-driven descent) ---

/// INVITE whose body is a multipart carrying SDP beside a nested
/// multipart/mixed that holds the PIDF-LO.
fn make_nested_multipart_invite() -> SipMessage {
    let mut inner = Vec::new();
    inner.extend_from_slice(b"--inner\r\n");
    inner.extend_from_slice(b"Content-Type: application/pidf+xml\r\n\r\n");
    inner.extend_from_slice(b"<presence/>");
    inner.extend_from_slice(b"\r\n--inner--");

    let mut body = Vec::new();
    body.extend_from_slice(b"--outer\r\n");
    body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    body.extend_from_slice(b"v=0\r\n");
    body.extend_from_slice(b"\r\n--outer\r\n");
    body.extend_from_slice(b"Content-Type: multipart/mixed;boundary=inner\r\n\r\n");
    body.extend_from_slice(&inner);
    body.extend_from_slice(b"\r\n--outer--");

    let mut content = Vec::new();
    content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
    content.extend_from_slice(b"Call-ID: nested@host\r\n");
    content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=outer\r\n");
    content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    content.extend_from_slice(b"\r\n");
    content.extend_from_slice(&body);

    make_sip_message(&content)
}

#[test]
fn nested_multipart_not_flattened() {
    let parsed = make_nested_multipart_invite().parse().unwrap();
    let parts = parsed.body_as_parts();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
    assert_eq!(parts[1].media_type().as_deref(), Some("multipart/mixed"));
}

#[test]
fn nested_multipart_explicit_descent() {
    let parsed = make_nested_multipart_invite().parse().unwrap();
    let outer = parsed.body_as_parts();
    let nested = &outer[1];

    assert!(nested.is_multipart());
    assert_eq!(nested.multipart_boundary(), Some("inner"));

    let inner = nested.body_parts().unwrap();
    assert_eq!(inner.len(), 1);
    assert_eq!(
        inner[0].media_type().as_deref(),
        Some("application/pidf+xml")
    );
    assert_eq!(inner[0].body, b"<presence/>");
}

#[test]
fn non_multipart_part_has_no_children() {
    let parsed = make_nested_multipart_invite().parse().unwrap();
    let sdp_part = &parsed.body_as_parts()[0];
    assert!(!sdp_part.is_multipart());
    assert!(sdp_part.multipart_boundary().is_none());
    assert!(sdp_part.body_parts().is_none());
}
