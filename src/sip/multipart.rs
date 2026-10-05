use std::borrow::Cow;

use memchr::memmem;

use crate::finders::CRLFCRLF;
use crate::sip::content_type::{canonical_body_header, extract_boundary, normalize_media_type};
use crate::sip::{header_block, HasHeaders};
use crate::types::{Headers, MimePart, ParsedSipMessage};

#[cfg(test)]
mod tests;

pub(crate) fn is_multipart_type(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| normalize_media_type(ct).starts_with("multipart/"))
        .unwrap_or(false)
}

/// A declared boundary that yields no parts is not a split: reporting it as
/// one empty makes a body vanish from a per-part loop.
pub(crate) fn split_multipart(content_type: Option<&str>, body: &[u8]) -> Option<Vec<MimePart>> {
    let boundary = extract_boundary(content_type?)?;
    let parts = parse_multipart_body(body, boundary);
    (!parts.is_empty()).then_some(parts)
}

impl MimePart {
    /// Content-Type with parameters stripped and lowercased, e.g.
    /// `application/sdp` from `Application/SDP; charset=utf-8`. Use this to
    /// dispatch on the type rather than matching the raw header value.
    pub fn media_type(&self) -> Option<Cow<'_, str>> {
        HasHeaders::media_type(self)
    }

    /// Returns `true` if this part's Content-Type starts with `multipart/`.
    pub fn is_multipart(&self) -> bool {
        HasHeaders::is_multipart(self)
    }

    /// Extract the MIME boundary string from this part's Content-Type header.
    pub fn multipart_boundary(&self) -> Option<&str> {
        HasHeaders::multipart_boundary(self)
    }

    /// Split a nested multipart part into its own [`MimePart`]s.
    /// Returns `None` when this part carries no boundary or that boundary
    /// yields no parts — either way, keep the part's own bytes.
    ///
    /// Descends exactly one level: a grandchild multipart comes back as a part
    /// with its `multipart/*` type intact, to be split by another explicit
    /// call. Depth is the caller's decision.
    pub fn body_parts(&self) -> Option<Vec<MimePart>> {
        HasHeaders::body_parts(self)
    }
}

impl ParsedSipMessage {
    /// Content-Type with parameters stripped and lowercased, e.g.
    /// `multipart/mixed` from `multipart/mixed;boundary=abc`. Use this to
    /// dispatch on the type rather than matching the raw header value.
    pub fn media_type(&self) -> Option<Cow<'_, str>> {
        HasHeaders::media_type(self)
    }

    /// Returns `true` if the Content-Type starts with `multipart/`.
    pub fn is_multipart(&self) -> bool {
        HasHeaders::is_multipart(self)
    }

    /// Extract the MIME boundary string from the Content-Type header.
    pub fn multipart_boundary(&self) -> Option<&str> {
        HasHeaders::multipart_boundary(self)
    }

    /// Split a multipart body into individual [`MimePart`]s.
    /// Returns `None` when the Content-Type carries no `boundary` parameter or
    /// that boundary yields no parts.
    pub fn body_parts(&self) -> Option<Vec<MimePart>> {
        HasHeaders::body_parts(self)
    }

    /// The body as parts, whatever its Content-Type: the multipart children
    /// when it splits, otherwise a single part carrying the message's own
    /// `Content-*` headers. Empty when there is no body.
    ///
    /// That single part is fabricated — a non-multipart body has no per-part
    /// header block on the wire — so its headers are copied down from the
    /// message, compact forms expanded, `Content-Length` excluded. A part
    /// split from a real multipart body carries only what the sender wrote
    /// there, and nothing is copied into it.
    ///
    /// A body that claims `multipart/*` but does not split — no boundary
    /// parameter, or one that never appears in the body — comes back as that
    /// one part, still typed `multipart/*`. A caller that only handles types it
    /// recognizes then sees an unknown type rather than nothing at all.
    ///
    /// Descends one level only; nested multipart parts are split by calling
    /// [`MimePart::body_parts`] on them.
    pub fn body_as_parts(&self) -> Vec<MimePart> {
        if self.body.is_empty() {
            return Vec::new();
        }
        if let Some(parts) = self.body_parts() {
            return parts;
        }
        vec![self.synthetic_part()]
    }

    /// The whole body as one part, headed by the message's own `Content-*`
    /// headers under their canonical names.
    fn synthetic_part(&self) -> MimePart {
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(ct) = self.content_type() {
            headers.push(("Content-Type".to_string(), ct.to_string()));
        }
        for (name, value) in &self.headers {
            let Some(canonical) = canonical_body_header(name) else {
                continue;
            };
            if headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(canonical))
            {
                continue;
            }
            headers.push((canonical.to_string(), value.clone()));
        }
        MimePart {
            headers: Headers::from(headers),
            body: self.body.clone(),
        }
    }
}

/// What follows a matched `--boundary` token, deciding whether the match is a
/// real RFC 2046 delimiter line and where the next part's content starts.
enum BoundaryTail {
    /// Open delimiter; the value is the byte count from the end of the token
    /// (transport padding plus CRLF) to the start of the part content.
    Open(usize),
    Close,
    /// Input ends inside the delimiter line itself (truncated dump).
    End,
}

/// Classify the bytes after a `--boundary` token. `None` means the match is
/// not a delimiter line at all — e.g. boundary `b` matched inside `--b2`.
fn boundary_tail(rest: &[u8]) -> Option<BoundaryTail> {
    if rest.starts_with(b"--") {
        return Some(BoundaryTail::Close);
    }
    let pad = rest
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(rest.len());
    match &rest[pad..] {
        [] => Some(BoundaryTail::End),
        [b'\r', b'\n', ..] => Some(BoundaryTail::Open(pad + 2)),
        _ => None,
    }
}

/// The `\r\n--boundary` pattern and its searcher, built once per body.
struct BoundaryMatcher {
    pattern: Vec<u8>,
    finder: memmem::Finder<'static>,
}

impl BoundaryMatcher {
    fn new(boundary: &str) -> Self {
        let mut pattern = Vec::with_capacity(boundary.len() + 4);
        pattern.extend_from_slice(b"\r\n--");
        pattern.extend_from_slice(boundary.as_bytes());
        let finder = memmem::Finder::new(&pattern).into_owned();
        BoundaryMatcher { pattern, finder }
    }

    /// Next RFC 2046 delimiter line at or after `from`: `--boundary` at body
    /// offset 0 (no preamble) or immediately after a CRLF. `part_end` is where
    /// the preceding part's content stops — the CRLF belongs to the delimiter.
    fn next_delimiter(&self, body: &[u8], from: usize) -> Option<(usize, usize, BoundaryTail)> {
        let dash_boundary = &self.pattern[2..];
        if from == 0 && body.starts_with(dash_boundary) {
            if let Some(tail) = boundary_tail(&body[dash_boundary.len()..]) {
                return Some((0, dash_boundary.len(), tail));
            }
        }
        let mut search = from;
        while let Some(rel) = self.finder.find(&body[search..]) {
            let crlf = search + rel;
            let token_end = crlf + 2 + dash_boundary.len();
            if let Some(tail) = boundary_tail(&body[token_end..]) {
                return Some((crlf, token_end, tail));
            }
            search = crlf + 1;
        }
        None
    }
}

fn parse_multipart_body(body: &[u8], boundary: &str) -> Vec<MimePart> {
    let matcher = BoundaryMatcher::new(boundary);
    let mut parts = Vec::new();

    let Some((_, token_end, tail)) = matcher.next_delimiter(body, 0) else {
        return parts;
    };
    let mut cursor = match tail {
        BoundaryTail::Open(skip) => token_end + skip,
        // The body opens with the close delimiter, or truncates inside the
        // first delimiter line: no parts.
        BoundaryTail::Close | BoundaryTail::End => return parts,
    };

    loop {
        match matcher.next_delimiter(body, cursor) {
            Some((part_end, token_end, BoundaryTail::Open(skip))) => {
                parts.push(parse_mime_part(&body[cursor..part_end]));
                cursor = token_end + skip;
            }
            Some((part_end, _, BoundaryTail::Close | BoundaryTail::End)) => {
                parts.push(parse_mime_part(&body[cursor..part_end]));
                break;
            }
            // Truncated before the close delimiter: the trailing bytes are
            // the final part, never silently dropped.
            None => {
                parts.push(parse_mime_part(&body[cursor..]));
                break;
            }
        }
    }
    parts
}

fn parse_mime_part(data: &[u8]) -> MimePart {
    let (header_bytes, body) = match CRLFCRLF.find(data) {
        Some(pos) => (&data[..pos], &data[pos + 4..]),
        None => (data, &[][..]),
    };
    let (headers, skipped) = header_block(header_bytes);
    // A first line that is no header line means the part has no headers.
    if skipped.first() == Some(&0) {
        return MimePart {
            headers: Headers::default(),
            body: data.to_vec(),
        };
    }
    MimePart {
        headers,
        body: body.to_vec(),
    }
}
