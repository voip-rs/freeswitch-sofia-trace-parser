//! sip-header corpus gate: every typed header and Request-URI of every
//! message, read with its warnings, spans and Display checked.
//! Prints counts only; no header text leaves this test.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use freeswitch_sofia_trace_parser::MessageIterator;
use freeswitch_sofia_trace_torture::{Corpus, Stats};
use sip_header::sip_uri::{Uri, UriParse};
use sip_header::{
    extract_request_line, ContactList, FaultCode, HeaderParams, HeaderParse, HistoryInfo,
    HistoryInfoEntry, ParseError, ParseWarning, SipAccept, SipAcceptEncoding, SipAcceptLanguage,
    SipAuthValue, SipCallId, SipGeolocation, SipGeolocationEntry, SipHeader, SipHeaderAddr,
    SipHeaderAddrList, SipHeaderLookup, SipHeaderRowsExt, SipJoin, SipMessageHeaders,
    SipReasonList, SipReplaces, SipSecurity, SipTargetDialog, SipVia, SipViaEntry, SipWarning,
    Span, SpanError, TokenList, TypedValue, UriInfo, UriInfoEntry, WarningCode, WarningKind,
};

const REQUEST_URI: &str = "Request-URI";

type Count = BTreeMap<String, u64>;

fn bump(map: &mut Count, key: String) {
    *map.entry(key).or_default() += 1;
}

fn fold(into: &mut Count, from: Count) {
    for (k, v) in from {
        *into.entry(k).or_default() += v;
    }
}

#[derive(Default)]
struct Gate {
    messages: u64,
    lib_parse_err: u64,
    skipped_lines: u64,
    extraction_diff_messages: u64,
    rows_lib: Count,
    rows_full: Count,
    attempted: Count,
    parsed: Count,
    errors: Count,
    warnings: Count,
    warnings_by_header: Count,
    panics: Count,
    span_checks: Count,
    span_failures: Count,
    roundtrip_checks: Count,
    roundtrip_failures: Count,
}

impl Stats for Gate {
    fn ok(&self) -> usize {
        self.parsed.values().sum::<u64>() as usize
    }

    fn total(&self) -> usize {
        self.attempted.values().sum::<u64>() as usize
    }

    fn merge(&mut self, other: Self) {
        self.messages += other.messages;
        self.lib_parse_err += other.lib_parse_err;
        self.skipped_lines += other.skipped_lines;
        self.extraction_diff_messages += other.extraction_diff_messages;
        fold(&mut self.rows_lib, other.rows_lib);
        fold(&mut self.rows_full, other.rows_full);
        fold(&mut self.attempted, other.attempted);
        fold(&mut self.parsed, other.parsed);
        fold(&mut self.errors, other.errors);
        fold(&mut self.warnings, other.warnings);
        fold(&mut self.warnings_by_header, other.warnings_by_header);
        fold(&mut self.panics, other.panics);
        fold(&mut self.span_checks, other.span_checks);
        fold(&mut self.span_failures, other.span_failures);
        fold(&mut self.roundtrip_checks, other.roundtrip_checks);
        fold(&mut self.roundtrip_failures, other.roundtrip_failures);
    }
}

fn catalog_name(name: &str) -> String {
    SipHeader::parse_name(name)
        .map(|h| h.as_str().to_string())
        .unwrap_or_else(|_| "(unknown)".to_string())
}

fn error_code(e: &ParseError) -> String {
    match e {
        ParseError::Malformed(f) => format!("Malformed:{}", f.code.as_str()),
        ParseError::Uri(u) => format!("Uri:{}", variant(&format!("{:?}", u.cause()))),
        ParseError::Row(r) => format!("Row:{}", r.kind().as_str()),
        ParseError::NonConformant(w) => format!("NonConformant:{}", warning_code(w)),
        _ => "other".to_string(),
    }
}

fn warning_code(w: &ParseWarning) -> String {
    match &w.code {
        WarningCode::Uri(c) => format!("Uri:{}", variant(&format!("{c:?}"))),
        c => c.as_str().to_string(),
    }
}

/// The variant name leading a Debug rendering, without the data after it.
fn variant(debug: &str) -> &str {
    debug
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
}

fn kind(w: &ParseWarning) -> &'static str {
    match w.kind {
        WarningKind::Lost => "Lost",
        WarningKind::Recovered => "Recovered",
        _ => "other",
    }
}

fn span_error(e: SpanError) -> &'static str {
    match e {
        SpanError::NoRow => "NoRow",
        SpanError::MissingRow => "MissingRow",
        SpanError::OutOfRange => "OutOfRange",
        _ => "other",
    }
}

/// One header's checks, against the rows its value was read from, or the
/// one string (`whole`) a row-less value was parsed from.
struct Check<'g, 'r> {
    gate: &'g mut Gate,
    header: &'static str,
    rows: &'r [&'r str],
    whole: Option<&'r str>,
}

impl Check<'_, '_> {
    fn fail(&mut self, what: &str, why: &str) {
        bump(
            &mut self.gate.span_failures,
            format!("{} {what} {why}", self.header),
        );
    }

    /// The text `span` covers, counting the check and any failure to reach it.
    fn slice(&mut self, what: &str, span: Option<Span>) -> Option<&str> {
        bump(
            &mut self.gate.span_checks,
            format!("{} {what}", self.header),
        );
        let Some(span) = span else {
            self.fail(what, "missing");
            return None;
        };
        let text = match self.whole {
            Some(whole) => span.get(whole),
            None => span.slice(self.rows),
        };
        match text {
            Ok(text) => Some(text),
            Err(e) => {
                self.fail(what, span_error(e));
                None
            }
        }
    }

    /// `span` must slice and reparse to `held`.
    fn reparse<T: PartialEq>(
        &mut self,
        what: &str,
        span: Option<Span>,
        held: &T,
        parse: impl FnOnce(&str) -> Option<T>,
    ) {
        let Some(text) = self.slice(what, span) else {
            return;
        };
        match parse(text) {
            None => self.fail(what, "reparse-err"),
            Some(v) if v != *held => self.fail(what, "unequal"),
            Some(_) => {}
        }
    }

    fn uri(&mut self, span: Option<Span>, held: &Uri) {
        self.reparse("uri", span, held, |s| Uri::parse(s).ok());
    }

    fn params(&mut self, params: &HeaderParams) {
        let mut names: Vec<&str> = params.iter().map(|(n, _)| n).collect();
        names.dedup();
        for name in names {
            let values = params
                .iter()
                .filter(|(n, v)| *n == name && v.is_some())
                .filter_map(|(_, v)| v);
            for (span, held) in params.value_spans(name).zip(values) {
                let Some(text) = self.slice("param", span) else {
                    continue;
                };
                if unquote(text) != held {
                    self.fail("param", "unequal");
                }
            }
        }
    }

    fn warnings(&mut self, warnings: &[ParseWarning]) {
        for w in warnings {
            let code = warning_code(w);
            bump(&mut self.gate.warnings, format!("{code} {}", kind(w)));
            bump(
                &mut self.gate.warnings_by_header,
                format!("{} {code}", self.header),
            );
            if w.span().is_some() {
                self.slice("warning", w.span());
            }
        }
    }

    fn addr(&mut self, a: &SipHeaderAddr) {
        self.reparse("entry", a.span(), a, |s| SipHeaderAddr::parse(s).ok());
        self.uri(a.uri_span(), a.uri());
        self.params(a.params());
    }
}

fn unquote(text: &str) -> String {
    let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
        return text.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// Spans and Display of one parsed value.
trait Walk: Sized {
    fn walk(&self, c: &mut Check<'_, '_>);
    /// Why Display fails to reparse strictly to the same value, if it does.
    fn round_trip(&self, header: Option<SipHeader>) -> Option<&'static str>;
}

fn strict<T: HeaderParse + Display + PartialEq>(v: &T) -> Option<&'static str> {
    match T::parse_strict(&v.to_string()) {
        Err(_) => Some("strict-err"),
        Ok(back) if back != *v => Some("unequal"),
        Ok(_) => None,
    }
}

macro_rules! walk_plain {
    ($($T:ty),+) => {$(
        impl Walk for $T {
            fn walk(&self, _: &mut Check<'_, '_>) {}
            fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
                strict(self)
            }
        }
    )+};
}

macro_rules! walk_params {
    ($($T:ty),+) => {$(
        impl Walk for $T {
            fn walk(&self, c: &mut Check<'_, '_>) {
                c.params(self.params());
            }
            fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
                strict(self)
            }
        }
    )+};
}

macro_rules! walk_list_params {
    ($($T:ty),+) => {$(
        impl Walk for $T {
            fn walk(&self, c: &mut Check<'_, '_>) {
                for e in self.iter() {
                    c.params(e.params());
                }
            }
            fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
                strict(self)
            }
        }
    )+};
}

walk_plain!(SipCallId, SipWarning);
walk_params!(SipReplaces, SipJoin, SipTargetDialog);
walk_list_params!(
    SipReasonList,
    SipSecurity,
    SipAccept,
    SipAcceptEncoding,
    SipAcceptLanguage
);

impl Walk for SipHeaderAddr {
    fn walk(&self, c: &mut Check<'_, '_>) {
        c.addr(self);
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for SipHeaderAddrList {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for a in self.iter() {
            c.addr(a);
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for ContactList {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for a in self.iter() {
            c.addr(a);
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for UriInfo {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for e in self.iter() {
            c.reparse("entry", e.span(), e, |s| UriInfoEntry::parse(s).ok());
            c.uri(e.uri_span(), e.uri());
            c.params(e.params());
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for HistoryInfo {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for e in self.iter() {
            c.reparse("entry", e.span(), e, |s| HistoryInfoEntry::parse(s).ok());
            c.uri(e.uri_span(), e.uri());
            c.params(e.params());
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for SipGeolocation {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for e in self.iter() {
            c.reparse("entry", e.span(), e, |s| SipGeolocationEntry::parse(s).ok());
            c.uri(e.uri_span(), e.uri());
            c.params(e.params());
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for SipVia {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for e in self.iter() {
            c.reparse("entry", e.span(), e, |s| SipViaEntry::parse(s).ok());
            c.slice("host", e.host_span());
            c.params(e.params());
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        strict(self)
    }
}

impl Walk for Vec<SipAuthValue> {
    fn walk(&self, c: &mut Check<'_, '_>) {
        for v in self {
            c.params(v.params());
        }
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        self.iter().find_map(strict)
    }
}

impl Walk for TokenList {
    fn walk(&self, _: &mut Check<'_, '_>) {}
    fn round_trip(&self, header: Option<SipHeader>) -> Option<&'static str> {
        let header = header?;
        match TokenList::parse_strict(header, &self.to_string()) {
            Err(_) => Some("strict-err"),
            Ok(back) if back != *self => Some("unequal"),
            Ok(_) => None,
        }
    }
}

macro_rules! walk_typed {
    ($($Variant:ident),+) => {
        impl Walk for TypedValue {
            fn walk(&self, c: &mut Check<'_, '_>) {
                match self {
                    $(TypedValue::$Variant(v) => v.walk(c),)+
                    _ => {}
                }
            }
            fn round_trip(&self, header: Option<SipHeader>) -> Option<&'static str> {
                match self {
                    $(TypedValue::$Variant(v) => v.round_trip(header),)+
                    _ => Some("unhandled-variant"),
                }
            }
        }
    };
}

walk_typed!(
    Addr,
    AddrList,
    Contact,
    UriInfo,
    HistoryInfo,
    Via,
    Warning,
    Security,
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    Geolocation,
    Reason,
    CallId,
    Replaces,
    Join,
    TargetDialog,
    Auth,
    Tokens
);

/// Count, walk and round-trip one parse result; `rows` or `whole` hold the
/// text it was read from.
fn tally<T: Walk>(
    gate: &mut Gate,
    name: &'static str,
    header: Option<SipHeader>,
    result: Result<sip_header::Parsed<T>, ParseError>,
    rows: &[&str],
    whole: Option<&str>,
) {
    bump(&mut gate.attempted, name.to_string());
    let parsed = match result {
        Ok(p) => p,
        Err(e) => {
            bump(&mut gate.errors, format!("{name} {}", error_code(&e)));
            return;
        }
    };
    bump(&mut gate.parsed, name.to_string());
    let mut c = Check {
        gate,
        header: name,
        rows,
        whole,
    };
    c.warnings(&parsed.warnings);
    parsed.value.walk(&mut c);
    if parsed.warnings.is_empty() {
        bump(&mut gate.roundtrip_checks, name.to_string());
        if let Some(why) = parsed.value.round_trip(header) {
            bump(&mut gate.roundtrip_failures, format!("{name} {why}"));
        }
    }
}

fn check(gate: &mut Gate, store: &SipMessageHeaders<'_>, header: SipHeader) {
    let name = header.as_str();
    let result = match store.parse_typed(header) {
        Err(ParseError::Malformed(f)) if f.code == FaultCode::WrongHeader => return,
        Ok(None) => {
            bump(&mut gate.errors, format!("{name} absent"));
            return;
        }
        Ok(Some(p)) => Ok(p),
        Err(e) => Err(e),
    };
    let Ok(rows) = store.sip_header_rows(header) else {
        bump(&mut gate.errors, format!("{name} store-rows"));
        return;
    };
    tally(gate, name, Some(header), result, &rows, None);
}

/// The Request-URI as the message's own value.
struct RequestUri {
    uri: Uri,
    span: Span,
}

impl Walk for RequestUri {
    fn walk(&self, c: &mut Check<'_, '_>) {
        c.uri(Some(self.span), &self.uri);
    }
    fn round_trip(&self, _: Option<SipHeader>) -> Option<&'static str> {
        match Uri::parse_strict(&self.uri.to_string()) {
            Err(_) => Some("strict-err"),
            Ok(back) if back != self.uri => Some("unequal"),
            Ok(_) => None,
        }
    }
}

fn request_uri(gate: &mut Gate, text: &str) {
    let result = match extract_request_line(text) {
        Ok(None) => return,
        Ok(Some(line)) => line.uri_with_warnings().map(|p| {
            p.map(|uri| RequestUri {
                uri,
                span: line.uri_span(),
            })
        }),
        Err(e) => Err(e),
    };
    tally(gate, REQUEST_URI, None, result, &[], Some(text));
}

fn gate_message(gate: &mut Gate, content: &[u8], lib_rows: Option<Vec<(String, String)>>) {
    gate.messages += 1;
    let text = String::from_utf8_lossy(content);
    let store = SipMessageHeaders::new(&text);
    gate.skipped_lines += store.skipped().len() as u64;

    let rows_full: Vec<(&str, &str)> = store.iter().collect();
    for (name, _) in &rows_full {
        bump(&mut gate.rows_full, catalog_name(name));
    }
    match lib_rows {
        Some(rows_lib) => {
            for (name, _) in &rows_lib {
                bump(&mut gate.rows_lib, catalog_name(name));
            }
            let same = rows_lib.len() == rows_full.len()
                && rows_lib
                    .iter()
                    .zip(&rows_full)
                    .all(|((n3, v3), (n4, v4))| n3 == n4 && v3 == v4);
            if !same {
                gate.extraction_diff_messages += 1;
            }
        }
        None => gate.lib_parse_err += 1,
    }

    if catch_unwind(AssertUnwindSafe(|| request_uri(gate, &text))).is_err() {
        bump(&mut gate.panics, REQUEST_URI.to_string());
    }

    let mut seen: Vec<SipHeader> = Vec::new();
    for (name, _) in &rows_full {
        let Ok(header) = SipHeader::parse_name(name) else {
            continue;
        };
        if seen.contains(&header) {
            continue;
        }
        seen.push(header);
        let outcome = catch_unwind(AssertUnwindSafe(|| check(gate, &store, header)));
        if outcome.is_err() {
            bump(&mut gate.panics, header.as_str().to_string());
        }
    }
}

fn gate_file(path: &Path) -> Gate {
    let mut gate = Gate::default();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => panic!("open {}: {e}", path.display()),
    };
    for msg in MessageIterator::new(file).flatten() {
        let lib_rows = msg.parse().ok().map(|p| p.headers.to_vec());
        gate_message(&mut gate, &msg.content, lib_rows);
    }
    gate
}

fn print(title: &str, map: &Count) {
    eprintln!("\n{title}:");
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (k, v) in rows {
        eprintln!("  {k}: {v}");
    }
}

#[test]
fn sip_header_corpus_gate() {
    let corpus = Corpus::discover();
    if corpus.is_empty() {
        eprintln!("no .dump files found in samples/, skipping");
        return;
    }
    std::panic::set_hook(Box::new(|_| {}));
    let total = corpus.run(gate_file);
    drop(std::panic::take_hook());

    eprintln!("\n=== sip-header corpus gate ===");
    eprintln!("messages: {}", total.messages);
    eprintln!("library parse errors: {}", total.lib_parse_err);
    eprintln!("skipped header lines: {}", total.skipped_lines);
    eprintln!(
        "messages whose library rows differ from whole-message rows: {}",
        total.extraction_diff_messages
    );
    let mut row_diff = Count::new();
    for name in total.rows_lib.keys().chain(total.rows_full.keys()) {
        let a = total.rows_lib.get(name).copied().unwrap_or(0);
        let b = total.rows_full.get(name).copied().unwrap_or(0);
        if a != b {
            row_diff.insert(format!("{name} library={a} message"), b);
        }
    }
    print("row count differences by header", &row_diff);
    print("attempted by header", &total.attempted);
    print("parsed by header", &total.parsed);
    print("errors by header and code", &total.errors);
    print("warnings by code and kind", &total.warnings);
    print("warnings by header and code", &total.warnings_by_header);
    print("panics by header", &total.panics);
    print("span checks by header and kind", &total.span_checks);
    print(
        "span failures by header, kind and cause",
        &total.span_failures,
    );
    print("strict round trips by header", &total.roundtrip_checks);
    print(
        "strict round-trip failures by header",
        &total.roundtrip_failures,
    );

    assert!(total.panics.is_empty(), "sip-header panicked");
}
