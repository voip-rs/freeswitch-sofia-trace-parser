use std::collections::HashMap;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::SipMessageType;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;
use freeswitch_sofia_trace_torture::{Corpus, Stats};
use sip_header::sip_uri::{Uri, UriParse};
use sip_header::{HeaderParse, SipHeaderAddr};

const NAMEADDR_HEADERS: &[&str] = &[
    "from",
    "to",
    "contact",
    "p-asserted-identity",
    "p-preferred-identity",
    "route",
    "record-route",
    "refer-to",
    "call-info",
    "reply-to",
];

#[derive(Default)]
struct UriStats {
    request_uri_total: usize,
    request_uri_ok: usize,
    nameaddr_total: usize,
    nameaddr_ok: usize,
    by_scheme: HashMap<String, usize>,
    by_header: HashMap<String, (usize, usize)>,
    failures: Vec<(String, String, String)>,
}

impl Stats for UriStats {
    fn ok(&self) -> usize {
        self.request_uri_ok + self.nameaddr_ok
    }

    fn total(&self) -> usize {
        self.request_uri_total + self.nameaddr_total
    }

    fn merge(&mut self, other: Self) {
        self.request_uri_total += other.request_uri_total;
        self.request_uri_ok += other.request_uri_ok;
        self.nameaddr_total += other.nameaddr_total;
        self.nameaddr_ok += other.nameaddr_ok;
        for (scheme, count) in other.by_scheme {
            *self.by_scheme.entry(scheme).or_default() += count;
        }
        for (header, (ok, total)) in other.by_header {
            let entry = self.by_header.entry(header).or_insert((0, 0));
            entry.0 += ok;
            entry.1 += total;
        }
        self.failures.extend(other.failures);
    }
}

impl UriStats {
    fn record_uri_type(&mut self, uri: &Uri) {
        *self
            .by_scheme
            .entry(uri.scheme().unwrap_or("(none)").to_string())
            .or_default() += 1;
    }

    fn record_request_uri(&mut self, uri: &str, file: &str) {
        self.request_uri_total += 1;
        match Uri::parse(uri) {
            Ok(parsed) => {
                self.request_uri_ok += 1;
                self.record_uri_type(&parsed);
            }
            Err(e) => {
                if self.failures.len() < 50 {
                    self.failures.push((
                        file.to_string(),
                        format!("Request-URI: {uri}"),
                        e.to_string(),
                    ));
                }
            }
        }
    }

    fn record_nameaddr(&mut self, header: &str, value: &str, file: &str) {
        self.nameaddr_total += 1;
        let entry = self
            .by_header
            .entry(header.to_lowercase())
            .or_insert((0, 0));
        entry.1 += 1;
        match SipHeaderAddr::parse(value) {
            Ok(parsed) => {
                self.nameaddr_ok += 1;
                entry.0 += 1;
                self.record_uri_type(parsed.uri());
            }
            Err(e) => {
                if self.failures.len() < 50 {
                    self.failures.push((
                        file.to_string(),
                        format!("{header}: {value}"),
                        e.to_string(),
                    ));
                }
            }
        }
    }
}

fn parse_file_uris(path: &Path) -> UriStats {
    let mut stats = UriStats::default();
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return stats,
    };

    for result in ParsedMessageIterator::new(file) {
        let msg = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let SipMessageType::Request { ref uri, .. } = msg.message_type {
            stats.record_request_uri(uri, &name);
        }

        for (header_name, header_value) in &msg.headers {
            if NAMEADDR_HEADERS
                .iter()
                .any(|h| header_name.eq_ignore_ascii_case(h))
            {
                stats.record_nameaddr(header_name, header_value, &name);
            }
        }
    }

    stats
}

#[test]
fn sip_uri_torture_all_samples() {
    let corpus = Corpus::discover();
    if corpus.is_empty() {
        eprintln!("no .dump files found in samples/, skipping");
        return;
    }

    eprintln!("\n=== sip-uri torture test results ===");
    eprintln!("files processed: {}", corpus.len());

    let total = corpus.run(parse_file_uris);

    eprintln!(
        "request URIs: {}/{} parsed",
        total.request_uri_ok, total.request_uri_total
    );
    eprintln!(
        "name-addr headers: {}/{} parsed",
        total.nameaddr_ok, total.nameaddr_total
    );
    eprintln!(
        "overall: {}/{} ({:.5}%)",
        total.ok(),
        total.total(),
        if total.total() > 0 {
            total.ok() as f64 / total.total() as f64 * 100.0
        } else {
            0.0
        }
    );

    eprintln!("\nby URI scheme:");
    let mut schemes: Vec<_> = total.by_scheme.iter().collect();
    schemes.sort_by(|a, b| b.1.cmp(a.1));
    for (scheme, count) in &schemes {
        eprintln!("  {scheme}: {count}");
    }

    eprintln!("\nby header:");
    let mut headers: Vec<_> = total.by_header.iter().collect();
    headers.sort_by_key(|(_, (_, total))| std::cmp::Reverse(*total));
    for (header, (ok, hdr_total)) in &headers {
        let pct = if *hdr_total > 0 {
            *ok as f64 / *hdr_total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!("  {header}: {ok}/{hdr_total} ({pct:.2}%)");
    }

    if !total.failures.is_empty() {
        eprintln!("\nfailure samples (first {}):", total.failures.len());
        for (file, input, err) in &total.failures {
            eprintln!("  [{file}] {input}");
            eprintln!("    error: {err}");
        }
    }

    assert!(total.total() > 0, "expected to find URIs in trace samples");

    let success_rate = total.ok() as f64 / total.total() as f64;
    assert!(
        success_rate > 0.99,
        "expected >99% parse success rate, got {:.2}% ({} failures out of {})",
        success_rate * 100.0,
        total.total() - total.ok(),
        total.total()
    );
}
