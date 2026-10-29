use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use clap::{Parser, ValueEnum};
use regex::Regex;
use tracing::{debug, warn};

use freeswitch_sofia_trace_parser::types::{Direction, SipMessageType};
use freeswitch_sofia_trace_parser::{
    FrameIterator, GrepFilter, MessageIterator, ParseError, ParseStats, ParsedMessageIterator,
    ParsedSipMessage, SipMessage, StaleClock,
};

mod pcap;

enum OutputMode {
    Summary,
    Full,
    Headers,
    Body,
}

#[derive(Parser)]
#[command(
    name = "freeswitch-sofia-trace-parser",
    about = "Parse and filter FreeSWITCH mod_sofia SIP trace dump files"
)]
struct Cli {
    /// Dump files to parse (- for stdin, default: stdin)
    files: Vec<String>,

    /// Include SIP method (request + responses via CSeq), repeatable
    #[arg(short, long = "method", value_name = "VERB")]
    method: Vec<String>,

    /// Exclude SIP method (request + responses via CSeq), repeatable
    #[arg(short = 'x', long = "exclude", value_name = "VERB")]
    exclude: Vec<String>,

    /// Match Call-ID by regex
    #[arg(short = 'c', long = "call-id", value_name = "REGEX")]
    call_id: Option<String>,

    /// Filter by direction (recv/sent)
    #[arg(short, long, value_name = "DIR")]
    direction: Option<DirectionArg>,

    /// Match address by regex
    #[arg(short, long, value_name = "REGEX")]
    address: Option<String>,

    /// Match header value by regex (NAME=REGEX), repeatable
    #[arg(short = 'H', long = "header", value_name = "NAME=REGEX")]
    header: Vec<String>,

    /// Match regex against message body
    #[arg(short = 'b', long = "body-grep", value_name = "REGEX")]
    body_grep: Option<String>,

    /// Match regex against full reconstructed SIP message
    #[arg(short = 'g', long = "grep", value_name = "REGEX")]
    grep: Option<String>,

    /// Output all messages sharing Call-IDs with matched messages
    #[arg(short = 'D', long = "dialog")]
    dialog: bool,

    /// Include OPTIONS messages (excluded by default)
    #[arg(long = "all-methods")]
    all_methods: bool,

    /// Show full SIP message content
    #[arg(long, group = "output_mode")]
    full: bool,

    /// Show headers only, no body
    #[arg(long, group = "output_mode")]
    headers: bool,

    /// Show body only
    #[arg(long, group = "output_mode")]
    body: bool,

    /// Show raw reassembled bytes (level 2)
    #[arg(long, group = "output_mode")]
    raw: bool,

    /// Show raw frames (level 1)
    #[arg(long, group = "output_mode")]
    frames: bool,

    /// Show statistics summary
    #[arg(long, group = "output_mode")]
    stats: bool,

    /// Emit libpcap to stdout (use --pcap-layer to pick depth)
    #[arg(long, group = "output_mode")]
    pcap_export: bool,

    /// Pcap depth: 3 = Level-1 frames as IP+SIP (proto 253), 4 = Level-2 messages as IP+UDP/TCP+SIP
    #[arg(long, value_name = "N", requires = "pcap_export")]
    pcap_layer: Option<PcapLayerArg>,

    /// Report unparsed input regions to stderr
    #[arg(long)]
    unparsed: bool,

    /// Skip grep separator filtering (faster when reading files directly)
    #[arg(long)]
    no_grep_filter: bool,

    /// Increase verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DirectionArg {
    Recv,
    Sent,
}

impl From<DirectionArg> for Direction {
    fn from(arg: DirectionArg) -> Self {
        match arg {
            DirectionArg::Recv => Direction::Recv,
            DirectionArg::Sent => Direction::Sent,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PcapLayerArg {
    #[value(name = "3")]
    Network,
    #[value(name = "4")]
    Transport,
}

struct CompiledFilters {
    methods: Vec<String>,
    excludes: Vec<String>,
    exclude_options: bool,
    call_id: Option<Regex>,
    direction: Option<Direction>,
    address: Option<Regex>,
    headers: Vec<(String, Regex)>,
    body_grep: Option<Regex>,
    grep: Option<Regex>,
}

impl CompiledFilters {
    /// Whether the run asked for any SIP-level filtering. The default OPTIONS
    /// exclusion is not a request, so it does not count.
    fn is_empty(&self) -> bool {
        self.methods.is_empty()
            && self.excludes.is_empty()
            && self.call_id.is_none()
            && self.direction.is_none()
            && self.address.is_none()
            && self.headers.is_empty()
            && self.body_grep.is_none()
            && self.grep.is_none()
    }

    fn excludes_method(&self, method: &str) -> bool {
        if self.exclude_options && method.eq_ignore_ascii_case("OPTIONS") {
            return true;
        }

        !self.excludes.is_empty() && self.excludes.iter().any(|m| m.eq_ignore_ascii_case(method))
    }

    fn selects_method(&self, method: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }

    fn is_excluded(&self, msg: &ParsedSipMessage) -> bool {
        self.excludes_method(msg.method().unwrap_or(""))
    }

    /// `--exclude` and the default OPTIONS exclusion, settled from the
    /// reassembled bytes. A message whose method those bytes do not settle is
    /// kept, so `matches` still decides it after the parse.
    fn excluded_before_parse(&self, msg: &SipMessage) -> bool {
        msg.method().is_some_and(|m| self.excludes_method(m))
    }

    /// Also applies `--method`. Only for paths that discard what they do not
    /// output: `--dialog` emits a matched dialog's other methods.
    fn rejected_before_parse(&self, msg: &SipMessage) -> bool {
        msg.method()
            .is_some_and(|m| self.excludes_method(m) || !self.selects_method(m))
    }

    fn matches(&self, msg: &ParsedSipMessage) -> bool {
        if self.is_excluded(msg) {
            return false;
        }

        if !self.selects_method(msg.method().unwrap_or("")) {
            return false;
        }

        if let Some(ref re) = self.call_id {
            match msg.call_id() {
                Some(cid) if re.is_match(cid) => {}
                _ => return false,
            }
        }

        if let Some(dir) = self.direction {
            if msg.direction != dir {
                return false;
            }
        }

        if let Some(ref re) = self.address {
            if !re.is_match(&msg.address) {
                return false;
            }
        }

        for (name, re) in &self.headers {
            if !msg.headers.values(name).any(|v| re.is_match(v)) {
                return false;
            }
        }

        if let Some(ref re) = self.body_grep {
            let body_str = msg.body_text();
            if !re.is_match(&body_str) {
                return false;
            }
        }

        if let Some(ref re) = self.grep {
            let full = msg.to_bytes();
            let full_str = String::from_utf8_lossy(&full);
            if !re.is_match(&full_str) {
                return false;
            }
        }

        true
    }
}

fn compile_regex(pattern: &str, label: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            eprintln!("invalid {label} regex '{pattern}': {e}");
            process::exit(2);
        }
    }
}

fn compile_filters(cli: &Cli) -> CompiledFilters {
    let methods: Vec<String> = cli.method.iter().map(|m| m.to_uppercase()).collect();
    let excludes: Vec<String> = cli.exclude.iter().map(|m| m.to_uppercase()).collect();

    let exclude_options = !cli.all_methods && !methods.iter().any(|m| m == "OPTIONS");

    let call_id = cli.call_id.as_ref().map(|p| compile_regex(p, "call-id"));

    let direction = cli.direction.map(Direction::from);

    let address = cli.address.as_ref().map(|p| compile_regex(p, "address"));

    let mut headers = Vec::new();
    for spec in &cli.header {
        let eq = match spec.find('=') {
            Some(pos) => pos,
            None => {
                eprintln!("invalid header filter '{spec}': expected NAME=REGEX");
                process::exit(2);
            }
        };
        let name = spec[..eq].to_string();
        let re = compile_regex(&spec[eq + 1..], &format!("header {name}"));
        headers.push((name, re));
    }

    let body_grep = cli
        .body_grep
        .as_ref()
        .map(|p| compile_regex(p, "body-grep"));
    let grep = cli.grep.as_ref().map(|p| compile_regex(p, "grep"));

    CompiledFilters {
        methods,
        excludes,
        exclude_options,
        call_id,
        direction,
        address,
        headers,
        body_grep,
        grep,
    }
}

fn output_mode(cli: &Cli) -> OutputMode {
    if cli.full {
        OutputMode::Full
    } else if cli.headers {
        OutputMode::Headers
    } else if cli.body {
        OutputMode::Body
    } else {
        OutputMode::Summary
    }
}

fn open_input(files: &[String], grep_filter: bool) -> Box<dyn Read> {
    let raw: Box<dyn Read> = if files.is_empty() || (files.len() == 1 && files[0] == "-") {
        Box::new(io::stdin().lock())
    } else {
        let mut readers: Vec<Box<dyn Read>> = Vec::new();
        for path in files {
            if path == "-" {
                readers.push(Box::new(io::stdin().lock()));
            } else {
                match File::open(path) {
                    Ok(f) => readers.push(Box::new(f)),
                    Err(e) => {
                        eprintln!("{path}: {e}");
                        process::exit(1);
                    }
                }
            }
        }

        if readers.len() == 1 {
            readers.remove(0)
        } else {
            let mut chain: Box<dyn Read> = readers.remove(0);
            for r in readers {
                chain = Box::new(chain.chain(r));
            }
            chain
        }
    };
    if grep_filter {
        Box::new(GrepFilter::new(raw))
    } else {
        raw
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()),
        )
        .with_writer(io::stderr)
        .init();
}

fn print_lossy(bytes: &[u8]) {
    let s = String::from_utf8_lossy(bytes);
    print!("{s}");
    if !s.ends_with('\n') {
        println!();
    }
}

fn format_summary(msg: &ParsedSipMessage) -> String {
    let call_id = msg.call_id().unwrap_or("-");
    format!(
        "{} {} {}/{} {} {}",
        msg.timestamp,
        msg.direction,
        msg.transport,
        msg.address,
        msg.message_type.summary(),
        call_id
    )
}

fn format_frame_header(msg: &ParsedSipMessage) -> String {
    format!(
        "{} ({} frames) {}",
        msg.meta(),
        msg.frame_count,
        msg.message_type.summary(),
    )
}

fn output_full(msg: &ParsedSipMessage) {
    println!("{}", format_frame_header(msg));
    print_lossy(&msg.to_bytes());
}

fn output_headers(msg: &ParsedSipMessage) {
    println!("{}", format_frame_header(msg));
    match &msg.message_type {
        SipMessageType::Request { method, uri } => {
            println!("{method} {uri} SIP/2.0");
        }
        SipMessageType::Response { code, reason } => {
            println!("SIP/2.0 {code} {reason}");
        }
    }
    for (name, value) in &msg.headers {
        println!("{name}: {value}");
    }
}

fn output_body(msg: &ParsedSipMessage) {
    if !msg.body.is_empty() {
        print_lossy(&msg.body);
    }
}

fn output_message(mode: &OutputMode, msg: &ParsedSipMessage) {
    match mode {
        OutputMode::Summary => println!("{}", format_summary(msg)),
        OutputMode::Full => output_full(msg),
        OutputMode::Headers => output_headers(msg),
        OutputMode::Body => output_body(msg),
    }
}

fn run_frames(reader: Box<dyn Read>, capture_skipped: bool) -> ParseStats {
    let mut iter = FrameIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(frame) => {
                println!(
                    "{} {} bytes {} {}/{} at {}",
                    frame.direction,
                    frame.byte_count,
                    frame.direction.preposition(),
                    frame.transport,
                    frame.address,
                    frame.timestamp,
                );
                print_lossy(&frame.content);
            }
            Err(ref e) => log_parse_error("frame error", e),
        }
    }
    iter.stats().clone()
}

fn run_raw(reader: Box<dyn Read>, capture_skipped: bool) -> ParseStats {
    let mut iter = MessageIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(msg) => {
                println!(
                    "{} ({} frames, {} bytes)",
                    msg.meta(),
                    msg.frame_count,
                    msg.content.len(),
                );
                print_lossy(&msg.content);
            }
            Err(ref e) => log_parse_error("message error", e),
        }
    }
    iter.parse_stats().clone()
}

#[derive(Default)]
struct MessageStats {
    method_counts: HashMap<String, usize>,
    status_counts: HashMap<u16, usize>,
    direction_counts: HashMap<Direction, usize>,
    total: usize,
    matched: usize,
    errors: usize,
    total_frames: usize,
    multi_frame_msgs: usize,
    max_frame_count: usize,
    input: ParseStats,
}

impl MessageStats {
    fn record(&mut self, msg: &ParsedSipMessage, matched: bool) {
        self.total += 1;
        self.total_frames += msg.frame_count;
        if msg.frame_count > 1 {
            self.multi_frame_msgs += 1;
            self.max_frame_count = self.max_frame_count.max(msg.frame_count);
        }
        if !matched {
            return;
        }
        self.matched += 1;
        *self.direction_counts.entry(msg.direction).or_default() += 1;
        match &msg.message_type {
            SipMessageType::Request { method, .. } => {
                *self.method_counts.entry(method.clone()).or_default() += 1;
            }
            SipMessageType::Response { code, .. } => {
                *self.status_counts.entry(*code).or_default() += 1;
                if let Some(method) = msg.method() {
                    *self.method_counts.entry(method.to_string()).or_default() += 1;
                }
            }
        }
    }

    fn record_error(&mut self) {
        self.total += 1;
        self.errors += 1;
    }
}

impl std::fmt::Display for MessageStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "total: {}", self.total)?;
        writeln!(f, "matched: {}", self.matched)?;
        if self.errors > 0 {
            writeln!(f, "parse errors: {}", self.errors)?;
        }

        if let Some(&n) = self.direction_counts.get(&Direction::Recv) {
            writeln!(f, "recv: {n}")?;
        }
        if let Some(&n) = self.direction_counts.get(&Direction::Sent) {
            writeln!(f, "sent: {n}")?;
        }

        writeln!(f, "\nreassembly:")?;
        writeln!(f, "  frames: {}", self.total_frames)?;
        writeln!(f, "  multi-frame messages: {}", self.multi_frame_msgs)?;
        if self.max_frame_count > 1 {
            writeln!(f, "  max frames per message: {}", self.max_frame_count)?;
        }

        let (read, skipped) = (self.input.bytes_read(), self.input.bytes_skipped());
        if read > 0 {
            let parsed_pct = ((read - skipped) as f64 / read as f64) * 100.0;
            writeln!(f, "\ninput:")?;
            writeln!(f, "  bytes: {read}")?;
            writeln!(
                f,
                "  parsed: {:.3}% ({}/{})",
                parsed_pct,
                read - skipped,
                read
            )?;
            if skipped > 0 {
                writeln!(f, "  skipped: {skipped} bytes")?;
            }
            if self.input.incomplete_frames() > 0 {
                writeln!(
                    f,
                    "  incomplete at end of input: {} frames, {} bytes short",
                    self.input.incomplete_frames(),
                    self.input.incomplete_frame_bytes()
                )?;
            }
            if self.input.stale_evictions() > 0 {
                writeln!(
                    f,
                    "  dropped with stale connections: {} buffers, {} bytes",
                    self.input.stale_evictions(),
                    self.input.stale_evicted_bytes()
                )?;
            }
            if self.input.non_sip_prefixes() > 0 {
                writeln!(
                    f,
                    "  resynced past non-SIP data: {} times, {} bytes",
                    self.input.non_sip_prefixes(),
                    self.input.non_sip_prefix_bytes()
                )?;
            }
            if self.input.unusable_content_lengths() > 0 {
                writeln!(
                    f,
                    "  messages ended at their blank line, Content-Length unusable: {}",
                    self.input.unusable_content_lengths()
                )?;
            }
        }

        let mut methods: Vec<_> = self.method_counts.iter().collect();
        methods.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        if !methods.is_empty() {
            writeln!(f, "\nmethods:")?;
            for (method, count) in &methods {
                writeln!(f, "  {method}: {count}")?;
            }
        }

        let mut statuses: Vec<_> = self.status_counts.iter().collect();
        statuses.sort_by_key(|&(code, _)| *code);
        if !statuses.is_empty() {
            writeln!(f, "\nresponse codes:")?;
            for (code, count) in &statuses {
                writeln!(f, "  {code}: {count}")?;
            }
        }

        Ok(())
    }
}

fn run_stats(
    reader: Box<dyn Read>,
    filters: &CompiledFilters,
    capture_skipped: bool,
) -> ParseStats {
    let mut counts = MessageStats::default();
    let mut iter = ParsedMessageIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(msg) => {
                let matched = filters.matches(&msg);
                counts.record(&msg, matched);
            }
            Err(_) => counts.record_error(),
        }
    }
    counts.input = iter.parse_stats().clone();
    print!("{counts}");
    counts.input
}

fn run_filtered(
    reader: Box<dyn Read>,
    mode: &OutputMode,
    filters: &CompiledFilters,
    capture_skipped: bool,
) -> ParseStats {
    let mut iter = MessageIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        let sip_msg = match result {
            Ok(m) => m,
            Err(ref e) => {
                log_parse_error("message error", e);
                continue;
            }
        };

        if filters.rejected_before_parse(&sip_msg) {
            continue;
        }

        match sip_msg.parse() {
            Ok(msg) => {
                if !filters.matches(&msg) {
                    continue;
                }
                output_message(mode, &msg);
            }
            Err(ref e) => log_parse_error("parse error", e),
        }
    }
    iter.parse_stats().clone()
}

struct DialogState {
    messages: Vec<SipMessage>,
    matched: bool,
    saw_bye: bool,
    saw_bye_response: bool,
    ended: bool,
    last_seen: u64,
}

/// A response that ends the INVITE transaction it answers without a dialog.
fn is_invite_failure(parsed: &ParsedSipMessage) -> bool {
    let SipMessageType::Response { code, .. } = &parsed.message_type else {
        return false;
    };
    // An auth challenge is answered by a re-sent INVITE on the same Call-ID.
    if matches!(code, 401 | 407) {
        return false;
    }
    (400..700).contains(code)
        && parsed
            .method()
            .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))
}

fn run_dialog(
    reader: Box<dyn Read>,
    mode: &OutputMode,
    filters: &CompiledFilters,
    capture_skipped: bool,
) -> ParseStats {
    let mut dialogs: HashMap<String, DialogState> = HashMap::new();
    let mut clock = StaleClock::new();

    let mut iter = MessageIterator::new(reader).capture_skipped(capture_skipped);
    // Single pass: collect messages by Call-ID, track matches
    for result in &mut iter {
        let sip_msg = match result {
            Ok(m) => m,
            Err(ref e) => {
                log_parse_error("message error", e);
                continue;
            }
        };

        if filters.excluded_before_parse(&sip_msg) {
            continue;
        }

        let parsed = match sip_msg.parse() {
            Ok(p) => p,
            Err(ref e) => {
                log_parse_error("parse error", e);
                continue;
            }
        };

        if filters.is_excluded(&parsed) {
            continue;
        }

        let call_id = match parsed.call_id() {
            Some(cid) => cid.to_string(),
            None => continue,
        };

        let now = clock.observe(sip_msg.timestamp);
        if clock.sweep_due() {
            let before = dialogs.len();
            dialogs.retain(|_, state| state.matched || !clock.is_stale(state.last_seen));
            let dropped = before - dialogs.len();
            if dropped > 0 {
                debug!(dialogs = dropped, "dropped stale unmatched dialogs");
            }
        }

        let is_match = filters.matches(&parsed);

        // Detect BYE and BYE responses for pruning
        let is_bye_request = matches!(
            &parsed.message_type,
            SipMessageType::Request { method, .. } if method.eq_ignore_ascii_case("BYE")
        );
        let is_bye_response = matches!(&parsed.message_type, SipMessageType::Response { .. })
            && parsed
                .method()
                .map(|m| m.eq_ignore_ascii_case("BYE"))
                .unwrap_or(false);

        let is_cancel = matches!(
            &parsed.message_type,
            SipMessageType::Request { method, .. } if method.eq_ignore_ascii_case("CANCEL")
        );

        let state = dialogs
            .entry(call_id.clone())
            .or_insert_with(|| DialogState {
                messages: Vec::new(),
                matched: false,
                saw_bye: false,
                saw_bye_response: false,
                ended: false,
                last_seen: now,
            });

        state.last_seen = now;
        if is_match {
            state.matched = true;
        }
        if is_bye_request {
            state.saw_bye = true;
        }
        if is_bye_response {
            state.saw_bye_response = true;
        }
        if is_cancel || is_invite_failure(&parsed) {
            state.ended = true;
        }

        state.messages.push(sip_msg);

        // Prune: dialog terminated and never matched
        let terminated = state.ended || (state.saw_bye && state.saw_bye_response);
        if terminated && !state.matched {
            dialogs.remove(&call_id);
        }
    }

    // Output matched dialogs in chronological order
    let mut matched_messages: Vec<SipMessage> = Vec::new();
    // The timestamp sort below is stable, so HashMap order would otherwise
    // decide how messages sharing a timestamp are interleaved.
    let mut by_call_id: Vec<_> = dialogs.into_iter().collect();
    by_call_id.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, state) in by_call_id {
        if state.matched {
            matched_messages.extend(state.messages);
        }
    }

    // Sort by timestamp for chronological output across Call-IDs
    matched_messages.sort_by_key(|m| m.timestamp.sort_key());

    for sip_msg in &matched_messages {
        match sip_msg.parse() {
            Ok(parsed) => output_message(mode, &parsed),
            Err(ref e) => log_parse_error("parse error on output", e),
        }
    }

    iter.parse_stats().clone()
}

fn log_parse_error(context: &str, e: &ParseError) {
    match e {
        ParseError::TransportNoise { .. } => debug!("{context}: {e}"),
        _ => warn!("{context}: {e}"),
    }
}

fn encode_qp(data: &[u8]) -> String {
    use quoted_printable::{encode_with_options, InputMode, Options};
    let opts = Options::default()
        .input_mode(InputMode::Binary)
        .line_length_limit(usize::MAX);
    encode_with_options(data, opts)
}

fn print_unparsed(stats: &ParseStats) {
    for region in stats.unparsed_regions() {
        eprintln!(
            "{}-{} ({} bytes): {}",
            region.offset,
            region.offset + region.length - 1,
            region.length,
            region.reason
        );
        if let Some(data) = &region.data {
            eprintln!("{}", encode_qp(data));
        }
    }
}

/// What the run does, with whatever it needs settled before any input is
/// opened. Only the variants that filter compile a regex.
enum Action {
    PcapLayer3,
    PcapLayer4(CompiledFilters),
    Frames,
    Raw,
    Dialog(OutputMode, CompiledFilters),
    Stats(CompiledFilters),
    Filtered(OutputMode, CompiledFilters),
}

fn resolve_action(cli: &Cli) -> Action {
    if cli.pcap_export {
        if cli.pcap_layer == Some(PcapLayerArg::Network) {
            Action::PcapLayer3
        } else {
            Action::PcapLayer4(compile_filters(cli))
        }
    } else if cli.frames {
        Action::Frames
    } else if cli.raw {
        Action::Raw
    } else if cli.dialog {
        Action::Dialog(output_mode(cli), compile_filters(cli))
    } else if cli.stats {
        Action::Stats(compile_filters(cli))
    } else {
        Action::Filtered(output_mode(cli), compile_filters(cli))
    }
}

fn validate(cli: &Cli) {
    if cli.dialog && (cli.raw || cli.frames) {
        eprintln!("--dialog is incompatible with --raw and --frames");
        process::exit(2);
    }

    if cli.dialog && cli.stats {
        eprintln!("--dialog is incompatible with --stats");
        process::exit(2);
    }

    if cli.pcap_export
        && cli.pcap_layer == Some(PcapLayerArg::Network)
        && (cli.dialog || !compile_filters(cli).is_empty())
    {
        eprintln!("--pcap-layer 3 emits raw frames; SIP-level filters are not applicable");
        process::exit(2);
    }
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    validate(&cli);

    let capture = cli.unparsed;
    let action = resolve_action(&cli);
    let input = open_input(&cli.files, !cli.no_grep_filter);

    let stats = match &action {
        Action::PcapLayer3 => pcap::run_layer3(input, capture),
        Action::PcapLayer4(filters) => pcap::run_layer4(input, filters, capture),
        Action::Frames => run_frames(input, capture),
        Action::Raw => run_raw(input, capture),
        Action::Dialog(mode, filters) => run_dialog(input, mode, filters, capture),
        Action::Stats(filters) => run_stats(input, filters, capture),
        Action::Filtered(mode, filters) => run_filtered(input, mode, filters, capture),
    };

    if cli.unparsed {
        print_unparsed(&stats);
    }
}

#[cfg(test)]
mod encode_qp_tests {
    use super::*;

    #[test]
    fn binary_mode_without_soft_line_breaks() {
        assert_eq!(encode_qp(b"\r\n\x00\xFF"), "=0D=0A=00=FF");
        let long = "A".repeat(200);
        assert_eq!(encode_qp(long.as_bytes()), long);
    }
}
