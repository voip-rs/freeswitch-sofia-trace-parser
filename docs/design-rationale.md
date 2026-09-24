# Design Rationale

## Why This Parser Exists

FreeSWITCH's `mod_sofia` writes SIP traffic to binary dump files at
`/var/log/freeswitch/sip_traces/{profile}/{profile}.dump`, rotated by logrotate
into `.dump.1.xz`, `.dump.2.xz`, etc. These files are the primary diagnostic
tool for NG-911 call tracing, incident reconstruction, and SIP interop debugging
in production PSAP environments.

The first parser was a Bash/awk script (`cauca_freeswitch-sip-trace-analyzer`)
that loaded entire dump files into memory (~2GB per profile), performed
line-by-line text matching, and couldn't handle TCP reassembly, multipart
MIME, or structured SIP parsing.

Its Rust successor (`freeswitch-sip-trace-analyzer`) tried to solve this
inline but accumulated four overlapping parsing subsystems over time, each
handling part of the format with different failure modes:

- A line-based parser using `recv `/`sent ` prefix detection that replaced
  `\x0B` with `^K` in output because it couldn't distinguish frame
  boundaries from `\x0B` appearing inside XML content.
- A `LazyMessageStitcher` that tried TCP reassembly by looking ahead
  through pre-split text strings, checking direction/connection/timestamp
  continuity with string heuristics — which broke on interleaved
  connections from different endpoints.
- A three-phase structured parser that introduced `memmap2`, `lz4_flex`,
  `tempfile`, and `lazy_static` as intermediate storage for a multi-pass
  approach.
- Supporting infrastructure for message hashing, deduplication, and
  memory-mapped output accumulation.

These subsystems had concrete bugs that surfaced on production data:
UTF-8 boundary panics when slicing SIP content at byte offsets that split
multi-byte sequences, incorrect TCP reassembly when same-direction frames
from different connections interleaved, and Content-Length splitting that
failed when body content contained SIP-like patterns. File concatenation
across logrotate boundaries (`cat dump.29 dump.28`) broke because the
inline parsers had no concept of truncated first frames.

This library extracted parsing into a dedicated, independently tested
concern. It replaced ~4,500 lines of fragile inline parsing with a
streaming `impl Read` API validated against 5.5GB of production dumps.
Separating parsing from application logic also unlocked downstream
features that were impractical against line-based text: dialog
participant role classification (Caller/Calltaker/Bridge/Responder from
typed headers and methods), AI-compact message formatting (abbreviated
headers via typed access instead of regex), and structure-aware
colorization that is correct by construction for any SIP method or
response code.

## Why Three Levels

The parser is split into three independent layers, each wrapping the previous:

```
Level 1: FrameIterator      raw bytes -> Frame (header + content)
Level 2: MessageIterator     Frame -> SipMessage (reassembled, split)
Level 3: ParsedMessageIterator  SipMessage -> ParsedSipMessage (headers, body)
```

This wasn't designed top-down from a spec. It emerged from the dump file format
itself: FreeSWITCH writes each `send()`/`recv()` as a separate frame with a text
header and `\x0B\n` boundary. TCP segments arrive as separate frames that need
reassembly. And SIP messages need header/body parsing for anything useful.

Each level is independently useful. A tool that just needs raw frame timing
doesn't pay for SIP parsing. A tool that needs reassembled message bytes
doesn't need to parse headers. The downstream `freeswitch-sip-trace-analyzer`
uses `ParsedMessageIterator` directly, while the torture test uses
`MessageIterator` to extract URIs from raw content.

Every level accepts `impl Read`, so they compose with files, pipes,
`xzcat` subprocesses, `Read::chain()` for file concatenation, and
`GrepFilter` for grep-piped input.

## Boundary Detection: byte_count First

Each frame header includes the byte count FreeSWITCH wrote:

```
recv 1234 bytes from tcp/10.0.0.1:5060 at 14:30:00.123456:
```

The frame ends at the next `\x0B\n` (vertical tab + newline). The naive approach
is to scan for `\x0B\n` in the content, but `\x0B` is valid ASCII that appears
in XML bodies, SDP, and JSON content. A scan-only approach would split frames
incorrectly.

The solution uses byte_count as the primary signal:

1. **Primary**: Check at the expected position (`content_start + byte_count`).
   If `\x0B` is there, accept it. This is correct for well-formed frames and
   handles file concatenation where garbage follows the boundary.

2. **Fallback**: Scan for `\x0B\n` followed by a valid frame header
   (`recv`/`sent N bytes ...`). This handles the rare case where byte_count
   is wrong (never observed in production, but defensive).

Production validation: zero byte_count mismatches across 6.9M+ frames in
83 dump files (~12GB). The primary path handles 100% of real-world data.

## Every Level Reports Where Its Record Began

Each frame, message and parsed message carries the byte position it started
at, against the stream the iterator consumed — the same origin the
unparsed-region records use. The position is the header's, not the content's,
and not the reader's: a source handing back one byte per call reports the
offsets of one handing back the whole file.

A reassembled message takes its first frame's offset, the frame its timestamp
also comes from, so the two agree about which part of the stream the message
belongs to. A read pulls whatever the socket had queued, so one frame can
carry several messages; each reports that frame's position, as each already
shares its timestamp. One frame bounds that approximation.

The offset rides on the value rather than being asked of the iterator,
because the two diverge: buffering and reassembly put the reader arbitrarily
far past the bytes that produced the message being emitted.

## Per-Connection TCP Buffering

The initial Level 2 implementation used naive consecutive-frame grouping:
if two frames had the same direction and address, concatenate them. This
broke immediately on real production data where frames from different
connections interleave:

```
recv 500 bytes from tcp/10.0.0.1:5060 ...   (connection A, fragment 1)
sent 200 bytes to tcp/10.0.0.2:5060 ...     (connection B, response)
recv 800 bytes from tcp/10.0.0.1:5060 ...   (connection A, fragment 2)
```

The fix was per-connection buffering keyed by direction and remote address.
Each connection maintains its own reassembly state. Frames are routed to the
correct buffer regardless of interleaving. Messages are emitted when headers
(`\r\n\r\n`) and Content-Length body bytes are fully available.

A buffer is removed the moment it holds no pending bytes, and a message's
frame count covers only the frames that carried it. This is critical for
constant-memory streaming: without eager removal, TLS profiles with
ephemeral source ports accumulate thousands of dead buffers over multi-day
runs.

## Stale Buffer Eviction

TLS connections use ephemeral source ports. Over a multi-day dump stream,
the buffer map grows without bound as new ports appear and old ones go
silent. The parser evicts buffers inactive for longer than the standard TCP
keepalive interval: any connection silent for that long in a VoIP environment
is dead. A non-empty buffer still held at end of input is flushed as an
incomplete message; one evicted mid-stream is discarded instead, and that loss
is counted in the parse statistics.

Elapsed time comes from the timestamp's own date when the header carries one;
time-only timestamps get a synthetic day counter that increments when the
clock wraps past midnight. The two share no epoch, so a stream that switches
format resets the clock rather than comparing across the switch. The CLI's
dialog grouping bounds its memory with the same clock and rule.

## Why SkipTracking Has Three Modes

Early versions accumulated every unparsed region in a `Vec<UnparsedRegion>`.
Processing 50+ dump files (50GB+) caused unbounded memory growth in the
region list alone, even though the actual parser maintained constant memory.

The fix was `SkipTracking`:

- **CountOnly** (default): Only maintain `bytes_read` and `bytes_skipped`
  counters. Zero allocation. This is what most consumers need.
- **TrackRegions**: Record offset, length, and reason for each skip.
  Useful for `--stats` output.
- **CaptureData**: Also keep the actual skipped bytes. Useful for
  `--unparsed` diagnostics with quoted-printable display.

The default is CountOnly because the parser processes arbitrarily large
inputs and most callers only care about the parse success rate, not the
exact bytes that were skipped.

## Skip Classification

Every byte in the input stream is either parsed into a frame or classified
with a `SkipReason`. This accounting was driven by a production need:
operators need to know whether "99.8% parsed" means "lost a few frames
at logrotate boundaries" or "hit corruption mid-stream."

The six reasons evolved from production observations:

- **PartialFirstFrame** — The first bytes of a dump file are almost always
  a truncated frame from logrotate. The file was rotated mid-write, so the
  new file starts with the tail of whatever frame was being written. This is
  expected and benign. Capped at the largest IP datagram plus its boundary.

- **OversizedFrame** — A skip larger than that cap, wherever it occurs.
  Indicates the input isn't a dump file (compressed data, binary garbage).
  The same cap bounds how far a declared byte count may run past the
  buffered bytes before boundary scanning takes over.

- **ReplayedFrame** — Logrotate's `copytruncate` creates a race: the
  frame being written when the file is rotated appears partially in both
  the old and new files. Detection heuristic: the skipped content ends with
  `\r\n\r\n\x0B\n` (SIP header terminator + frame boundary). Confirmed by
  hexdump: dump.28 starts with `NS\r\nRoute:...` which is the tail of
  dump.29's last OPTIONS response.

- **MidStreamSkip** — Unclassifiable garbage between valid frames. Rare in
  practice (never observed outside synthetic tests).

- **IncompleteFrame** — EOF arrived before `byte_count` bytes of content.
  The frame header declared N bytes but the file ended with fewer. Tracked
  separately so operators know the file was truncated, not corrupt.

- **InvalidHeader** — Data starts with `recv`/`sent` but fails header
  parsing. Usually a dump restart marker or inter-frame padding that
  wasn't fully stripped.

A single reader cannot separate a rotation cut from a real truncation, which
turns on the datagram size the caller expects, on whether it stitches adjacent
files back together, and on whether the file is the newest of a set. Severity
is the caller's to assign; the count and the total shortfall are maintained in
every tracking mode, so that judgement stays available where the region
records are not.

## TLS Keep-Alive and TransportNoise

RFC 5626 Section 3.5.1 specifies CRLF as a SIP application-layer
keep-alive. sofia-sip sends bare `\n` instead. These 1-byte frames
accumulate in TCP reassembly buffers because the reassembly logic
only recognized `\r\n` pairs as inter-message padding.

The fix operates at two levels:

**Level 2** (MessageIterator): `extract_complete()` drains leading
whitespace (CR, LF, SP, TAB) before looking for SIP message starts.
If the entire buffer is whitespace, it's cleared. This handles the
common case silently during reassembly.

**Level 3** (ParsedMessageIterator): If whitespace-only content escapes
Level 2 (e.g., accumulated during a flush), it returns
`ParseError::TransportNoise` instead of the misleading
`InvalidMessage("no CRLF found")`. This is a distinct error variant so
callers can filter it: the CLI logs it at `debug` level, not `warn`.

The distinction matters operationally. On a TLS profile with keep-alives
enabled, ~353 noise frames per dump file is normal. Logging them as
warnings would drown real errors.

## Content-Type-Aware Body Parsing

NG-911 infrastructure embeds SIP messages inside JSON bodies. A NOTIFY
with Content-Type `application/emergencyCallData.AbandonedCall+json`
contains a JSON object with an `invite` field holding a complete
INVITE message, but with literal `\r\n` escape sequences instead of
actual CRLF line endings.

Grepping for SIP headers in these bodies fails unless the JSON escapes
are resolved. Three methods address different use cases:

- **`body_data()`** returns raw bytes as lossy UTF-8. No processing.
  Use when you need the exact wire representation.

- **`body_text()`** unescapes RFC 8259 JSON string sequences for JSON
  content types: `\r\n` becomes CRLF, `\t` becomes tab, `\uXXXX`
  becomes Unicode (including surrogate pairs). Passthrough for
  non-JSON types. Use when grepping body content.

- **`json_field(key)`** parses the body as JSON and returns the
  unescaped string value of a top-level key. Returns None if the
  content type isn't JSON, the body isn't valid JSON, the key is
  missing, or the value isn't a string.

JSON detection matches `application/json` and any `application/*+json`
subtype, case-insensitive, ignoring media type parameters like
`charset=utf-8`.

`message/sipfrag` parts get a dedicated fragment parser: RFC 3420
fragments may lack a start line or a trailing CRLF, so they cannot
round-trip through the full-message parse, and treating them as opaque
text would hide the headers they legally carry.

## GrepFilter: Handling Piped Input

A common workflow is `grep -C5 'Call-ID.*abc123' profile.dump | parser`.
But `grep -C` inserts `--\n` separator lines between match groups, which
corrupt the binary frame stream.

`GrepFilter<R>` is a `Read` adapter that strips exactly `--\n` and
`--\r\n` lines from the input. It's applied in the CLI before the parser,
making piped grep output transparent. The filter preserves lines like
`---\n` or `-- \n` that aren't grep separators.

This was moved from `src/bin/grep.rs` to `src/grep.rs` and re-exported
from the library when the downstream `freeswitch-sip-trace-analyzer`
needed it. Binary-only code belongs in `src/bin/`; shared utilities
belong in the library.

## Library-First Design

This is a library crate. The CLI (`src/bin/main.rs`) is a sample
implementation, feature-gated behind `cli` to avoid pulling clap, regex,
and tracing-subscriber into library consumers.

Rules that emerged from production use:

- **No `unwrap()`/`expect()`/`panic!()` in library code.** Return
  `Result` or `Option`. Clippy denies them outside tests.

- **Root re-exports are an explicit list.** A glob would make every type
  added to a module public API on the day it is added, with no review.

- **Binary-only deps must be feature-gated.** Library consumers with
  `default-features = false` must not pull CLI dependencies.

- **CLI-only modules stay in `src/bin/`.** No `pub mod` in lib.rs for
  code that only the binary uses.

- **Never expose dependency types in public signatures.** A dependency
  major-version bump becomes a semver break if its types leak into the
  public API. All public signatures use standard library types.

- **Loss reaches the caller, never only the log.** Every loss is a
  returned error or a parse-statistics count, so the library logs a
  counted loss at info or below.

## Memory Profile

The parser processes arbitrarily large inputs with constant memory.
This was validated with jemalloc heap profiling and gdb inspection
during processing of 50+ chained dump files:

- `FrameIterator::buf` — 64KB capacity, ~200 bytes typical usage
- `MessageIterator::buffers` — 0 entries at steady state (evicted after extraction)
- `MessageIterator::ready` — 0 entries, capacity 10 (drained each iteration)

One production pitfall: using `Read::chain()` to concatenate 50+ XZ
files upfront keeps all LZMA decoder state alive simultaneously (172MB).
The fix is to open files lazily, one at a time, feeding them through
the parser sequentially.

## Multipart MIME for NG-911

NG-911 SIP messages carry both SDP (media negotiation) and PIDF/EIDO
(caller location) as multipart MIME bodies. The parser splits these
into separate `MimePart` structs with their own headers and bodies.

Production data: 1,223 multipart messages split into 2,446 parts
(always SDP + PIDF), zero failures. Boundary extraction handles
quoted boundaries and ignores MIME preamble text.

This was added specifically because emergency call analysis requires
extracting location data (PIDF-LO XML) separately from session
description (SDP), and no SIP library we found handled FreeSWITCH's
dump format.

Body access is uniform: every message yields its body as parts. A body
that does not split — not multipart, or multipart whose declared boundary
never appears in it — comes back as one part typed with the message's own
Content-Type, so no body is silently absent from a per-part loop.
Downstream redaction dispatches per part; a second code path for plain
bodies is a second place to forget a media type, and an unknown type has
to surface as a part for a fail-closed consumer to withhold it.

That fabricated part carries the message's `Content-*` headers, compact
forms expanded to their full names, less `Content-Length`, which counts
the message body and goes stale once a consumer rewrites the part.
Nothing in a per-part loop tells a fabricated part from a wire one, so a
transfer encoding visible on only one kind leaves redaction reading
encoded bytes as text.

Boundary delimiters match only as full RFC 2046 delimiter lines —
line-anchored, with the delimiter tail checked — never as substrings, so
binary content cannot fabricate parts and a boundary cannot match inside
a longer one. A body cut off before the close delimiter still surfaces
its trailing bytes as a part; truncation must not make bytes vanish from
a per-part loop.

Splitting is one level per call and never recursive on the library's
side: a nested `multipart/*` part surfaces intact with its media type,
and a caller that wants its children asks explicitly. Depth stays a
caller decision.

## Pcap on Demand from Text Traces

FreeSWITCH dumps are text traces of decrypted SIP. The natural workflow for an
operator is: open the dump, find a Call-ID, extract the dialog, hand it to
Wireshark. Capturing the same traffic at the wire — with `tcpdump` on a TLS
SIP profile — requires session keys we don't keep, leaves a haystack of
unrelated calls, and is unavailable retroactively. The pcap module inverts
the problem: search in text with this library's filters, then synthesize a
pcap that contains *only* the matched stream. No keys, no noise, no live
capture window.

The output is libpcap-classic, not pcapng — every NG-911 tool we ship to
operators reads classic pcap; pcapng's per-packet metadata earns no value
here. `LINKTYPE_LINUX_SLL` is the link type for layer-4 export because its
`pkttype` field encodes recv vs sent without inventing MAC addresses, and
because the dump records direction per frame. TLS and WSS frames are written
as plain TCP on their original ports (5061, etc.) — the dump payload is
already-decrypted SIP, so re-wrapping it in TLS records would only add
ciphertext we cannot produce. Wireshark dissects SIP from any TCP stream
once port-based heuristics fire, so synthesizing SYN/FIN handshakes adds no
dissector benefit; the writer omits them and starts each connection's SEQ
at zero.

Layer-3 export (LINKTYPE_RAW, IP proto 253 from RFC 3692 testing range)
exists for the case where the consumer wants raw IP payloads without
inventing transport state — useful for one-packet-per-frame review where
TCP segmentation order matters. The library exposes `write_frame` and
`write_message` independently; the CLI's `--pcap-layer 3|4` couples
layer-3-with-frames and layer-4-with-messages because that pairing is what
makes each output legible in Wireshark.

The synthetic local endpoint defaults to RFC 5737 (`192.0.2.1`) and RFC 3849
(`2001:db8::1`) — addresses reserved for documentation, guaranteed never to
collide with real traffic. This is a library default, not a hard-coded
constant; callers override `PcapConfig::local_v4`/`local_v6` for site-
specific synthesis. Date anchoring for the older `Timestamp::TimeOnly`
format is also a caller decision (`PcapConfig::date_base`); the library
makes no policy choice between "use file mtime" and "use today" because
both can be wrong, and pure integer civil-day math (Howard Hinnant's
`days_from_civil`) avoids pulling `chrono` into the public API where a
major-version bump would become a semver break.

A payload larger than the IP family's length field can carry is refused as
an error; the writer never truncates a length field or exceeds the snaplen
it advertised, since a silently corrupt packet reads as the dump's truth.

The module is behind a `pcap` feature flag. Library consumers that only
need parsing pay nothing for it; the CLI enables it transitively.

## Typed Remote Address

Which shapes the frame header's remote address takes is Level 1
knowledge — mod_sofia brackets IPv4 like IPv6 — so the typed accessor
lives here instead of every consumer re-learning those forms. Anything
that isn't an ip:port shape yields `None` rather than a guess; the raw
string remains available.

## Error Recovery at Frame Boundaries

FreeSWITCH writes "dump started at Thu Oct 10 11:59:14 2024" lines
when the dump file is initialized. These appear as invalid frame
headers. The parser recognizes them and skips just the marker line
(plus trailing newlines), not the entire region up to the next boundary.

Between frames, extra `\n` or `\r\n` padding can appear from various
sources (dump restart markers with trailing blank lines, inter-frame
padding). The parser strips this whitespace before attempting header
parsing, which eliminated 10 false recovery events per dump file on
one production sample (recovering 10 previously-lost frames).

Recovery from genuine invalid headers scans forward to the next
`\x0B\n` + valid header pattern and returns `Some(Err(...))` so the
caller sees the error. The library never silently swallows parse
failures.

## Torture Corpus Outside the Package

The URI and PIDF torture runs live in a standalone crate beside the library:
not in its test directory, not as a workspace member. They need the EIDO
crate, a git dependency without a crates.io release, and Cargo has no
optional dev-dependencies and resolves a workspace lock as a whole, so either
placement would make every library test build fetch it, on hosts without
access to the git host.

## Per-File Throughput

The downstream `freeswitch-sip-trace-analyzer` processes 700MB–2GB of
xz-compressed dump data per call investigation query. Even after
parallelizing across files with `spawn_blocking`, per-file parse time
dominates wall-clock: a single 340MB TCP dump takes ~3 seconds, and a
worst-case query across 6 files and 2 profiles takes ~41 seconds.
These queries happen during live NG-911 incident investigation where
operators are reconstructing call flows, so parsing latency directly
delays answers.

Perf profiling confirmed the bottleneck is CPU-bound — parsing, UTF-8
validation, and allocation — not I/O. The optimizations below target
the hot paths identified in profiling production dump files.

### Level 2 Accessors Never Guess

An accessor that answers from reassembled bytes rather than a parse
answers nothing where the bytes leave it in doubt, and agrees with the
parsed message everywhere else — down to the header-block boundary the
header crate applies, which is stricter than the message's own. Both
halves bind: a consumer filtering on one drops only what it has
classified, and anything classified would have parsed, so rejecting
before Level 3 hides no parse error.

Level 3 splits its body at that same header-block boundary, so no byte
falls between the halves. Level 2 keeps framing on CRLF pairs and
Content-Length; on a malformed blank line the levels disagree by design,
each still accounting for every byte.

One start-line grammar serves both levels, and it sits below them rather
than inside Level 3, so Level 2 resynchronises on any request Level 3 would
parse without depending on it. A start line cut short by a frame boundary
waits for more bytes rather than being scanned past. The shared data types
sit under every level and reach up into none.

### GrepFilter Zero-Copy Path

`GrepFilter` wraps all CLI input unconditionally, even when not piping
from grep. The original `read_until` implementation copied every byte
through an intermediate Vec: source → BufReader → GrepFilter.buf →
caller. Switching to `fill_buf()` lets non-separator content flow
directly from BufReader's internal buffer to the caller. The
intermediate Vec only appears when a line straddles a buffer boundary.
This eliminated ~8% of wall-clock time on a 340MB dump file.

### Why Not FxHashMap

`rustc-hash::FxHashMap` was benchmarked for the per-connection TCP
reassembly buffer map. Despite FxHash being faster than SipHash per
lookup, it was consistently slower end-to-end. The buffer map has very
few live entries — buffers are eagerly removed after extraction — so
the HashMap overhead is negligible and the additional dependency cost
more than it saved.
