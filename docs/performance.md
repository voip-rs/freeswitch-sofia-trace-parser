# Performance

Measured with the bundled CLI on production NG-911 dump files. Every figure came
from repeated interleaved runs, the parser comparisons additionally pinned to one
core; the protocol in [Measuring a change](#measuring-a-change) matters more than
the figures, which are workload- and build-specific.

## Throughput

Parse-only, reading an uncompressed dump from page cache, all messages parsed
(`--stats --all-methods`), one core:

| CPU | corpus | messages | wall | MB/s | per message |
|---|---|---|---|---|---|
| Ryzen 9 7950X3D (Zen 4) | 352 MB, TCP IPv4 | 477,616 | 0.70 s | 500 | 1.5 µs |
| Xeon Silver 4214 (Cascade Lake) | 248 MB, mixed TCP/UDP/TLS | 330,196 | 1.35 s | 184 | 4.1 µs |
| Neoverse-N1 | 400 MB, TCP IPv4 | 555,765 | 2.17 s | 184 | 3.9 µs |

Per-message cost tracks message *count* far more than byte count — a dump of
short keep-alives costs more per megabyte than one carrying multipart bodies.
Compare like corpora only.

## Decompression is not the bottleneck

Dumps are archived xz-compressed, so decompression is the first thing everyone
suspects — and it has not once been the answer. Two independent measurements:

- **In-process profile.** A production run answering one phone-number query over
  2,023,282 messages spent ~48% of cycles moving bytes and ~9% in SIP parsing
  proper. `lzma_code` was **0.01%** — it did not register.
- **Pipeline timing**, 400 MB of decompressed output on the Neoverse-N1:
  `xzcat` alone 1.6 s, the parse alone 2.2 s, `xzcat | parser` 2.5 s. The stages
  overlap in the pipe and the parse is the critical path; decompression hides
  behind it and adds ~0.3 s.

Profile the parse. Reach for the decompressor only after an actual profile puts
it there — on this workload, no profile ever has.

### The one decompression win: skip CRC64

There is still cheap CPU to reclaim on the decompression side, and on ARM64 it
is not small. `xz` verifies a CRC64 (ECMA-182) over the decompressed bytes.
x86_64 has had a carry-less-multiply implementation of that for years; ARMv8's
CRC instructions cover CRC32 only, so there is no equivalent instruction to fall
back on. Decompressing to `/dev/null`, with and without `--ignore-check`:

| CPU | xz | corpus | verify | `--ignore-check` | CRC64 cost |
|---|---|---|---|---|---|
| Neoverse-N1 | 5.8.1 | 1,604 MiB out | 5.07 s | 3.48 s | **31%**, 0.99 ms/MiB |
| Xeon Silver 4214 | 5.4.1 | 237 MiB out | 948 ms | 889 ms | 6.2%, 0.25 ms/MiB |
| Ryzen 9 7950X3D | 5.8.3 | 64 MiB out | 74 ms | 70 ms | 5.4%, 0.06 ms/MiB |

Per byte the check spans a 16× range, cheapest on the newest x86 and worst on
ARM64 — compare `ms/MiB`, not the percentage, which also moves with how fast
each machine decompresses. The N1 measured here does expose `pmull`, so a
carry-less-multiply CRC64 is possible in principle; at ~1 GB/s the check is
running at table speed, so this build is not using one. For a host scanning the
archive in bulk it is worth taking:

```sh
xz -dc --ignore-check profile.dump.1.xz | freeswitch-sofia-trace-parser -m INVITE
```

It buys throughput rather than latency: parsing is still the critical path in a
pipe on every machine measured (on the N1, parse 184 MB/s against decompress
331 MB/s verified), so on a single file the saving largely hides behind the
parse. It pays when many files run in parallel, where CRC64 cycles are cycles
not spent parsing.

The trade is real: nothing then detects a corrupt or truncated stream, so a
damaged file yields garbage instead of an error. Take it for bulk scanning of an
archive that is verified elsewhere, not for a one-off investigation. A library
consumer sets this on the decoder rather than the CLI — in liblzma it is
`LZMA_IGNORE_CHECK` (`0x10`) passed to the stream decoder, which has the useful
side effect of tolerating a truncated trailing block on the dump FreeSWITCH is
still writing.

## Rejecting before Level 3

Level 3 turns every header into two owned `String`s. A consumer keeping a small
fraction of a trace should reject earlier, using
[`SipMessage::method`](../src/sip.rs), which reads the method from the
reassembled bytes with no parse.

Same 352 MB TCP dump, Zen 4, before and after the CLI adopted that prefilter:

| invocation | before | after |
|---|---|---|
| `--full --all-methods` (parses everything) | 1.82 s | 1.69 s |
| `--full` (OPTIONS excluded by default) | 937 ms | 558 ms |
| `--full -m INVITE` | 818 ms | 378 ms |

The gap is the traffic mix: OPTIONS keep-alives are ~87% of messages in an
ESInet trace, and INVITE requests under 0.2%. On such a trace the prefilter
skips almost all header extraction.

## Level 2 reads headers through sip-header's row walker

Level 2 frames on Content-Length read from the same rows Level 3 sees, so it
walks every header block with sip-header's lazy row walker rather than a
byte scan of its own. The walk is the cost to watch: every row of every
message is split and its name compared, to find one row. Two things keep it
near the byte scan: the walk also yields the end of the headers, so there is
no separate blank-line search, and a row name is only matched when its length
could be Content-Length's.

1 GB TCP dump, Level 2 only (`MessageIterator`), Zen 4, pinned, interleaved,
against the byte scan it replaced:

| build | instructions | elapsed |
|---|---|---|
| byte scan for Content-Length | 9.54 G | 0.76 s |
| sip-header's full reader per message | 36.1 G | 2.15 s |
| row walker, name-length gate, end of headers from the walk | 11.1 G | 0.88 s |

A full parse (`--stats --all-methods`) costs the same as before the change,
0.95x the instructions: the faster reader at Level 3 pays for Level 2's walk.
Anyone moving Level 2 back to a byte scan of its own reintroduces a second
reading of the headers that Level 3 has to agree with; bring numbers that
show the walk is the bottleneck first.

## Memory

Constant memory for inputs of any size, including multi-day dump chains (50GB+).
Validated with jemalloc heap profiling (`_RJEM_MALLOC_CONF=prof:true`) and gdb
inspection of live structures while processing 50+ chained files.

Parser internals at runtime, gdb-verified:

- `FrameIterator::buf` — 64KB capacity, ~200 bytes used (single read buffer, never grows)
- `MessageIterator::buffers` — 0 entries (TCP reassembly buffers evicted after message extraction)
- `MessageIterator::ready` — 0 entries, capacity 10 (drained each iteration)

What keeps it flat:

- `SkipTracking` defaults to `CountOnly` — no allocation for unparsed region tracking unless opted in
- TCP connection buffers are eagerly removed after complete message extraction
- Stale buffers (>2h inactive) are evicted via time-based sweep, so TLS ephemeral ports cannot accumulate
- `flush_all()` clears the entire buffer map at EOF

**Consumers processing many files** should open them lazily, one at a time,
rather than `Read::chain()` upfront: chaining keeps every file handle and
decompression state alive for the whole run. With 50+ XZ-compressed dumps, eager
chaining held 172MB of LZMA decoder state alone.

## Measuring a change

Wall clock alone is not enough to accept or reject a parser change at this
scale; several effects are larger than the change being measured.

1. **Prove output identity first.** Hash `--full --all-methods` over several
   dumps before and after, and compare `--stats` in full. A performance change
   that alters output is a bug, and `--stats` is only comparable because its
   ordering is deterministic by construction.
2. **Pin the core.** `taskset -c N`. On a 7950X3D the two CCDs differ (96 MB vs
   32 MB L3, different clocks) and an unpinned run picks between them — worth
   ~9% here, far more than most changes.
3. **Count instructions, not just time.** `perf stat -r 7 -e instructions,cycles`.
   Instruction counts are reproducible to six significant figures; wall clock on
   a shared or thermally-loaded box is not.
4. **Interleave A/B/A/B.** Machine state drifts. A single A-then-B pass has
   repeatedly shown a difference that reversed when run again.
5. **Watch IPC.** Fewer instructions is not faster. Both variants below scan the
   same bytes, and the one retiring less work lost on IPC.

## UTF-8 conversion: measured, not assumed

Header blocks and start-line tokens reach `&str` through one conversion
(`bytes_to_str`), which borrows valid UTF-8 and falls back to lossy only for
malformed input. An earlier version instead tested `is_ascii()` and took
`from_utf8_unchecked`, on the reasoning that SIP is ASCII and full UTF-8
validation is waste.

That reasoning does not survive measurement, because both paths scan every byte
either way. Across three microarchitectures, same corpus per machine, pinned and
interleaved:

| CPU | instruction count | wall clock |
|---|---|---|
| Zen 4 | `is_ascii` 0.50% fewer | no difference; ordering flips between runs |
| Neoverse-N1 | `from_utf8` 0.17% fewer | no difference; ordering flips between runs |
| Cascade Lake | `is_ascii` 0.48% fewer | **`from_utf8` 1.2–1.9% faster**, every pairing |

The instruction-count advantage is real, reproducible, and points in *opposite
directions* per architecture — and it never made `is_ascii` faster on any of the
three. On Cascade Lake `from_utf8` wins on time while retiring more
instructions, by holding higher IPC (2.37 vs 2.28), with roughly a third of the
run-to-run variance.

So the safe conversion is kept: it is never slower, sometimes faster, and it
removes the crate's only `unsafe` block. Anyone reproposing the unchecked path
should bring instruction counts and IPC from more than one CPU.
