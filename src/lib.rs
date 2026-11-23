//! Streaming parser for FreeSWITCH `mod_sofia` SIP trace dump files.
//!
//! FreeSWITCH logs SIP traffic to dump files at
//! `/var/log/freeswitch/sip_traces/{profile}/{profile}.dump`, rotated as
//! `.dump.1.xz`, `.dump.2.xz`, etc. This library provides a multi-level
//! streaming parser that processes these files with constant memory.
//!
//! # Architecture
//!
//! Three parsing levels, each wrapping the previous:
//!
//! - **Level 1** ([`FrameIterator`]) — splits raw bytes on `\x0B\n` boundaries,
//!   parses frame headers (direction, byte count, transport, address, timestamp).
//! - **Level 2** ([`MessageIterator`]) — reassembles TCP segments by connection,
//!   splits aggregated messages by Content-Length, passes UDP frames through.
//! - **Level 3** ([`ParsedMessageIterator`]) — parses SIP request/status lines,
//!   headers, and bodies. Supports multipart MIME splitting and JSON body unescaping.
//!
//! Every level accepts [`std::io::Read`], so they compose with files, pipes,
//! `xzcat` subprocesses, [`std::io::Read::chain`] for file concatenation, and
//! [`GrepFilter`] for grep-piped input.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::fs::File;
//! use freeswitch_sofia_trace_parser::ParsedMessageIterator;
//!
//! let file = File::open("profile.dump").unwrap();
//! for result in ParsedMessageIterator::new(file) {
//!     let msg = result.unwrap();
//!     println!("{} {} {} call-id={}",
//!         msg.timestamp, msg.direction, msg.message_type,
//!         msg.call_id().unwrap_or("-"));
//! }
//! ```
//!
//! # Input Coverage Tracking
//!
//! Every byte in the input is either parsed into a frame or classified with a
//! [`SkipReason`]. Access parse statistics via the `stats()` / `parse_stats()`
//! methods on each iterator. See [`ParseStats`] and [`SkipTracking`] for details.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]

mod finders;
mod startline;
#[cfg(test)]
mod test_reader;

/// Level 1: frame boundary detection and header parsing.
pub mod frame;

/// `Read` adapter that strips `grep -C` separator lines from piped input.
pub mod grep;

/// Level 2: TCP reassembly and Content-Length-based message splitting.
pub mod message;

/// On-demand pcap export: synthesize libpcap packets from parsed frames/messages.
#[cfg(feature = "pcap")]
pub mod pcap;

/// Level 3: SIP message parsing, multipart MIME, and JSON body handling.
pub mod sip;

/// Core data types shared across all parsing levels.
pub mod types;

pub use frame::{FrameIterator, ParseError};
pub use grep::GrepFilter;
pub use message::MessageIterator;
#[cfg(feature = "pcap")]
pub use pcap::{PcapConfig, PcapError, PcapLayer, PcapWriter};
pub use sip::{is_json_content_type, parse_sipfrag, ParsedMessageIterator};
pub use types::{
    Direction, Frame, FrameMeta, HeaderPart, HeaderWarning, HeaderWarningKind, Headers, MimePart,
    ParseStats, ParsedSipMessage, SipFragment, SipMessage, SipMessageType, SkipReason,
    SkipTracking, SkippedLine, StaleClock, Timestamp, Transport, UnknownKeyword, UnparsedRegion,
};
