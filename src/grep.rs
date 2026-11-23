use std::io::{BufRead, BufReader, Read};
use std::panic::AssertUnwindSafe;

/// A [`Read`] adapter that strips `grep -C` separator lines (`--\n`) from the
/// input stream.
///
/// When piping grep output into the parser (`grep -C5 pattern dump | parser`),
/// grep inserts `--` lines between match groups. These corrupt the binary frame
/// stream. Wrap the input in `GrepFilter` to transparently remove them.
///
/// Only exact `--\n` and `--\r\n` lines are stripped. Similar lines like
/// `---\n` or `-- \n` pass through unchanged.
///
/// # When to skip this filter
///
/// `GrepFilter` adds a small per-byte overhead (~3% CPU on large files) for
/// newline scanning even when no separators are present. If your application
/// opens dump files directly (not piped through grep), pass the reader
/// straight to [`FrameIterator`](crate::FrameIterator) /
/// [`MessageIterator`](crate::MessageIterator) /
/// [`ParsedMessageIterator`](crate::ParsedMessageIterator) without wrapping:
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::ParsedMessageIterator;
///
/// // Direct file — no GrepFilter overhead
/// let file = File::open("profile.dump").unwrap();
/// for msg in ParsedMessageIterator::new(file) {
///     // ...
/// }
/// ```
pub struct GrepFilter<R> {
    inner: BufReader<R>,
    /// Accumulates a partial line when `--\n` / `--\r\n` detection straddles
    /// a BufReader buffer boundary.
    partial: Vec<u8>,
    partial_pos: usize,
    /// A read failure met after bytes were already copied out, returned on
    /// the next call so neither the bytes nor the failure are lost. The
    /// wrapper keeps GrepFilter unwind-safe, which io::Error is not; a panic
    /// can at worst leave an error still pending, never a broken invariant.
    pending_error: AssertUnwindSafe<Option<std::io::Error>>,
}

impl<R: Read> GrepFilter<R> {
    /// Create a new filter wrapping the given reader.
    pub fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
            partial: Vec::new(),
            partial_pos: 0,
            pending_error: AssertUnwindSafe(None),
        }
    }
}

fn is_grep_separator(line: &[u8]) -> bool {
    line == b"--\n" || line == b"--\r\n"
}

impl<R: Read> Read for GrepFilter<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Drain leftover partial line from a previous call
        if self.partial_pos < self.partial.len() {
            let available = &self.partial[self.partial_pos..];
            let n = out.len().min(available.len());
            out[..n].copy_from_slice(&available[..n]);
            self.partial_pos += n;
            if self.partial_pos == self.partial.len() {
                self.partial.clear();
                self.partial_pos = 0;
            }
            return Ok(n);
        }

        if let Some(e) = self.pending_error.take() {
            return Err(e);
        }

        let mut filled = 0;

        loop {
            let buf = match self.inner.fill_buf() {
                Ok(buf) => buf,
                Err(e) if filled > 0 => {
                    *self.pending_error = Some(e);
                    return Ok(filled);
                }
                Err(e) => return Err(e),
            };
            if buf.is_empty() {
                return Ok(filled);
            }

            let remaining = &mut out[filled..];
            if remaining.is_empty() {
                return Ok(filled);
            }

            match memchr::memchr(b'\n', buf) {
                Some(nl) => {
                    let line_len = nl + 1;
                    if is_grep_separator(&buf[..line_len]) {
                        self.inner.consume(line_len);
                        continue;
                    }
                    let n = remaining.len().min(line_len);
                    remaining[..n].copy_from_slice(&buf[..n]);
                    if n < line_len {
                        self.partial.extend_from_slice(&buf[n..line_len]);
                        self.partial_pos = 0;
                    }
                    self.inner.consume(line_len);
                    filled += n;
                }
                None => {
                    // No newline — partial line, can't be a separator.
                    let buf_len = buf.len();
                    let n = remaining.len().min(buf_len);
                    remaining[..n].copy_from_slice(&buf[..n]);
                    if n < buf_len {
                        self.partial.extend_from_slice(&buf[n..buf_len]);
                        self.partial_pos = 0;
                    }
                    self.inner.consume(buf_len);
                    filled += n;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn filter(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        GrepFilter::new(input).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn bytes_copied_before_a_failed_read_are_returned() {
        use crate::test_reader::{ScriptedReader, Step};
        use std::io::ErrorKind;

        let inner = ScriptedReader::new(
            vec![Step::Data(b"line one\n"), Step::Fail(ErrorKind::Other)],
            None,
        );
        let mut grep = GrepFilter::new(inner);
        let mut out = [0u8; 64];
        let n = grep.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"line one\n");
        assert!(
            grep.read(&mut out).is_err(),
            "the failure still reaches the caller"
        );
    }

    #[test]
    fn grep_filter_stays_unwind_safe() {
        fn unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        unwind_safe::<GrepFilter<&[u8]>>();
    }

    #[test]
    fn strip_separator() {
        assert_eq!(filter(b"hello\n--\nworld\n"), b"hello\nworld\n");
    }

    #[test]
    fn strip_crlf_separator() {
        assert_eq!(filter(b"hello\n--\r\nworld\n"), b"hello\nworld\n");
    }

    #[test]
    fn passthrough_no_separators() {
        let input = b"line one\nline two\nline three\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn consecutive_separators() {
        assert_eq!(filter(b"a\n--\n--\n--\nb\n"), b"a\nb\n");
    }

    #[test]
    fn separator_at_start() {
        assert_eq!(filter(b"--\nhello\n"), b"hello\n");
    }

    #[test]
    fn partial_separator_preserved() {
        let input = b"---\n-- \n--x\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn empty_input() {
        assert_eq!(filter(b""), b"");
    }

    #[test]
    fn only_separators() {
        assert_eq!(filter(b"--\n--\n--\n"), b"");
    }

    #[test]
    fn no_trailing_newline() {
        assert_eq!(filter(b"hello"), b"hello");
    }

    #[test]
    fn binary_content_with_separator_like_bytes() {
        let input = b"data\x00--\nmore\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn frame_iterator_grep_separator_between_frames() {
        use crate::FrameIterator;

        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(
            b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n",
        );

        let filtered = GrepFilter::new(&data[..]);
        let frames: Vec<_> = FrameIterator::new(filtered)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"world");
    }

    #[test]
    fn frame_iterator_grep_partial_context() {
        use crate::FrameIterator;

        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"Accept: application/sdp\r\nContent-Length: 0\r\n\r\n");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/2.2.2.2:5060 at 00:00:01.000000:\nbye\x0B\n");

        let filtered = GrepFilter::new(&data[..]);
        let items: Vec<_> = FrameIterator::new(filtered).collect();
        let frames: Vec<_> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"bye");
    }

    #[test]
    fn frame_iterator_grep_separator_strips_from_content() {
        use crate::FrameIterator;

        let content = b"SIP/2.0 200 OK\r\nVia: a\r\nContent-Length: 0\r\n\r\n";
        let mut data = Vec::new();
        let header = format!(
            "recv {} bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(b"SIP/2.0 200 OK\r\nVia: a\r\n--\nContent-Length: 0\r\n\r\n");
        data.extend_from_slice(b"\x0B\n");

        let filtered = GrepFilter::new(&data[..]);
        let frames: Vec<_> = FrameIterator::new(filtered)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, content);
    }
}
