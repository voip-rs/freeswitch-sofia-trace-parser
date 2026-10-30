use std::sync::LazyLock;

use memchr::memmem;

/// SIP header line terminator.
pub(crate) static CRLF: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\r\n"));

/// Frame boundary written by `mod_sofia` after each frame's content.
pub(crate) static BOUNDARY: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\x0B\n"));
