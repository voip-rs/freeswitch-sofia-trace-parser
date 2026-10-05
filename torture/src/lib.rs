//! Torture-corpus runner shared by the URI, PIDF and sip-header corpus tests.
//!
//! This crate exists outside the parser's own workspace so that its
//! `eido` dependency (a git dependency with no crates.io release) never
//! enters a `cargo test`/`cargo publish` run of the library itself. See
//! `docs/design-rationale.md`, "Torture Corpus Outside the Package".

use std::path::{Path, PathBuf};

use rayon::prelude::*;

/// Per-file torture statistics, reduced across the whole corpus after a
/// parallel scan.
///
/// `ok`/`total` drive the printed success ratio for one file or for the
/// accumulated total; `merge` folds one file's counts into another's,
/// letting [`Corpus::run`] combine per-file results without a shared
/// mutable side-channel.
pub trait Stats: Default + Send {
    /// Successfully parsed item count.
    fn ok(&self) -> usize;
    /// Attempted item count.
    fn total(&self) -> usize;
    /// Fold `other`'s counts into `self`.
    fn merge(&mut self, other: Self);
}

/// The set of sample dump files discovered under `../samples` (this
/// crate's sibling to the parser's gitignored `samples/` directory).
pub struct Corpus {
    files: Vec<PathBuf>,
}

impl Corpus {
    /// List non-`.xz` dump files beside this crate. Empty, with a skip
    /// message on stderr, when the directory is absent — samples are
    /// gitignored production data and not every checkout has them.
    pub fn discover() -> Self {
        let dir = Path::new("../samples");
        let mut files = Vec::new();
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.filter_map(Result::ok) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".xz") || !name.contains(".dump") {
                        continue;
                    }
                    files.push(entry.path());
                }
            }
            Err(_) => eprintln!("samples/ not found beside torture/, skipping corpus"),
        }
        files.sort();
        Corpus { files }
    }

    /// Number of dump files discovered.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether no dump files were found.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Run `parse_one` over every file in parallel, then fold the results
    /// sequentially with [`Stats::merge`]. Prints each file's ok/total and
    /// the corpus-wide total; returns the merged total for the caller's
    /// own assertions.
    pub fn run<S, F>(&self, parse_one: F) -> S
    where
        S: Stats,
        F: Fn(&Path) -> S + Sync,
    {
        let per_file: Vec<(&Path, S)> = self
            .files
            .par_iter()
            .map(|path| (path.as_path(), parse_one(path)))
            .collect();

        for (path, stats) in &per_file {
            if stats.total() > 0 {
                let pct = stats.ok() as f64 / stats.total() as f64 * 100.0;
                eprintln!(
                    "  {}: {}/{} ({pct:.1}%)",
                    path.display(),
                    stats.ok(),
                    stats.total()
                );
            }
        }

        let mut total = S::default();
        for (_, stats) in per_file {
            total.merge(stats);
        }

        if total.total() > 0 {
            let pct = total.ok() as f64 / total.total() as f64 * 100.0;
            eprintln!(
                "=== corpus totals: {}/{} ({pct:.2}%) across {} files ===",
                total.ok(),
                total.total(),
                self.files.len()
            );
        }

        total
    }
}
