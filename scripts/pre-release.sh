#!/bin/bash
# Runs the checks .claude/commands/release.md front-loads before tagging.
# The pre-commit hook is the real gate; this only surfaces failures sooner.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

cargo fmt -- --check
cargo clippy --features cli --all-targets --message-format=short -- -D warnings
cargo check --no-default-features --message-format=short
cargo check --features cli --all-targets --message-format=short
cargo test --release --lib
cargo test --release --features cli --bin freeswitch-sofia-trace-parser

last_tag=$(git tag --list 'v*' --sort=-v:refname | head -1)
cargo semver-checks --baseline-rev "$last_tag"

# The version bump stays uncommitted until tag-release.sh; any other change,
# untracked files included, still makes publish refuse.
allow_dirty=()
[ "$(git status --porcelain)" = " M Cargo.toml" ] && allow_dirty=(--allow-dirty)
cargo publish --dry-run "${allow_dirty[@]}"

if [ -d samples ]; then
	cargo test --release --test level1_samples
	cargo test --release --test level2_samples
	cargo test --release --test level3_samples
	cargo test --release --manifest-path torture/Cargo.toml
else
	echo "samples/ absent: integration and torture tests skipped"
fi
