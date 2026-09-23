Perform a release of freeswitch-sofia-trace-parser.

Optional override: $ARGUMENTS (format: vX.Y.Z). If provided, use that version.

## Version determination

1. Find the last release tag (`git tag --sort=-v:refname | head -1`).
2. Examine commits since that tag and classify the whole set.

This crate is pre-`1.0`, where cargo reads the **minor** slot as the major one:
every `0.10.x` is compatible with every other, and `0.10` → `0.11` breaks each
consumer pinned to `"0.10"`. The slots therefore shift down by one, and the
mapping below is the one to apply — not the post-`1.0` habit:

- **Patch** (`0.10.0` → `0.10.1`) — everything additive: bug fixes, new features
  (`feat:`), new public API surface, dependency bumps, build changes, docs.
- **Minor** (`0.10.x` → `0.11.0`) — breaking changes only: changed or removed
  public items. Stop and confirm before proceeding.
- **Major** (`0.x` → `1.0.0`) — never chosen automatically; ask.

A `feat:` commit alone is a patch release here. Taking the minor slot for it
tells every consumer their pin broke when nothing did. `cargo semver-checks`
does not catch that direction — it flags a breaking change shipped as a patch,
never an additive change shipped as a break — so a green run says nothing about
whether the bump was too large.

## Pre-release checks

Run `cargo fmt && cargo clippy --fix --allow-dirty --features cli --all-targets --message-format=short`
first to land any formatting/lint fixes, then `scripts/pre-release.sh` —
stop and report on any failure. It runs, in order: `cargo fmt -- --check`,
clippy with `-D warnings`, lib-only and cli+all-targets `cargo check`,
`cargo test --release --lib`, the CLI binary's own tests, `cargo
semver-checks --baseline-rev <last-tag>`, and `cargo publish --dry-run`.
If `samples/` is present it also runs the three
`--test level{1,2,3}_samples` integration suites and
`cargo test --release --manifest-path torture/Cargo.toml`; otherwise it
prints one line noting they were skipped, which is not a release blocker.

Semver is checked here and nowhere else — a breaking change is a release
decision, not something a commit can be rejected for. It runs with cargo's
default feature heuristic; there is no `--only-explicit-features`, since that
flag sees an empty explicit-feature set and hides the `pcap`/`cli` API
entirely.

`eido` lives in the standalone `torture/` crate (see
`docs/design-rationale.md`, "Torture Corpus Outside the Package"), not in
this package's manifest, so it plays no part in publishing.

The `pre-commit` hook re-runs fmt, clippy, rustdoc coverage and tests on the
release commit, so `scripts/pre-release.sh` front-loads those failures and is
itself the only place semver is checked.

## Steps

1. Bump `version` in `Cargo.toml` — often already done, since a breaking change
   bumps it in its own commit. Then master needs no release commit and step 4
   skips it.

2. Run pre-release checks above.

3. Draft a changelog from `git log --oneline <last-tag>..HEAD`.

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - No git hashes, no raw commit subjects, no co-author lines.

   Tag annotation format:
   ```
   vX.Y.Z

   New features:
   - what changed

   Bug fixes:
   - what was fixed

   Build:
   - what changed
   ```

4. Write the changelog sections (no version line) to `release-notes.txt`, then
   commit the bump and build the tag:

```sh
scripts/tag-release.sh vX.Y.Z release-notes.txt
rm release-notes.txt
```

   Nothing is pushed. The tag sits on a detached child commit that pins
   `Cargo.lock`, so the lock never lands on master while the tagged tree still
   builds from an exact dependency set. The script refuses to run unless it is
   on master with a clean tree or `Cargo.toml` as its only modification, the
   manifest version matches, and the tag does not exist yet; it aborts before
   staging the lock if the detach did not take.

   Never open-code these git commands instead — a chain rejected part-way
   (a hook, a denied permission) silently skips its untried half, and the
   failure mode is `Cargo.lock` committed onto master.

   Both commits run the `pre-commit` hook in full, so expect two clippy+test
   cycles. Back on master the working-tree `Cargo.lock` is untracked again; the
   next cargo command regenerates it.

5. Push master, wait for CI green:

```sh
git push
gh run watch "$(gh run list --workflow=ci.yml -b master -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   No run within a couple of minutes: check the `Actions` component at
   `https://www.githubstatus.com/api/v2/components.json` — during an outage no
   run is created and missed events are never backfilled. Stop and report.

   Red: fix on master, rebuild the tag onto the new head, restart this step.

6. Push the tag:

```sh
git push origin vX.Y.Z
```

   CI does not run on tags and there is no release workflow — the tag is the
   release artifact. No GitHub release is created.

7. Publish, from the tagged commit:

```sh
git checkout vX.Y.Z
cargo publish
git switch master
```

   `git switch master` deletes the working-tree `Cargo.lock` (untracked there);
   the next cargo command regenerates it.

8. Report the tag, the changelog, the CI run that gated the publish, and the
   crates.io version.

## Important

- **Never tag or publish a commit CI has not run on.** If the tree changed after
  the checks — a rebase, a hand-resolved conflict, a dependency that resolved
  differently — the earlier green run does not cover it. Re-run the checks and
  go back to step 5.
- **Ask before pushing the tag when anything deviated from these steps.** An
  outage, a rebase, a skipped step, a red-then-fixed run: report the state and
  let me decide.
- **Cargo.lock never reaches master** — library crate, stays gitignored there. It
  exists only on the tag's own commit, so a tagged build is reproducible.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
