# Contributing to dbsec

Thanks for your interest in contributing! Contributions of all kinds are welcome: bug
reports, fixes, docs, and features.

## Development setup

A stable Rust toolchain on the 2021 edition is all the build needs — no pinned version,
no nightly, except for `make fuzz`, which needs nightly plus `cargo-fuzz`.

```bash
git clone https://github.com/rsvalerio/dbsec
cd dbsec
cargo build --all --all-features
cargo install cargo-nextest --locked   # the runner `make test` and CI use
```

`make help` lists every target. The two worth knowing up front:

```bash
make check   # every QA gate, via `ops verify qa` (fmt, clippy, build, deps, tests)
make e2e     # the driver matrix against a dockerized Postgres
```

`make check` is the gate that has to be green before a PR; it runs the same fmt, clippy
and test commands listed under "Before you open a PR". The e2e targets need docker and are
not part of `make check`, so run `make e2e` yourself when you touch the wire protocol, the
SQL rewrite or the read path — it drives the real binary from tokio-postgres, sqlx and
psycopg 2/3, and it is the only suite that catches a change that breaks one driver's use
of the extended query protocol. `make e2e-vault` does the same for Vault/OpenBao-backed
keys against a dev-mode server.

Two more gates are not in `make check` but do run in CI: `make deny` (licenses and
advisories) and `make forge-sync`, which diffs the files this repo copies from
[forge](https://github.com/rsvalerio/forge) against the tag the workflows pin. If you
change one of those copies on purpose, record the divergence instead of reverting it:

```bash
FORGE_SYNC_REASON='why this repo differs' ./scripts/forge-sync-check.sh --update
```

## Before you open a PR

All of these must pass — CI enforces them:

```bash
cargo fmt --all --check
cargo clippy --all --all-features -- -D warnings
cargo nextest run --all --all-features
cargo test --all --all-features --doc
```

If you touch dependencies, also run `cargo deny check`.

The fmt, clippy and dependency gates come from the shared `rust-ci` workflow; the tests
are this repo's own CI job, because nextest replaces `cargo test` there — and because
nextest does not run doctests, they stay a separate `cargo test --doc` run. Either way a
green local run means a green CI run. Note `cargo fmt --all --check` **checks** rather than reformats: a
misformatted tree fails rather than silently fixing itself.

## Commit messages

This repo uses **[Conventional Commits](https://www.conventionalcommits.org/)** — version
bumps and the changelog are generated automatically from commit messages by
[cocogitto](https://github.com/cocogitto/cocogitto) (`cog bump --auto` runs on green CI on
`main`; see `cog.toml`).

Examples:

```
feat(api): relay user-follow viewport events
fix(server): strip port from bracketed IPv6 Host headers
docs: clarify frontend build memory requirements
```

Use `feat:` for user-visible features (minor bump), `fix:` for bug fixes (patch bump), and
add `!` or a `BREAKING CHANGE:` footer for breaking changes.

Commit type matters more than it looks: it is the sole input to the next version number.
A `feat:` on a `0.x` line and a `fix:` produce different releases, and neither can be
undone once the tag is pushed.

## Pull requests

1. Fork and create a topic branch from `main`.
2. Keep PRs focused — one logical change per PR.
3. Add or update tests for behavior changes.
4. Update docs (`README.md`, `docs/`) when behavior or configuration changes.

## Reporting issues

- **Bugs / features**: open a GitHub issue with reproduction steps or a clear use case.
- **Security vulnerabilities**: please do *not* open a public issue — see
  [SECURITY.md](SECURITY.md).

## Project layout

The split is deliberate: everything that touches key material or ciphertext lives in the
library, and the binary is a relay that calls into it. A change that needs the network to
be tested usually belongs on the proxy side; a change that does not usually belongs in
core, where it can be property-tested and fuzzed.

| Path | What it owns |
|---|---|
| `crates/core` | `dbsec-core`: the AES-256-GCM envelope, key ids and key sources, the HMAC blind index, FPE/token pseudonymization, masking, and PostgreSQL wire framing. No I/O. |
| `crates/proxy` | The `dbsec` binary: TOML config, TLS on both hops, the session relay, the write-path SQL rewrite, portal/`RowDescription` tracking, the read path, and column resolution. |
| `crates/*/tests` | Integration tests, including the property tests (`core/tests/props.rs`) and the driver matrix (`proxy/tests/e2e*.rs`, `#[ignore]`d — `make e2e` runs them). |
| `fuzz` | `cargo-fuzz` targets for the wire parser, the envelope and the transforms. Excluded from the workspace, so it has its own `Cargo.toml`. |
| `scripts`, `.forge-sync` | The forge drift check and the manifest/waivers it reads. |
| `plans` | Design notes and the roadmap (`plans/PLAN.md`). |

Workspace-wide lint policy lives in `[workspace.lints]` in the root `Cargo.toml`, not in
CI flags, so a local `cargo clippy` enables exactly what CI enables. `unsafe_code` is
`forbid`den across both crates; if you need it, that is a design discussion, not a
`#[allow]`.
