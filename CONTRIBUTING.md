# Contributing to {{REPO}}

<!--
Shared template. Copy into the consuming repository, replace {{REPO}}, and fill in the
"Development setup" and "Project layout" sections — those are the parts that cannot be
shared. Everything else is common across these repos and should be kept in sync with
forge/templates/CONTRIBUTING.md rather than edited in place.
-->

Thanks for your interest in contributing! Contributions of all kinds are welcome: bug
reports, fixes, docs, and features.

## Development setup

<!-- Project-specific. Include the toolchain requirement and the shortest path to a
     running build. -->

```bash
git clone https://github.com/rsvalerio/{{REPO}}
cd {{REPO}}
cargo build
```

## Before you open a PR

All of these must pass — CI enforces them:

```bash
cargo fmt --all --check
cargo clippy --all --all-features -- -D warnings
cargo test --all --all-features
```

If you touch dependencies, also run `cargo deny check`.

These are the same gates the shared `rust-ci` workflow runs, so a green local run means a
green CI run. Note `cargo fmt --all --check` **checks** rather than reformats: a
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

<!-- Project-specific. A short table of the crates/directories and what each owns. -->
