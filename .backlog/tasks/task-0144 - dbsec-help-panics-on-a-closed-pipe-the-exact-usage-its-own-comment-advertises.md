---
id: TASK-0144
title: >-
  dbsec --help panics on a closed pipe, the exact usage its own comment
  advertises
status: Triage
assignee: []
created_date: '2026-08-18 14:25'
labels:
  - code-review-rust
  - cli
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/tests/cli.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs` (`main`, the `Startup::Help` arm)

**What**: the help arm prints with `println!("{USAGE}\n\n{OPTIONS}")`. Rust's std sets
`SIGPIPE` to `SIG_IGN` at startup, so a write to a closed pipe returns `EPIPE` and
`println!` panics with `failed printing to stdout`. `dbsec --help | head -1` therefore
exits with a panic message on stderr and a non-zero status — while `dbsec --help` alone
exits 0. The code comment on that arm names `dbsec --help | grep` as the motivating case,
and README's "Deploying the proxy" now advertises `--help` on stdout, so the piped shape
is the documented one.

**Why it matters**: TASK-0130 exists precisely because a CLI that fails on `--help` is
the first thing an operator tries and the first thing that looks broken. A pipe into
`head`, `less -F` that the reader quits, or any short-circuiting consumer reintroduces a
non-zero exit and an ugly panic on the path the fix was meant to make clean. Writing to a
locked `io::stdout()` and treating `ErrorKind::BrokenPipe` as success (or restoring the
default `SIGPIPE` handler for this binary) is the usual fix; `tests/cli.rs` already runs
the binary as a command and can pin it.

**Origin**: discovered during TASK-0142 while verifying TASK-0130.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dbsec --help piped into a consumer that closes the pipe early exits without a panic
- [ ] #2 A CLI test pins the closed-pipe exit status and asserts no panic text reaches stderr
<!-- AC:END -->
