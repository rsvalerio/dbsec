---
id: TASK-0130
title: dbsec --help exits non-zero with a usage error instead of printing usage
status: Done
assignee:
  - TASK-0142
created_date: '2026-08-17 20:31'
updated_date: '2026-08-18 10:57'
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
**File**: `crates/proxy/src/main.rs` (`Args::parse`)

**What**: TASK-0120 gave the binary a real argument parser (`--plain-relay`, `--allow-core-dumps`, one optional config path). Anything else beginning with `-` is an `Error::Usage`, which `main` logs at ERROR as "startup failed" and exits 1 on. That includes `--help` and `-h`: an operator asking what the flags are gets a failure, and the usage line arrives as part of a `tracing` ERROR record rather than as help output.

**Why it matters**: a CLI that fails on `--help` is the first thing an operator tries and the first thing that looks broken. The decisions it needs — which stream help goes to (this binary deliberately keeps stdout clean for the operator's pipe, per tests/cli.rs) and which exit code — are exactly the kind `tests/cli.rs` exists to pin, and they are worth making deliberately rather than inheriting from the error path.

**Origin**: discovered during TASK-0120 while fixing TASK-0088.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 dbsec --help and -h print the usage line and exit 0
- [x] #2 Help output goes to a deliberately chosen stream, and a CLI test pins both the stream and the exit code
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0142. Args gained a `help` flag (-h / --help, HELP_FLAGS); `start` now returns a `Startup` enum (`Help` | `Serve(Box<ValidatedConfig>)`) so asking for the flags is a startup *outcome* rather than an `Error::Usage`. `main` prints `USAGE` plus a new `OPTIONS` block to stdout and returns ExitCode::SUCCESS. Stream choice is deliberate and documented: a --help run never becomes a proxy, so there is no pipe to keep clean, and `dbsec --help | grep` is what an operator does; diagnostics from a running proxy stay on stderr. Help is answered before hardening and before config loading, so it works in a directory with no dbsec.toml and on a kernel where the core-dump limit cannot be set. Tests: main::tests::help_is_a_startup_outcome_rather_than_a_usage_error (both spellings, help wins over a config argument, every flag is documented in OPTIONS) and cli::help_prints_usage_to_stdout_and_exits_zero (exit 0, usage on stdout, stderr empty).
<!-- SECTION:NOTES:END -->
