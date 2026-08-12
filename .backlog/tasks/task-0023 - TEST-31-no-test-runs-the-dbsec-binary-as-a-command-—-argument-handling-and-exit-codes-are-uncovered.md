---
id: TASK-0023
title: >-
  TEST-31: no test runs the dbsec binary as a command — argument handling and
  exit codes are uncovered
status: Done
assignee:
  - TASK-0056
created_date: '2026-08-11 19:16'
updated_date: '2026-08-12 16:28'
labels:
  - code-review-rust
  - tests
  - main
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:62-106`

**What**: `main` and `load_config` make several caller-visible decisions that no test exercises:

- `dbsec <path>` loads that config; `dbsec` with no argument loads `./dbsec.toml` if it exists and otherwise runs on defaults (line 94-106).
- A config that fails to load logs `startup failed` and returns `ExitCode::FAILURE` (line 71-74). Likewise a runtime that fails to build (line 79) and a `serve` that errors (line 86).
- Diagnostics go to `tracing_subscriber::fmt()`, which writes to **stdout** by default, not stderr (line 63-67). For a long-running server that is defensible, but it is an undeclared choice — a caller doing `dbsec 2>/dev/null` still sees every log line, and one piping stdout gets logs mixed into whatever it expected.

The e2e suites do spawn the real binary (`tests/common/mod.rs:186`), which is the right instinct, but they only ever call it one way: one argument, a valid config, and success. Nothing asserts an exit code, nothing covers the no-argument paths, and nothing covers a bad config path.

Concretely uncovered: `dbsec /nonexistent.toml` (does it exit non-zero with a usable message?), `dbsec` in a directory with no `dbsec.toml` (does it really start on defaults?), `dbsec` in a directory that has one (is it picked up?), and a malformed TOML (does `ConfigParse` reach the operator legibly?).

**Why it matters**: Low severity — these are startup paths, and a broken one fails loudly on first run rather than corrupting data. It earns a task because this is where CLI regressions actually land: a changed exit code breaks a supervisor's restart policy, and a config-discovery change breaks every deployment relying on the implicit `./dbsec.toml`. Both are invisible to unit tests over internal functions. `assert_cmd` covers all four cases in a few lines, and the e2e harness already proves `CARGO_BIN_EXE_dbsec` is available.

The stdout-vs-stderr question should be settled explicitly in the same change rather than left as a default nobody chose.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A test binary runs dbsec as a process (assert_cmd or equivalent) covering: explicit config path, missing config path, no argument with ./dbsec.toml present, no argument without it, and malformed TOML
- [x] #2 Each case asserts the exit code and that the diagnostic names the offending path
- [x] #3 The stream the log output goes to is a deliberate, documented choice, and a test pins it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in wave TASK-0056.

- Cases covered by `crates/proxy/tests/cli.rs`: explicit config path (wins over a `dbsec.toml` in the cwd), no argument with `./dbsec.toml`, no argument without one, a missing config path, malformed TOML, and a config that parses but fails validation.
- AC #2 substitution: the two cases where the proxy starts successfully have no exit code to assert (the binary is a long-running server), so they assert the process is still serving and that the startup log names the config actually loaded. The three failing cases assert exit code 1 plus the offending path.
- The "no argument, no `dbsec.toml`" case observes the defaults by taking `127.0.0.1:6432` away first and asserting the bind failure names it, rather than binding a fixed global port in a suite that runs alongside the e2e suites and other checkouts. `main.rs` gained an `Error::Listen { addr, source }` variant so that diagnostic names the address.
- AC #3: diagnostics now go to stderr (`with_writer(std::io::stderr)`), with ANSI colour enabled only when stderr is a terminal; the choice is documented at the call site and pinned by asserting stdout stays empty in every case.
<!-- SECTION:NOTES:END -->
