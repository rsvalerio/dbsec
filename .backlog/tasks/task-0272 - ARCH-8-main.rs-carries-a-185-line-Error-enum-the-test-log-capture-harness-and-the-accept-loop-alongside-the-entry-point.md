---
id: TASK-0272
title: >-
  ARCH-8: main.rs carries a 185-line Error enum, the test log-capture harness
  and the accept loop alongside the entry point
status: Triage
assignee: []
created_date: '2026-08-22 00:39'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:228`

**What**: crates/proxy/src/main.rs:228-411 defines the proxy-wide `Error` enum (30 variants, 185 lines, plus the `From<dbsec_vault::Error>` impl at main.rs:214-226); main.rs:122-212 holds the `log_capture` / `CapturedEvents` / `captured_events` test infrastructure used by four other modules; main.rs:789-954 holds the `Accept` trait, error classification, `Refusals` and `accept_loop`. The file is ~955 production lines before its test module. ARCH-8 asks for the entry file to be module declarations, crate docs and small central types, with an error type over ~50 lines moved to `error.rs`; TASK-0200 files the same shape for core's lib.rs.

**Why it matters**: Every module in the proxy imports `crate::Error`, so the variant list is the most-edited shared surface in the crate and lives in the file with the least cohesive theme; the test capture harness is shared infrastructure that has nothing to do with `main`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Error` and its `From` impls move to `crates/proxy/src/error.rs` (re-exported as `crate::Error`), with no change to messages or variants
- [ ] #2 `log_capture`, `CapturedEvents` and `captured_events` move to a `#[cfg(test)]` test-support module that the other modules import
- [ ] #3 `accept_loop`, `Accept`, `Refusals` and the accept-error predicates move to a `listener`/`accept` module; `main.rs` keeps `main`, `start`, `Args`, `load_config`, `serve`, shutdown handling and the constants
<!-- AC:END -->
