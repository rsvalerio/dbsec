---
id: TASK-0239
title: >-
  DUP-3: a stub KeySource returning fixed keys is hand-written seven times
  across the crate's test modules, integration tests, bench and example
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/transform.rs
  - crates/core/src/protector.rs
  - crates/core/src/policy.rs
  - crates/core/tests/props.rs
  - crates/core/tests/derive.rs
  - crates/core/tests/bench.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:625-662` (also `crates/core/src/transform.rs:337-353`, `crates/core/src/protector.rs:238-251`, `crates/core/src/policy.rs:487-505`, `crates/core/tests/props.rs:18-34`, `crates/core/tests/derive.rs:14-27`, `crates/core/tests/bench.rs:36-49`)

**What**: `OneKey`, `TestKeys`, `BenchKeys` — seven near-identical `impl KeySource` blocks of 12-17 lines each, every one a single fixed DEK with a fixed id, plus an `index_key` that either returns one constant or errors. They already drift in ways that matter for what a test proves: `protector.rs` and `derive.rs` answer an unknown key id with `Error::Decrypt` while the others return `Error::UnknownKey`, and `bench.rs` returns the DEK for *any* id. `envelope.rs` additionally has a `RollingKeys` that is the only rotation stub in the crate and is unreachable from `tests/`. DUP-10 hands test duplication to TEST-12, but this is a shared fixture, not scenario setup: the rule text calls out "similar trait implementations across different types" as DUP-3, and the `ERR-9`-style drift in the unknown-id arm is the cost.

**Why it matters**: Low, but the crate is now a library whose downstream users also need a stub `KeySource` to write tests — a `test-support` feature (or a `tests/common` module plus a `#[cfg(test)]` `keys::testing` module) exporting `StaticKeys`/`RollingKeys` would serve both, and stop the seven copies diverging on which error an unknown key id produces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One shared fixed-key KeySource stub (and the rolling variant) lives in a single place reachable from unit tests, integration tests, the bench and the example
- [ ] #2 Every in-crate stub KeySource is replaced by the shared one, and the unknown-key-id arm returns Error::UnknownKey everywhere
<!-- AC:END -->
