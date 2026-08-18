---
id: TASK-0077
title: >-
  SEC-37: the Bind-time array codec parses untrusted client bytes but is neither
  fuzzed nor property-tested
status: Done
assignee:
  - TASK-0121
created_date: '2026-08-14 12:34'
updated_date: '2026-08-17 20:15'
labels:
  - code-review-rust
  - security
  - test-coverage
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:1259` (`decode_binary_array`), `crates/proxy/src/encrypt.rs:1317` (`decode_text_array`), `crates/proxy/src/encrypt.rs:1227` (`index_array`)

**What**: the `= ANY($1)` codec added by TASK-0062 hand-parses client-supplied bytes in
both wire formats — a binary format with dimension/flag/OID headers and length-prefixed
elements, and a text format with a hand-rolled quote/escape state machine over byte
indices. It is covered by example-based unit tests only. Every comparable parser of
untrusted input in this workspace has a fuzz target (`fuzz/fuzz_targets/pgwire.rs`,
`envelope.rs`, `transform.rs` — the last added by TASK-0029 for exactly this rule), and
the text-array decoder has already had one silent-wrong-answer bug (TASK-0073, the
unquoted-escape mis-split) that example tests missed and a real PostgreSQL had to
arbitrate.

**Why it matters**: a panic here is a session-task crash reachable from any client, and a
mis-decode is worse than a crash — a wrong element split re-encodes into a well-formed
`bytea[]` of indexes for values nobody stored, silently returning wrong rows (the outcome
`index_array`'s own docs call the one that must never happen).

**Fix shape**: the codec lives in the `dbsec` binary crate, which `fuzz/` cannot depend
on, so either (a) add proptest round-trip/never-panic properties in-crate — decode(encode(x)) == x
for arbitrary element sets, decode never panics on arbitrary bytes, text decode agrees
with binary decode where both accept — or (b) move the array codec into `dbsec-core` and
extend the fuzz targets. (a) is the smaller change; `proptest` is already a workspace
dev-dependency used by `crates/core/tests/props.rs`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decode_text_array and decode_binary_array are exercised by property-based tests or a fuzz target, covering never-panic on arbitrary bytes and a round-trip property
- [x] #2 The properties encode the fail-closed contract: any input the codec cannot decode faithfully yields None, never a partially indexed array
<!-- AC:END -->
