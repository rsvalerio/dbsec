---
id: TASK-0012
title: >-
  SEC-33: the per-session prepared-statement map grows without bound on
  client-chosen names
status: To Do
assignee:
  - TASK-0050
created_date: '2026-08-11 19:13'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:83`, `crates/proxy/src/encrypt.rs:105-112`, `crates/proxy/src/encrypt.rs:157-166`

**What**: `QueryRewriter` keeps `statements: HashMap<Vec<u8>, ParamTransforms>` keyed by the client's prepared-statement name. Every `Parse` ('P') frame inserts an entry:

```rust
self.statements.insert(parse.statement.to_vec(), outcome.params);
```

Entries are removed only by an explicit `Close` with the `'S'` target (line 159). There is no size cap, no eviction, and nothing bounds the key length — the name comes straight off the wire and a `Parse` body may be up to 1 GiB. A client that issues named `Parse` messages and never closes them (or issues them with distinct random names) grows the map for the life of the session. Note that `Parse` on the *unnamed* statement (`b""`) is self-limiting, so this needs deliberately named statements — but every driver that caches prepared statements uses named ones, and nothing stops a client from using a fresh name each time.

**Why it matters**: The map is per session, so a single connection cannot exhaust the host on its own — but this is untrusted, client-controlled input driving an unbounded allocation on a pre-authentication-reachable path, which is the shape SEC-33 exists for. Two aggravating factors: the value side (`ParamTransforms`) holds `Arc<dyn FieldTransform>` clones per protected parameter, and combined with the unbounded accept loop ([[task-0009]]) the per-session bound multiplies by the connection count. A cheap fix is a cap on entry count plus a cap on the statement-name length, both of which a real driver will never approach.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The statement map has a documented maximum entry count, and exceeding it is a session error rather than unbounded growth
- [ ] #2 The statement-name length used as a key is bounded
- [ ] #3 A test asserts that a client issuing more than the cap in distinct named Parse messages is rejected instead of growing the map
<!-- AC:END -->
