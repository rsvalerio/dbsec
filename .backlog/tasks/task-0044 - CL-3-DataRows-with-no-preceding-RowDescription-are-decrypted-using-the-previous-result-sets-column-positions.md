---
id: TASK-0044
title: >-
  CL-3: DataRows with no preceding RowDescription are decrypted using the
  previous result set's column positions
status: Done
assignee:
  - TASK-0050
created_date: '2026-08-11 21:04'
updated_date: '2026-08-12 16:54'
labels:
  - code-review-rust
  - read-path
  - security
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:41-64`

**What**: `RowDecryptor` keeps the protected positions of the *current* result set in `active`, and `active` is written in exactly one place — the `b'T'` (RowDescription) arm:

```rust
pub struct RowDecryptor {
    ctx: Arc<RowContext>,
    active: Vec<(usize, ReadColumn)>,
}
...
b'T' => { ...; self.active = fields.iter().enumerate().filter_map(...).collect(); Ok(None) }
b'D' if !self.active.is_empty() => { /* uses self.active */ }
```

Nothing ever clears `active`: not `CommandComplete` ('C'), not `ReadyForQuery` ('Z'), not `NoData` ('n'), not `EmptyQueryResponse` ('I'), not `ErrorResponse` ('E'). The doc comment says "Set by each RowDescription, used by the DataRows that follow", which is only true if every result set is preceded by a RowDescription.

In the extended query protocol it is not. The server emits RowDescription in response to **Describe**, not Execute. Drivers that cache prepared statements — tokio-postgres, sqlx, and psycopg3 in prepared mode, i.e. all three drivers this crate has e2e suites for — send `Parse`/`Describe`/`Sync` once per statement and then `Bind`/`Execute`/`Sync` on every subsequent call. Those Executes produce DataRows with **no RowDescription in front of them**, so the decryptor applies whatever `active` was left over from the last statement that *was* described.

Reproduction: on one connection, prepare and describe statement A (`SELECT id, email FROM users WHERE id = $1`, `email` protected at position 1), then prepare and describe statement B (`SELECT id, created_at FROM users WHERE id = $1`, nothing protected). Re-execute A from the driver's statement cache. The last `b'T'` seen was B's, so `active` is empty and A's DataRows relay untouched.

The mirror case is worse: describe B last where B's position 1 is an unprotected `text` column, re-execute A, and the proxy applies A's stale `ReadColumn` to B's plaintext — a configured `mask` gets applied to the wrong column, and `open()` runs against a value that was never sealed.

**Why it matters**: This is the read path's core invariant — "configured columns are matched by table OID + attnum" — silently not holding, and it fails in the direction that leaks. When `active` is stale-empty the client receives **raw ciphertext** (an envelope, or a blind-index-prefixed blob) for a column the operator configured as protected, and it does so without an error, a warning, or a failed session. `RowContext`'s own module doc promises "Crypto errors fail the session — never a silent passthrough of ciphertext"; this path is a silent passthrough of ciphertext that never reaches a crypto error at all.

The window is not exotic. It is the steady state for any connection-pooled application that reuses more than one prepared statement, which is the normal deployment for all three supported drivers. The existing tests do not reach it: every `rows.rs` unit test sends a `b'T'` immediately before its `b'D'` frames, and the e2e suites exercise one statement shape at a time.

The correct fix is to key the DataRow's protected positions to the portal/statement they came from rather than to the last RowDescription seen: track `Describe`/`Bind`/`Execute` on the client→upstream side (`QueryRewriter` already parses `Bind` and already keys per-statement state) and hand the decryptor the portal's field list, falling back to failing the session when a DataRow arrives with no known description.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A DataRow that arrives with no known RowDescription for its portal never relays a protected column untouched — it is either decrypted using the correct positions or fails the session
- [x] #2 Protected positions are associated with the portal/statement the DataRow belongs to, not with the most recent 'T' frame on the connection
- [x] #3 A unit test in rows.rs interleaves two described statements and re-executes the first, asserting its protected column is still decrypted
- [x] #4 A unit test asserts a DataRow arriving with no prior RowDescription does not pass a protected value through in stored form
- [x] #5 An e2e test exercises a driver's prepared-statement cache with at least two distinct statements over the same connection and asserts both decrypt correctly
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed by keying protected column positions to the portal/statement rather than to the last 'T' frame.

New `crates/proxy/src/portal.rs` holds one `SessionPortals` per session, shared by both relay directions. The write path records Parse/Bind/Describe/Execute/Sync; the read path consumes those expectations in order and asks `row_source()` which statement the DataRows now in flight belong to. A RowDescription is attributed to the Describe that asked for it and stored on the statement, so every later Execute of that statement — the steady state of every prepared-statement cache — decrypts with its own positions. `NoData` counts as a description (empty positions), so an Execute of a statement that returns no rows cannot fall back to another statement's positions. Recovery is anchored on ReadyForQuery.

AC#1: `RowSource::Undescribed` and a `LastDescription` with no prior 'T' both return `Error::UndescribedRow`, which fails the session rather than relaying. Documented in README as a deliberate, non-configurable fail-closed.
AC#2: positions live on the `Statement` entry, reached through the portal the Execute names.
AC#3/#4: `rows.rs::a_cached_statement_decrypts_with_its_own_positions_not_the_last_described_ones` and `a_data_row_no_description_covers_fails_instead_of_relaying_stored_values`.
AC#5: `e2e.rs::a_cached_prepared_statement_decrypts_with_its_own_columns` — two prepared statements interleaved over one connection through the real binary, including one pipelined pair.

Found and fixed while proving it: PostgreSQL ignores Flush/Sync in copy-in mode, so a driver's pipelined Sync leaves a batch marker no ReadyForQuery ever answers and every later response is attributed one expectation early. `SessionPortals::copy_data`, driven by the client's CopyData/CopyDone/CopyFail, drops exactly those markers.
<!-- SECTION:NOTES:END -->
