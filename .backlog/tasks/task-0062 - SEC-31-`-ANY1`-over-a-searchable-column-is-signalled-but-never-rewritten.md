---
id: TASK-0062
title: 'SEC-31: `= ANY($1)` over a searchable column is signalled but never rewritten'
status: Done
assignee:
  - TASK-0066
created_date: '2026-08-12 16:14'
updated_date: '2026-08-12 19:22'
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
**File**: `crates/proxy/src/encrypt.rs` (`QueryRewriter::rewrite_selection`, the `Expr::AnyOp` arm)

**What**: `col = ANY(ARRAY['a', 'b'])` is rewritten to a blind-index prefix match, and so is
`col IN ($1, $2)`. `col = ANY($1)` — where the whole list is *one* bound array parameter — is
not: it falls to `unsupported_predicate`, which warns (and refuses under
`on_unprotected = "reject"`). That is safe, but it is not a rewrite.

Rewriting it means decoding the array parameter at Bind time, replacing each element with its
blind index, and re-encoding as a `bytea[]`, in both the text (`{"a","b"}`, with the array
literal's own quoting and backslash-escaping rules) and binary (ndim / has-null / element OID /
per-dimension bounds / length-prefixed elements) parameter formats. The SQL side already works —
`substring(col from 1 for 32) = ANY($1)` is the same shape the `ARRAY[...]` case produces — so
the work is entirely a new `ParamAction` and an array codec.

**Why it matters**: `= ANY($1)` is how sqlx and asyncpg express a multi-value lookup, so this is
a mainline shape for those drivers, not an edge case. Today those queries are refused under
strict mode (or warned about and returned empty under the default), which means a deployment
that turns on `on_unprotected = "reject"` — the setting that makes the encryption invariant
actually hold — breaks every sqlx list lookup against a searchable column.

The safe half is done: the shape is no longer a silent no-op. What is left is the rewrite, and
it was deliberately not attempted inside TASK-0049 because a half-tested array codec produces a
*valid* query that matches the wrong rows, which is worse than the refusal it would replace.

**Origin**: discovered during TASK-0049 while fixing TASK-0037.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Bind-time array parameters for `= ANY($1)` over a searchable column are decoded, indexed element by element, and re-encoded as bytea[], in both text and binary parameter formats
- [x] #2 A mixed or undecodable array falls back to the existing Unprotected::Predicate signal rather than sending a partially-indexed array
- [x] #3 An e2e case covers `= ANY($1)` through sqlx against a real Postgres, asserting the rows come back
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Bind-time array codec: new ParamAction::SearchIndexArray, index_array/decode_binary_array/decode_text_array/encode_* in encrypt.rs. `= ANY($1)` over a searchable column now rewrites to substring(col from 1 for 32) = ANY($1) and the array parameter is decoded, indexed element by element and re-encoded as bytea[] in whichever parameter format it arrived in. Undecodable or non-indexable arrays (wrong element OID, nested/multi-dim, truncated, over 65536 elements) fall back to the Unprotected::Predicate signal at Bind time — warn relays the array untouched (matches no rows), reject answers with the same ErrorResponse the write path uses and owns the batch until Sync. Other parameters of the same Bind are still transformed on the fallback path. e2e: sqlx `= ANY($1)` case in crates/proxy/tests/e2e_sqlx.rs, run green against dockerized Postgres.
<!-- SECTION:NOTES:END -->
