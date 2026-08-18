---
id: TASK-0127
title: >-
  Envelope AAD binds the column but not the row, so a value can still be
  relocated between rows of the same column
status: In Progress
assignee:
  - TASK-0141
created_date: '2026-08-17 20:22'
updated_date: '2026-08-18 10:19'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/proxy/src/columns.rs
  - crates/proxy/src/rows.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:59` (`CellContext`), `crates/proxy/src/columns.rs:60` (what is bound), `crates/proxy/src/rows.rs:391` (read path, which has no row identity)

**What**: TASK-0082 bound `schema.table.column` into the GCM associated data, so a ciphertext pasted into a *different column or table* now fails authentication. The row half of that finding is not covered: copying a stored blob from one row's `users.ssn` into another row's `users.ssn` still decrypts cleanly, because both cells share the same context string.

Row binding was not implemented because neither data path knows a row's identity. The write path rewrites INSERT/UPDATE parameters before the server assigns generated keys, so the primary key of the row being written is frequently not in the statement at all; the read path matches result columns by `(table oid, attnum)` and never sees a primary key unless the client happened to select it. Closing this needs a design decision above the envelope — requiring a configured row key present in every protected statement, or an opaque per-row token the proxy maintains — not a change to `CellContext`.

**Why it matters**: the headline scenario in TASK-0082 — an attacker with write access to stored bytes copying a high-privilege user's `users.ssn` into their own row and reading it back through the proxy — is a cross-*row* relocation, and it is still undetected. Cross-column and cross-table relocation are now caught, so this is the remaining half of the original confidentiality break.

**Origin**: discovered during TASK-0118 while fixing TASK-0082 (the row half of its AC #2 was left unsatisfiable at this layer). The limitation is documented in `plans/PLAN.md` (Caveats) and in the `envelope` module docs so it is not mistaken for coverage.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A ciphertext moved into the same column of a different row fails authentication on read
- [x] #2 The chosen row identity is available on both the write and the read path, or the design note records why the deployment must supply it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Worked in wave TASK-0141 (branch code-review/TASK-0141). **AC #1 not satisfied and NOT
implementable at this layer.** AC #2 satisfied via its second branch: the design note now
exists at plans/PLAN.md, "Why the row half is not bound", with a condensed version in the
`envelope` module docs. Task stays In Progress; the wave parks.

No format change was made. Changing the stored format again on a design that cannot be
completed would have been the wrong trade.

## Why AC #1 cannot be met without a decision above the envelope

The governing constraint, stated sharply: **relocation detection requires the opener to
know where the bytes belong independently of the bytes themselves.** Any identifier
carried inside the envelope — a per-cell salt, a random token — is copied along with the
ciphertext and proves nothing. A token in a sibling column is copied too, unless that
token is itself row-bound, which is circular. So the identity has to be one the
application already treats as the row's name: the primary key. (An attacker who rewrites
the primary key has not relocated a value; they have renamed the row. That is exactly why
the PK qualifies and a proxy-minted identifier does not.)

## What the two paths actually have

The earlier framing ("neither data path knows a row's identity") is true but imprecise,
and the imprecision hid where the real cost is. Verified against the source:

**Write path** — `crates/proxy/src/encrypt.rs`
- `FieldTransform::seal(&self, plaintext)` (core/src/transform.rs:27) takes bytes only;
  the AAD is a `CellContext` fixed at config time (proxy/src/columns.rs:49,60).
- Inline literals: `rewrite_insert_values` (encrypt.rs:878) holds the whole `Insert` —
  full column list and every VALUES row — so a sibling `id` *expression* is in scope.
- Bound parameters: `QueryRewriter::bind` (encrypt.rs:468) holds the entire parameter
  array (`values`, :478), so a sibling `$3`'s bytes are in scope at the moment
  `transform.seal(value)` runs (:489).
- What does not survive Parse -> Bind is the mapping: only
  `ParamTransforms = Vec<(usize, ParamAction)>` (portal.rs:140) crosses, index -> action,
  carrying no column or table. Threading "row key is at index N" through it is mechanical.
- The UPDATE `WHERE` clause *is* parsed and walked (`rewrite_predicate` encrypt.rs:1142,
  `rewrite_selection` :1408) and already pattern-matches `col = <literal|placeholder>`
  (:1416-1420, `rewrite_equality` :1521) — but only for *protected* columns; an
  unprotected `id` resolves to `ColumnResolution::Unknown` (:1886) and is dropped.
  Extending it is mechanical too.

The write-path blockers are semantic, not structural:
1. **Server-generated keys.** `INSERT INTO users (ssn) VALUES ($1)` with `id serial` has
   no row key in the statement; the value does not exist until after the statement the
   proxy is rewriting has run. This is the ordinary case.
2. **Multi-row UPDATE.** `UPDATE users SET ssn = $1 WHERE dept = 'x'` needs a *different*
   ciphertext per target row, and a Bind parameter is one byte string. No rewrite can
   satisfy row binding here — only refusal.
3. **ON CONFLICT DO UPDATE.** The conflicting row's key need not be the key the INSERT
   proposed, and the proxy cannot know which branch ran.

**Read path** — `crates/proxy/src/rows.rs`, `resolve.rs`
This half is *closer* than the task assumed. `Described::fields` (rows.rs:172) already
holds `(table_oid, attnum)` for **every** field in order, not only protected ones, and
`decrypt_row` (rows.rs:614) already has every field's bytes in `values` (:619-620). The
resolve query (resolve.rs:36-42) is parameterised by `(schema, table, attname)`, so
resolving one extra declared column per table is one more round trip. So a projected row
key *is* reachable. Two things still block it:
1. **Untyped, format-ambiguous.** `parse_row_description` discards the type OID and the
   format code (core/src/pgwire.rs:122-123 skips 12 bytes), and the result format is a
   per-query client choice. `id = 42` is `b"42"` from a text-format client and four
   big-endian bytes from a binary one — binding raw wire bytes means a row written
   through psycopg cannot be read through sqlx (both are in this repo's e2e suite).
   Binding the logical value means retaining `atttypid` + format codes and canonicalising
   per type: a PostgreSQL type-decoding surface the proxy has nowhere today, and the one
   thing this path has consistently avoided (`decode_wire` rows.rs:680 sniffs a `\x`
   prefix rather than consulting a type).
2. **Usually not projected.** `SELECT ssn FROM users WHERE id = $1` does not return `id`.
   Under row binding that query becomes unanswerable. Injecting the key into the target
   list and stripping it before relay means parsing and rewriting SELECTs — which this
   path exists to avoid: it matches on catalog OIDs precisely so `SELECT *`, CTEs, unions
   and cached prepared statements without a fresh RowDescription need no SQL
   understanding.

## The two designs

**A — declared row key (the only viable one).** Per-table `row_key` in config (today
`config.rs:475` has `[[column]]` only, `deny_unknown_fields`, so a `[[table]]` block is a
hard parse error — this is a config-schema change), resolved to its attnum by the same
catalog query, bound into a new `DBS3` AAD as
`key_id || schema.table.column || canonical(row_key)`. `DBS2` stays readable, so the
migration is the same re-encryption sweep as the DBS1 -> DBS2 upgrade. Price: protected
tables accept client-generated keys only; UPDATEs of protected columns must be
single-row `WHERE row_key = ?`; every read of a protected column must project its table's
row key; and the proxy takes on type-aware decoding of the key column.

**B — proxy-maintained side table of per-cell MACs** keyed by `(table, row key, column)`,
verified on read. Keeps application queries untouched only in appearance: it needs the
same row key on the same two paths, so it inherits every blocker above and adds
transactional consistency with the user's own writes. Strictly worse; not viable.

Design A is a product decision (it changes what SQL a protected deployment may issue), not
a code-review fix. That is why this stays open rather than being forced.
<!-- SECTION:NOTES:END -->
