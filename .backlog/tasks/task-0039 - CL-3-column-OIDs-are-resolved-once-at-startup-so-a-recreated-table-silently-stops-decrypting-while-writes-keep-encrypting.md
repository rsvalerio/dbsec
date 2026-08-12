---
id: TASK-0039
title: >-
  CL-3: column OIDs are resolved once at startup, so a recreated table silently
  stops decrypting while writes keep encrypting
status: Done
assignee:
  - TASK-0050
created_date: '2026-08-11 19:35'
updated_date: '2026-08-12 16:54'
labels:
  - code-review-rust
  - correctness
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:19-61`, `crates/proxy/src/main.rs:121-128`

**What**: The two data paths key protected columns differently:

- **write path** — `WriteCatalog` (`encrypt.rs:27-53`) matches by `(schema, table) → column` *name*, resolved per statement from the SQL text.
- **read path** — `ColumnMap` (`rows.rs:26`) matches by `(table_oid, attnum)`, resolved exactly once in `serve()` before the listener binds, and never revisited for the life of the process.

Anything that changes a protected column's OID or attnum desynchronises the two. `DROP TABLE users; CREATE TABLE users (...)` gives a new `pg_class.oid`; `ALTER TABLE users DROP COLUMN email, ADD COLUMN email BYTEA` gives a new `attnum` (PostgreSQL never reuses one). After either, the running proxy:

- keeps encrypting writes, because the catalog matches the unchanged *name*;
- stops decrypting reads, because no RowDescription field matches the stale `(oid, attnum)` — `RowDecryptor::on_frame` (`rows.rs:53-62`) simply finds nothing in `self.active` and relays the frame untouched.

There is no error, no warning, and no periodic re-resolution. The startup log line `"protected column resolved"` was correct when it was written and is now stale.

**Why it matters**: `resolve.rs:1-4` argues the case itself — "A column that doesn't exist is a startup error — silently protecting nothing would be worse than refusing to start." That reasoning is applied only at startup; the same silent-nothing state is reachable at runtime through an ordinary migration, and there it produces the worse outcome of the two, because writes continue to succeed. Every row written after the migration is correctly sealed and every read of it hands the client raw `blind_index || envelope` bytes, which the client will store, compare or display as if they were the value. Migrations that recreate a table are routine (some tooling recreates rather than alters by default), and the proxy is a long-lived process that outlives many of them. The failure is invisible until someone reads the column.

The map is also not the only startup-frozen state: `ProtectedColumn::readable` and the mask travel with it, so the same staleness applies to mask policy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A RowDescription field whose (table_oid, attnum) does not match, but whose table and column names identify a protected column, is detected rather than relayed untouched
- [x] #2 The proxy re-resolves the column map (on a schema-change signal, a TTL, or an explicit reload) instead of trusting a startup snapshot for the process lifetime
- [x] #3 A stale mapping produces a loud, actionable log line or a failed session under the strict setting, not a silent passthrough of ciphertext
- [x] #4 An e2e test recreates a protected table under a running proxy and asserts the chosen behaviour
- [x] #5 The read path's dependency on startup-resolved OIDs, and its divergence from the name-keyed write path, is documented in rows.rs and resolve.rs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The startup snapshot is now a snapshot: `rows::Resolved` behind an `RwLock<Arc<_>>` in `RowContext`, swapped by `resolve::refresh_loop`.

AC#2: `column_refresh_secs` (default 300, `0` disables) re-resolves on a timer, and a session that sees a suspect field wakes the refresher immediately through a `Notify` — so the timer is a backstop, not the exposure window. A failed re-resolution warns and keeps the last good mapping rather than taking the proxy down mid-migration.
AC#1/#3: `RowDecryptor::check_for_stale_mapping` flags a RowDescription field that comes from a real table (`table_oid != 0`), is labelled like a configured *readable* column, and is not in the current mapping. Under `warn` it logs one actionable line per session and requests a re-resolution; under `on_unprotected = "reject"` it fails the session with `Error::StaleColumnMap`. The refresher separately logs, by qualified column name, every position that moved between two resolutions — old and new `(oid, attnum)` — which is the line an operator can act on.
  The name match is a heuristic and is documented as one: a RowDescription names its fields but identifies their table only by OID, so an unrelated table with a same-named column trips it too. That is why the response is "re-resolve" (which settles it authoritatively) and why the fail-closed reading is behind the same switch the write path uses. `dbsec_core::pgwire::RowField` gained the field name to make this possible.
AC#4: `e2e.rs::a_recreated_table_is_re_resolved_and_refused_in_strict_mode` recreates a protected table under a running proxy, asserts writes are still sealed, asserts reads heal well inside the 300 s interval (so it is the on-demand trigger being exercised, not the timer), then asserts the strict-mode refusal.
AC#5: documented in the `rows.rs` and `resolve.rs` module docs and on `rows::Resolved`, plus a `column_refresh_secs` section in README's "Operating the proxy".
<!-- SECTION:NOTES:END -->
