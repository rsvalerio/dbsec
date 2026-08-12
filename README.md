# dbsec

Transparent PostgreSQL proxy for field-level encryption — a deliberately small
Acra replacement. A library (`dbsec-core`) does the work; the `dbsec` binary is
a thin tokio TCP wrapper around it.

- AES-256-GCM ciphertext envelope with key ids (rotation-friendly), Vault/OpenBao-backed keys
- Searchable encryption via deterministic HMAC blind index
- Storage-free pseudonymization (FF1 FPE + HMAC tokens) and read-path masking
- TLS on both hops (rustls), flat TOML config, PostgreSQL only

Status: scaffold. Roadmap and design in [plans/PLAN.md](plans/PLAN.md).

## Operating the proxy

Three settings decide how much of the "a protected column is never at rest in
plaintext" invariant the proxy can actually enforce. All are documented in full
in `crates/proxy/src/config.rs`; the short version:

**`on_unprotected`** — what happens to a statement the SQL rewrite cannot cover,
so a protected column would take a plaintext write (or a searchable predicate
would match nothing). The sites are non-UTF-8 and unparseable SQL, `INSERT`
without a column list, `INSERT ... SELECT`, `COPY`, `MERGE`, `PREPARE` of a
write, a non-literal expression assigned to a protected column, an unqualified
name under a changed `search_path`, and a predicate over a searchable column
that no blind-index match can express.

```toml
on_unprotected = "warn"    # default: log and relay — fail *open*
on_unprotected = "reject"  # answer the client with an ErrorResponse instead
```

`reject` is statement-level, not connection-level: the client gets a PostgreSQL
`ERROR` (SQLSTATE 42501) and the session carries on. It is not the default
because it refuses statements that work today — including any SQL sqlparser
cannot parse but PostgreSQL can, whether or not it touches a protected table.
Run on `warn`, collect the warnings, fix them, then switch.

**`search_path`** — a `[[column]]` entry without a schema means `public`, and
the write path resolves an unqualified SQL name the same way. A session that
points `search_path` elsewhere breaks that equivalence in both directions, so
the proxy watches the startup packet and `SET search_path` and stops resolving
bare names once the default no longer holds (an `on_unprotected` site).
Schema-qualifying either the config or the SQL avoids the question entirely.

**`column_refresh_secs`** — how often the `[[column]]` list is re-resolved to
`(table oid, attnum)`. The read path matches result columns on those; the write
path matches on names. A migration that recreates a table or a column moves the
first and not the second, so between the migration and the next resolution the
proxy keeps encrypting writes and hands reads back the stored form — no error on
either side. The default is 300 s, and a session that sees a result column it
cannot explain asks for a re-resolution immediately, so the timer is a backstop
rather than the exposure window. `0` disables the timer.

Under `on_unprotected = "reject"` that same detection fails the session instead
of relaying. The name match it rests on is a heuristic — a RowDescription names
its fields but identifies their table only by OID — so an unrelated table with a
column named like a protected one trips it too.

One read-path behaviour is not configurable: a `DataRow` the proxy cannot tie to
any described statement fails the session. In the extended protocol the server
sends `RowDescription` in reply to `Describe`, not to `Execute`, so the proxy
tracks `Parse`/`Bind`/`Describe`/`Execute` and keys protected column positions
to the portal being executed rather than to the last `RowDescription` on the
connection. A client that never describes what it executes leaves nothing to key
on, and relaying those rows is exactly the silent passthrough of ciphertext this
path exists to prevent. Every driver the e2e matrix covers describes its
statements.

`COPY` is never encrypted. `COPY ... FROM` carries its payload in `CopyData`
frames rather than SQL, and `COPY ... TO` bypasses the read path — so a
protected column leaves as its stored form, which for a mask-only column is the
*unmasked* value. Both are `on_unprotected` sites; bulk-load through `INSERT`,
or seal the data before it reaches the proxy.

## Develop

```
make help      # all targets
make check     # QA gates via `ops verify qa` (fmt, clippy, check, test)
make deny      # license/advisory audit
make e2e       # driver matrix through the real binary (needs docker)
make e2e-vault # OpenBao-backed keys against a live dev-mode server (needs docker)
```

Both e2e targets also run in CI (`.github/workflows/e2e.yml`) against service
containers, since the QA gates alone never reach them.

`make e2e` runs the proxy between a dockerized Postgres and tokio-postgres, sqlx
and psycopg 2/3; the Python cases are skipped unless
`pip install 'psycopg[binary]' psycopg2-binary` has run — set
`DBSEC_E2E_STRICT_DRIVERS=1` to make that a failure instead. Both targets reuse
services you already run when `DBSEC_E2E_DSN` / `DBSEC_E2E_VAULT_ADDR` are set,
and start throwaway containers otherwise.

Each suite listens on its own port from a block starting at 16432. Set
`DBSEC_E2E_PORT_BASE` to move the block when something else on the machine — a
second checkout, another CI job on the same runner — already holds it.

CI and release run through [forge](https://github.com/rsvalerio/forge) reusable
workflows; lint configs (`deny.toml`, `clippy.toml`, `rustfmt.toml`) and
`CONTRIBUTING.md` are copies of forge's canonical versions. `make forge-sync`
(also a CI job) diffs them against the forge tag the workflows are pinned to, so
a copy going stale fails the build instead of going unnoticed. Divergence that
is deliberate is recorded as a waiver under `.forge-sync/waivers/`, which pins
the expected diff — a later change on the forge side still fails.
