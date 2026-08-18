# dbsec

Transparent PostgreSQL proxy for field-level encryption — a deliberately small
Acra replacement. A library (`dbsec-core`) does the work; the `dbsec` binary is
a thin tokio TCP wrapper around it.

- AES-256-GCM ciphertext envelope with key ids (rotation-friendly) and the column bound
  into the associated data, so stored bytes do not authenticate in another column;
  Vault/OpenBao-backed keys
- Searchable encryption via deterministic HMAC blind index
- Storage-free pseudonymization (FF1 FPE + HMAC tokens) and read-path masking
- TLS on both hops (rustls), flat TOML config, PostgreSQL only

Status: scaffold. Roadmap and design in [plans/PLAN.md](plans/PLAN.md).

## Operating the proxy

Three settings decide how much of the "a protected column is never at rest in
plaintext" invariant the proxy can actually enforce. All are documented in full
in `crates/proxy/src/config.rs`; the short version:

**`on_unprotected`** — what happens when the proxy cannot cover a protected
column: it would take a plaintext write, a searchable predicate would match
nothing, or a read would hand back the stored form. The sites are non-UTF-8 and
unparseable SQL, `INSERT` without a column list, `INSERT ... SELECT`, `COPY`,
`MERGE`, `PREPARE` of a write, a non-literal expression assigned to a protected
column, an unqualified name under a changed `search_path`, a predicate over a
searchable column that no blind-index match can express, and a protected column
projected through an expression — `email::text`, `ccnum || ''`,
`coalesce(email, '')` — whose result PostgreSQL describes with no table
identity, so the read path cannot decrypt or mask it.

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

Under `on_unprotected = "reject"` that same detection refuses the result set
instead of relaying it. The name match it rests on is a heuristic — a
RowDescription names its fields but identifies their table only by OID — so an
unrelated table with a column named like a protected one trips it too. The read
path deliberately has no separate switch for this: `on_unprotected` is the one
answer to "this may be unprotected, error rather than guess", and a deployment
that is strict about writing plaintext but lax about handing back stored bytes
is the half-enforced state the setting exists to rule out.

One read-path behaviour is not configurable: a `DataRow` the proxy cannot tie to
any described statement is refused. In the extended protocol the server sends
`RowDescription` in reply to `Describe`, not to `Execute`, so the proxy tracks
`Parse`/`Bind`/`Describe`/`Execute` and keys protected column positions to the
portal being executed rather than to the last `RowDescription` on the
connection. A client that never describes what it executes leaves nothing to key
on, and relaying those rows is exactly the silent passthrough of ciphertext this
path exists to prevent. Every driver the e2e matrix covers describes its
statements.

Read-path refusals are *not* statement-level, and the asymmetry with the write
path is deliberate. The client gets the same PostgreSQL `ERROR` (SQLSTATE
42501) — a refusal should never reach an application as a bare connection reset
it would retry as a network fault — and then the connection closes.

It closes because a refused read is a result, so its statement has already run.
Whatever the client sent behind it in the same batch is still executing
upstream, and PostgreSQL offers no in-band way to abort a batch already in
flight: answering the client and carrying on would let `SELECT protected;
UPDATE …` commit its `UPDATE` behind an error saying the statement failed.
Closing the connection is what makes the backend roll that implicit transaction
back. A refused *write*, by contrast, never reaches the backend at all, so
there is nothing to stop and the session continues.

**Do not run the proxy under a pre-forking supervisor.** GCM nonces come from a
userspace generator whose state is per thread, so a `fork()` after the process
has resolved its DEK gives both children the same nonce stream under the same
key — and GCM nonce reuse is retroactive over every row stored under that key.
The proxy is a single multi-threaded process that never forks; run it that way,
and scale by running independent instances rather than by forking one.

Two more operational constraints worth knowing before an incident: revoking a
Vault token or rotating a key in Vault does **not** reach a running proxy (the
key caches have no TTL — restart it), and ciphertext relocation is detected
across columns and tables but not between rows of the same column. Both are
covered in `plans/PLAN.md`.

`COPY` is never encrypted. `COPY ... FROM` carries its payload in `CopyData`
frames rather than SQL, and `COPY ... TO` bypasses the read path — so a
protected column leaves as its stored form, which for a mask-only column is the
*unmasked* value. Both are `on_unprotected` sites; bulk-load through `INSERT`,
or seal the data before it reaches the proxy. The query form,
`COPY (SELECT ...) TO STDOUT`, is the same site: it is flagged when the query
reads a protected table anywhere — its own `FROM`, a join, a derived table, a
CTE or a set-operation branch — because the projection of a COPY query does not
say which columns actually leave. Run the query as an ordinary `SELECT` and its
rows come back as `DataRow` frames the read path can decrypt and mask.

The legacy function-call fast path is the other read shape the proxy cannot
cover. `FunctionCall`/`FunctionCallResponse` invokes a function by OID with no
SQL and no `RowDescription`, so its one-value answer carries no column identity
at all — a function that reads a protected column (`lo_get`, a custom accessor,
a `SECURITY DEFINER` reader) would return the stored form, and for a mask-only
column the unmasked value. It is an `on_unprotected` site like `COPY`: `warn`
relays it and logs once per session, `reject` refuses it. Modern drivers use it
only for libpq's large-object API, so switching to `reject` may need those calls
moved to SQL (`lo_get(oid)`).

## Deploying the proxy

**Startup is fail-closed.** `dbsec` with no argument loads `./dbsec.toml`, and if
that file is not there it refuses to start. The built-in defaults configure no
columns and no TLS, so falling back to them would leave a transparent plaintext
relay whose only evidence is `protected_columns=0` in one log line — and the
ways to get there are mundane: a systemd unit whose `WorkingDirectory` moved, a
container whose config volume mounted somewhere else. A deployment that really
does want a bare relay says so:

```
dbsec /etc/dbsec/dbsec.toml   # explicit path — the shape to prefer in a unit file
dbsec --plain-relay           # no config, no protection, on purpose
```

**The config file is a secret file when it carries a secret.** `keys_file`, the
Vault `token_file` and the downstream TLS key are refused unless they are
readable only by their owner (`chmod 600`), and the config itself joins them the
moment it holds an inline `[vault] token` or a `control_dsn` with a password.
Prefer `token_file` over an inline `token` so the credential is not in the file
that ships with the deployment at all. A config that carries no secret is an
ordinary file and its mode is not checked.

**Core dumps are disabled.** The process holds every DEK, every deterministic
index key and the Vault token in memory, and a core file writes all of it to
disk at once — the `Drop`-based zeroization the crate relies on never runs on an
abort. Startup therefore sets `RLIMIT_CORE` to 0 and clears the process'
`dumpable` attribute (`prctl(PR_SET_DUMPABLE, 0)`), which is what stops a
`kernel.core_pattern` piping to `systemd-coredump` or `apport` from collecting
the image anyway; clearing it also blocks a `ptrace` attach from another process
running as the same user. `dbsec --allow-core-dumps` turns both off for
debugging a crash — with the understanding that the resulting core is key
material.

**Authentication passes through, which rules out SCRAM channel binding.** The
proxy never terminates or re-originates the auth exchange — it relays the SASL
frames between two independent TLS sessions, so it holds no credential of yours.
The cost is `SCRAM-SHA-256-PLUS`: it binds the client's proof to *its own* TLS
session, and there are two of them here, so a client that selects `-PLUS` — what
a TLS-aware client does whenever the server advertises it — fails to
authenticate, and a client configured `channel_binding=require` cannot connect at
all. Use `channel_binding=prefer` (libpq's default, which falls back) or
`disable`. A client that asks for GSSAPI *encryption* is answered `N` and falls
back to the ordinary startup flow, which is plaintext unless downstream TLS is
configured — so configure `[tls.downstream]` if any client might prefer GSSENC.
What replaces channel binding here is per-hop verification: `verify-full`
upstream TLS with a pinned CA and hostname, and a downstream certificate the
client verifies. A deployment that needs end-to-end channel binding cannot use a
TLS-terminating proxy of any kind.

**Swap is the other half, and it is a host setting.** Key material paged out
lands on disk just as a core file would. The proxy deliberately does not call
`mlockall` itself: to be worth anything it would have to cover every allocation
the process ever makes, needs an `RLIMIT_MEMLOCK` only the deployment can grant,
and a partial lock would read as a guarantee it is not. Run the proxy on a host
with no swap, or with encrypted swap — `cryptsetup` with a random key per boot,
which is what a swap partition holding this process' pages is worth. Systemd
covers the rest of the process' surface:

```ini
# /etc/systemd/system/dbsec.service
[Service]
ExecStart=/usr/local/bin/dbsec /etc/dbsec/dbsec.toml
WorkingDirectory=/etc/dbsec
LimitCORE=0
MemoryDenyWriteExecute=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
```

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
