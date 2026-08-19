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
column, an unqualified name under a changed `search_path`, a session that turned
`standard_conforming_strings` off, a predicate over a searchable column that no
blind-index match can express, and a protected column projected through an
expression — `email::text`, `ccnum || ''`,
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
the proxy watches the startup packet and every spelling that moves the setting —
`SET search_path`, `SET SCHEMA`, `set_config('search_path', …)` — and stops
resolving bare names once the default no longer holds (an `on_unprotected`
site). Schema-qualifying either the config or the SQL avoids the question
entirely.

**`standard_conforming_strings`** — the proxy assumes the default, `on`, in
which a backslash in an ordinary string literal is just a backslash. Sealed
values go out as `E'\\x…'` so they mean the same bytes either way, but a
session that turns the setting off makes the server read the *client's* own
literals differently from the proxy's parser, so the change is an
`on_unprotected` site. Turning it off in the startup packet — as a parameter or
through `options=-c standard_conforming_strings=off` — is watched the same way
and reported on the session's first statement.

**`row_key`** — by default a stored value is bound to its *column*, so pasting
one column's ciphertext into another fails to decrypt. Binding it to its *row*
as well is opt-in per table:

```toml
[[table]]
table   = "users"
row_key = "id"      # unique per row: a primary key, or a unique column
```

With that, a value copied from one row's `users.ssn` into another row's
`users.ssn` no longer decrypts. It is opt-in because it constrains the SQL the
table can take. **Every write-path constraint below is an `on_unprotected`
site**, so it follows that setting rather than being an unconditional refusal:
on the default `warn` the statement is logged — one warning naming the table
and the row key — and relayed, and only `reject` answers the client with an
ErrorResponse. Read-path verification is the exception and is never relaxed.

- **Client-generated keys only.** `INSERT` must carry `id` in its column list,
  and its value must be a literal or a bound parameter. A `serial` key does not
  exist yet when the proxy rewrites the statement, so there is nothing to seal
  the value against. Refused under `reject`; under `warn` the row's protected
  columns are sealed cell-only, which is the binding the table had before it
  declared a row key — never plaintext.
- **Single-row updates.** `UPDATE users SET ssn = $1 WHERE id = $2` is fine;
  `WHERE dept = 'x'` is a site — refused under `reject`, and under `warn`
  sealed cell-only, which is the binding the table had before it declared a row
  key. One bound parameter cannot become a different ciphertext for every
  matching row. The key has to be named on the table being written, so with an
  `UPDATE ... FROM other`, qualify it: `WHERE u.id = $2`.
- **The row key is immutable once a row holds a protected value.** An `UPDATE`
  that assigns `id` moves the row out from under the key its values are sealed
  against, and they never open again — so a statement that writes both `id` and
  a protected column of the same table is a site too. That is only the case the
  proxy can see: changing `id` on its own is reported by nothing and still
  orphans every value already stored in that row. Re-encrypt the row's protected
  columns in the same transaction if the key really has to move.
- **Upserts conflict on the key.** `INSERT … ON CONFLICT (id) DO UPDATE SET ssn
  = $2` is fine: the conflicting row is the row with that `id`. `ON CONFLICT
  (email)`, `ON CONFLICT ON CONSTRAINT …` and a multi-row `VALUES` list are
  sites, because the row the action updates may carry any key at all.
- **A row key bound as a parameter has to be usable.** A NULL `$2`, a text key
  that is not UTF-8, or a binary integer of the wrong width refuses that one
  statement with an ErrorResponse under either setting — the session carries on
  — because there is no "warn and relay" answer that is not a write bound to
  the wrong row or to none.
- **Reads must project the key.** `SELECT ssn FROM users WHERE id = $1` does not
  return `id`, so it cannot be verified; select `id` too. Unlike the write-path
  sites this is an unconditional refusal (SQLSTATE 42501): the alternative is
  handing the client a stored value the proxy could not verify.
- **Once per result set.** A self-join projects `id` twice, and the wire
  protocol identifies a result column by table OID and attribute number, which
  are identical for both instances of the table. `SELECT a.id, a.ssn, b.id,
  b.ssn FROM users a JOIN users b ...` is refused rather than opened against
  whichever `id` came first; query each instance separately. An unconditional
  refusal too, for the same reason.

  Projecting the key *once* — `SELECT a.id, a.ssn, b.ssn` — is the same problem
  seen from the other side, and it is not detectable in advance: it describes
  identically to `SELECT id, ssn, ssn FROM users`, where both fields do name the
  same row and open correctly. So it is not refused on sight. The values are
  opened, and if one cannot authenticate against the single key on offer the
  refusal names the table and says to query each instance separately. The
  message also carries the other reading — a value that really does belong to
  another row — because at that point the two are indistinguishable.

The key column must be a type the proxy can canonicalise — integer, text or
uuid — and must not itself be protected. Both are refused at startup, naming the
column. `char(n)` is not one of them: the server blank-pads it on output and the
client does not on input, so `'abc'` would seal against one form and read back as
the other. The key's *value* is what binds, not the spelling it was written in —
`0007`, `+7` and `7` are the same row, as are an upper-case, braced or
unhyphenated `uuid`. Only `transform = "encrypt"` binds a row: `fpe` and `token`
store the same bytes for a plaintext in every row by design, which is what makes
them searchable, so a `row_key` on a table with no encrypt column is refused
rather than left looking like coverage.

Adopting it needs no migration. Values written before the change keep opening —
the stored value decides which binding verifies it — so re-encrypt only when you
want the row binding to be retroactive.

That tolerance is a migration window, not a permanent setting. While it is open,
a value carrying no row binding is accepted in a row-bound column, and nothing in
the stored bytes says whether it predates the `row_key` or came from a write that
could not name its row — an upsert branch, or an `UPDATE` the proxy warned about
under `on_unprotected = "warn"`. Either way the result is a ciphertext that can
be copied between rows of that column undetected, for as long as the DEK lives.
Close the window once the table's older values have been re-encrypted:

```toml
[[table]]
table              = "users"
row_key            = "id"
strict_row_binding = true   # a value with no row binding is refused on read
```

The refusal reaches the client as the same ErrorResponse a missing row key
carries, and names the remedy. Turn it back off for the duration if a migration
has to be re-run.

**Identifier names** — a `[[column]]` name is the name the catalog holds. SQL
identifiers are folded the way PostgreSQL folds them before they are compared
against it: unquoted names are downcased ASCII-only (a multibyte character is
left exactly as written), and every name is clipped to 63 bytes. A configured
name longer than that is refused at startup, and one that is not itself in
folded form warns — only a double-quoted SQL reference will ever match it.

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

**`max_protected_value_bytes`** — the largest single protected column value the
read path will decrypt, mask and re-encode; the default is 16 MiB. Opening one
value costs several times its own size in transient memory — the hex-decoded
stored form, the plaintext, the masked copy, the hex re-encode — so an
unbounded value near the 1 GiB frame limit drives peak resident memory to
several GiB *per session*. A value over the ceiling is a read-path refusal
(`ERROR` + closed session, as above), never a relay of the stored form. The
default is generous for field-level encryption, so raising it is only for a
deployment that really does encrypt a column holding documents, images or large
JSONB — and it buys that with the memory. `0` is refused at startup, as is
anything above the 1 GiB frame limit, which no `DataRow` could reach anyway.

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
rows come back as `DataRow` frames the read path can decrypt and mask. Its
*predicates* are rewritten like any other query's, so under `warn` the relayed
statement still selects the rows the client asked for rather than none; only
the out-direction query form is re-rendered, never `COPY ... FROM STDIN`.

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
dbsec --help                  # the flags, on stdout, exit 0
```

The refusal only covers a *missing* file, though — a config file that exists and
declares no `[[column]]` reaches the same zero-protection state by a likelier
route (a `[[column]]` block lost to a bad merge or an environment overlay). That
is allowed, because a plain relay is a legitimate deployment, but it is never
silent: every startup that protects nothing logs one WARN saying so, naming the
config it read. `--plain-relay` logs the same line. Alert on it.

**The config file is a secret file when it carries a secret.** `keys_file`, the
Vault `token_file` and the downstream TLS key are refused unless they are
readable only by their owner (`chmod 600`), and the config itself joins them the
moment it holds an inline `[vault] token` or a `control_dsn` with a password.
Prefer `token_file` over an inline `token` so the credential is not in the file
that ships with the deployment at all. A config that carries no secret is an
ordinary file and its mode is not checked.

**Every outbound hop is refused in the clear.** The two pgwire hops already
send their own `SSLRequest` and fail on a refusal, and startup now holds the
other two to the same bar. `[vault] addr` must be `https` — that channel
carries the Vault token, every DEK in plaintext and every deterministic index
key, so a config copied out of a dev example does not get to put it on the
wire; a plaintext dev server is reachable only by writing
`allow_insecure_addr = true`, which is a choice rather than an oversight. And
with `[tls.upstream]` configured, `control_dsn` must carry `sslmode=require`:
its default is `prefer`, under which a server — or a MITM stripping the TLS
offer — that answers `N` gets a plaintext session with no error, and that is
the connection holding the control user's password and deciding which columns
are protected.

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
