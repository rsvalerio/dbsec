# dbsec — minimal Rust field-encryption proxy for PostgreSQL

A small library (`dbsec-core`) plus a thin proxy binary (`dbsec`) covering the bare
minimum: transparent field-level encryption, searchable encryption, pseudonymization
and masking for PostgreSQL. Not a framework.

## Scope decisions

| Decision | Choice |
|---|---|
| Database | PostgreSQL only (wire protocol v3) |
| Shape | Library + thin proxy binary (~200-line `main`) |
| Crypto format | Fresh envelope — no compatibility with other proxies |
| SQL depth | sqlparser rewrite of literals + extended-protocol Parse/Bind |
| TLS | Both hops via rustls, each independently optional |
| Keys | `KeySource` trait; OpenBao/Vault impl (Transit envelope), `FileKeySource` for dev |
| Config | Flat TOML: `[[column]]` entries |
| Searchable | Deterministic HMAC-SHA256 prefix + equality WHERE rewrite |
| Pseudonymization | Storage-free: FF1 FPE (format-shaped data) + HMAC tokens (strings) |
| Masking | Static per-column, read-path only (e.g. keep_last = 4) |
| Dropped | MySQL, alternative crypto backends, SQL firewall, poison records, zones, per-client identity, HTTP/gRPC API |

## Ciphertext envelope

```
"DBS2" | key_id (16B) | nonce (12B) | AES-256-GCM ciphertext+tag
```

Searchable columns prepend `hmac_sha256(index_key, plaintext)[..32]`. Stored as BYTEA.
Non-magic values pass through untouched (gradual migration of existing plaintext).

The GCM associated data is `key_id || schema.table.column`, not the key id alone. Every
encrypted column in a process seals under the same active DEK and so stamps the same key
id; binding only that would authenticate a blob anywhere the key reaches, letting anyone
who can write stored bytes paste one column's ciphertext into another and have it decrypt
cleanly. Binding the column means a relocated value fails authentication instead. A table that
declares a `row_key` goes further, sealing as `DBS3` with the row's key in the associated
data so a value moved between two rows of the same column also fails; see "Binding a value
to its row" for what that costs a deployment.

`"DBS1"` is the pre-context version: same header, key id alone as associated data. See
"Upgrading DBS1 rows to the bound envelope" below.

## Core abstraction

`FieldTransform` trait — encrypt / tokenize-fpe / tokenize-hmac are the implementations;
blind-index and mask-on-read are read/write-path decorators. Everything else is plumbing.

## Data path

Client→DB: `Query` → sqlparser rewrite of INSERT/UPDATE literals and searchable WHERE
equality; `Parse` → remember param positions per statement; `Bind` → transform bound
params.

Two kinds of failure, and they fail in opposite directions:

- **Crypto failures always fail closed**, under every setting: a seal or open that errors,
  a key that cannot be fetched, a blind index that cannot be computed. The session is
  dropped rather than relaying a value the proxy could not protect.
- **Routing failures obey `on_unprotected`.** These are the statements the rewrite cannot
  cover, so a protected column would take a plaintext write (or a searchable predicate
  would match nothing): non-UTF-8 or unparseable SQL, `INSERT` without a column list,
  `INSERT ... SELECT`, `COPY`, `MERGE`, `PREPARE` of a write, a non-literal expression
  assigned to a protected column, an unqualified name in a session that moved
  `search_path`, a session that turned `standard_conforming_strings` off, and a predicate
  over a searchable column that no blind-index match can express. `on_unprotected =
  "warn"` (the default) logs and relays; `on_unprotected =
  "reject"` answers the client with a PostgreSQL ErrorResponse and never forwards the
  statement. The refusal is statement-level — the connection stays open and the session
  recovers at the next `ReadyForQuery` — because the statement never reached the backend.
  A *read*-path refusal carries the same ErrorResponse but then closes the connection:
  its statement has already run, and only closing makes the backend roll back the rest of
  the batch instead of committing it behind the error.

The default is `warn` because `reject` refuses statements that work today, including any
SQL sqlparser cannot parse but PostgreSQL can, whether or not it touches a protected
table. A deployment that needs the "never at rest in plaintext" invariant enforced runs
on `warn` long enough to collect the warnings, fixes them, then switches to `reject`.

DB→Client: `RowDescription` → match configured columns by table OID + attnum (resolved at
startup via a control connection); `DataRow` → strip blind index, check magic, decrypt /
detokenize, then mask; recompute message length.

TLS: `MaybeTls` stream enum both hops. Downstream handles `SSLRequest` from clients
(reject plaintext when TLS configured); upstream sends `SSLRequest`, verify-full.

## Milestones

1. **Pass-through proxy** — tokio listener, PG framing, byte relay, works with psql. *(done)*
2. **Crypto core** — envelope + blind index + `FileKeySource`, property tests. *(done)*
3. **TLS** — `MaybeTls` both hops + SSLRequest handling. Early because it fixes stream types.
   *(done; plaintext clients rejected when downstream TLS is set, upstream is verify-full
   with no downgrade)*
4. **Decrypt path** — RowDescription/DataRow interception, OID resolution, passthrough.
   *(done; control connection uses tokio-postgres, columns resolved at startup fail-closed.
   Text-format BYTEA (`\x` hex) and binary format both handled by per-value envelope
   detection, so Bind-time result formats don't need tracking yet)*
5. **Encrypt path** — sqlparser rewrite (Query) + Parse/Bind; `FieldTransform` trait born here.
   *(done; searchable columns already get their blind index prepended on write, so
   milestone 8 only adds the WHERE equality rewrite. `INSERT ... ON CONFLICT DO UPDATE`
   seals its conflict action through the same path as `UPDATE`. Everything the rewrite
   cannot cover — INSERT without a column list, INSERT...SELECT, COPY, MERGE, PREPARE of
   a write, non-literal expressions — is an `on_unprotected` site: warned about by
   default, refused with an ErrorResponse under `on_unprotected = "reject"`)*
6. **Pseudonymization** — FPE + HMAC token transforms; optional detokenize-on-read.
   *(done; `transform = "fpe" | "token"` per column, FF1 over decimal digits with
   separators preserved (<6 digits refused at seal time), tokens are irreversible
   hex HMACs. Transforms declare a `WireForm` so text-shaped stored forms are not
   hex-mangled; write-only columns never join the read map)*
7. **Masking** — read-path mask transform + TOML mask specs. *(done;
   `mask = { keep_first, keep_last, mask_with }` per column, applied after
   open (or to raw values when nothing opens). `transform = "none"` allows
   mask-only columns; too-short values mask entirely)*
8. **Searchable** — HMAC prefix + WHERE equality rewrite. *(done; `col = <value>`
   on searchable columns becomes `substring(col from 1 for 32) = <index>` in
   SELECT/UPDATE/DELETE WHERE clauses — literals inline, placeholders replaced
   with the index at Bind. Traverses AND/OR/NOT and parens; alias-qualified
   references resolve, ambiguous ones are skipped with a warning)*
9. **Vault/OpenBao KeySource** — DEKs by key_id + blind-index/FPE/token-HMAC keys; DEK cache.
   *(done; `[vault]` config section. Fresh Transit data key per startup, wrapped blob
   stored in KV v2 under the envelope key id; older DEKs unwrapped via Transit on
   demand and cached. Index keys live one-per-secret at `{path}/index_keys/{name}`,
   minted on first use with KV v2 check-and-set (`cas = 0`) and versioned inside the
   record, so minting column B cannot overwrite column A's key and two proxies racing
   to mint the same name cannot lose one; the loser adopts the winner's key. A failed
   read is an error, never "no keys yet". The pre-versioning shared-map layout is still
   read and migrated on first touch, at WARN, leaving the old copy for an operator to
   retire (see "Retiring the shared-map layout"). Every roundtrip is bounded by
   `[vault] timeout_secs`.
   Needs live-server integration coverage in milestone 10)*
10. **Hardening** — cargo-fuzz on the frame parser; driver integration suite (sqlx,
    psycopg) over TLS against dockerized Postgres. *(done; `fuzz/` has `pgwire`,
    `envelope` and `transform` targets — the last covering masking and the read path over
    arbitrary stored bytes (`make fuzz`; smoke-ran millions of execs clean). `make e2e`
    runs the real binary between dockerized Postgres 17 and three driver families
    over the TLS client hop — tokio-postgres (both protocols), sqlx (cached named
    statements, binary results, text-format BYTEA decoding) and psycopg 2/3 (unnamed
    statements, prepared statements, client-side binding) — verifying
    encrypt/decrypt, FPE, tokens, masking, searchable equality and at-rest
    ciphertext. `make e2e-vault` repeats the core of that against a live dev-mode
    OpenBao, covering cross-restart DEK unwrap through Transit and index-key reuse
    from KV. Both targets take an already-running service via `DBSEC_E2E_DSN` /
    `DBSEC_E2E_VAULT_ADDR` instead of starting a container. The matrix paid for
    itself immediately: it found decrypted BYTEA handed back raw in text result
    format (undecodable by typed drivers) and `'\x…'::bytea` literals from
    client-side binding passing through unencrypted — both fixed)*

## Caveats (accepted trade-offs)

- Deterministic blind index / tokens leak equality and frequency patterns.
- sqlparser-rs won't parse all exotic PG syntax; those queries pass through unencrypted —
  log loudly. Literals wrapped in casts (`'\x…'::bytea`, as psycopg's client-side binding
  emits) are understood, but function calls and other computed values are not. All of
  these are `on_unprotected` sites, so a deployment can turn them into refusals.
- **`COPY` is refused, not encrypted** (decided; the two options were rejecting the
  statement under `on_unprotected = "reject"` or parsing and transforming the `CopyData`
  stream). `COPY ... FROM` carries its payload in `CopyData` frames rather than SQL, so
  encrypting it means implementing the text, CSV and binary copy formats and refusing the
  ones that are left — a second, format-specific rewrite engine for a path that is a bulk
  load, i.e. exactly where a parsing bug is most expensive. `COPY ... TO` is the same hole
  in the read direction: it bypasses `DataRow` interception entirely, so a protected
  column leaves as its stored form — ciphertext for encrypted columns (fail-safe) but the
  *unmasked* stored value for a mask-only column, which silently defeats masking. Both
  directions are `on_unprotected` sites: warned about by default, refused under `reject`.
  Bulk-loading a protected table means going through `INSERT`, or sealing the data before
  it reaches the proxy.
- **Unqualified table names assume `search_path` is the default.** A `[[column]]` entry
  without a schema means `public`, and the write path resolves a bare SQL name the same
  way. A session that moves `search_path` breaks that in both directions — a bare write
  can miss the catalog (plaintext at rest) or match the wrong table (sealed for a table
  the read path, which resolves by OID, never looks at, so it reads back as ciphertext
  forever). The proxy therefore watches the startup packet's `search_path`/`options`
  parameters and every spelling that moves the setting in-session — `SET search_path`,
  `SET SCHEMA`, `set_config('search_path', …)`, read from the SQL token stream because
  two of the three are invisible in the parsed statement — and once the default no longer
  holds it stops resolving unqualified names at all; that is an `on_unprotected` site
  too. Qualifying either the config or the SQL removes the question.
- **Sealed literals assume nothing about `standard_conforming_strings`.** They go out as
  `E'\\x…'`, whose backslash handling does not depend on the setting, rather than the
  plain `'\x…'` that reads as `bytea` hex input only while it is on. The proxy still
  reports a session that turns it off as an `on_unprotected` site: from that point the
  server reads the *client's* own string literals differently from the proxy's parser.
  Both halves of "turns it off" are watched — the startup packet's own parameter or
  `options=-c` spelling, reported on the first statement because a refusal needs a frame
  to answer, and every in-session spelling, reported where it is written.
- **Identifiers are folded the way PostgreSQL folds them.** Unquoted names are downcased
  ASCII-only — Rust's `to_lowercase` would fold `Ä` and the Kelvin sign, where the server
  leaves every multibyte character alone — and every name is clipped to 63 bytes
  (`NAMEDATALEN - 1`). One function does it for both the write path's SQL identifiers and
  the configured `[[column]]` names, so the two sides of a name comparison cannot drift.
- **Ciphertext relocation is detected across columns always, across rows only where a
  `row_key` is declared.** The envelope AAD binds `schema.table.column`, so pasting a
  stored value into a different column or table fails authentication. Pasting it into the
  *same* column of another row fails only for a table with a declared row key, and only
  for `transform = "encrypt"` columns — deterministic transforms store identical bytes in
  every row by design. Rows written before either binding (`DBS1`, `DBS2`) keep the
  guarantee they were written under until re-encrypted. See "Binding a value to its row".
- **Authentication is relayed, not terminated, so `SCRAM-SHA-256-PLUS` cannot work and
  GSSAPI encryption is always refused.** The proxy never speaks the auth exchange itself:
  it forwards the SASL frames verbatim between two independent TLS sessions. Channel
  binding is what that breaks — `-PLUS` binds the SCRAM proof to *its own* TLS session's
  endpoint data, and there are two different sessions here, so a client that selects
  `-PLUS` (which a TLS-aware client does whenever the server advertises it) computes its
  proof over the downstream channel while the server checks it against the upstream one,
  and authentication fails. `channel_binding=require` clients therefore cannot connect
  through the proxy at all. Separately, a client that sends `GSSENCRequest` is answered
  `N` and falls back to the ordinary startup flow — which is plaintext when downstream TLS
  is not configured.
  **Decision: `channel_binding=require` is not supported, and re-originating SCRAM is
  rejected.** Making `-PLUS` work means terminating authentication at the proxy: holding
  or verifying the client's credential to run one SCRAM exchange downstream and another
  upstream, which turns a proxy that has never needed a password into one that stores
  them, and puts an auth implementation in the trusted path next to the crypto. The
  proxy's own answer to MITM detection is `verify-full` upstream TLS with a pinned CA and
  hostname, plus a downstream certificate the client verifies — the property channel
  binding provides, established per hop rather than end to end. Deployments that must have
  end-to-end channel binding should not put a TLS-terminating proxy in the path.
- FF1 on tiny domains (<6 digits) is brute-forceable — refuse in config validation.
- Rotating the blind-index/FPE/token keys breaks determinism; only DEKs rotate freely.
  Rotation is an operator re-index, not a proxy feature — see below.
- AES-GCM nonces are random 96-bit, so a DEK has a finite safe lifetime: NIST SP 800-38D
  §8.3 caps a random-IV key at 2^32 invocations (nonce-collision probability under 2^-32;
  a repeat leaks the XOR of two plaintexts and the GHASH subkey, retroactively over every
  row stored under that key). `envelope::MAX_ENCRYPTIONS_PER_KEY` enforces that budget per
  DEK across the whole process — the write path goes through one shared `envelope::Ciphers`
  cache, which rolls to a fresh DEK when the key source offers one (Vault mints one per
  start) and otherwise fails closed with `Error::KeyExhausted` rather than reusing a spent
  key. A counter-based nonce would remove the birthday bound but needs durable counter
  state across restarts; that trade is not taken.
- **The proxy must not be run under a pre-forking supervisor.** The per-key budget bounds
  nonce collisions inside one generator's stream; it says nothing about two generators
  emitting the *same* stream. Nonces come from `thread_rng` — thread-local userspace
  ChaCha12 state — so a `fork()` after a DEK is resolved gives both children identical
  nonces under one key, each staying inside its budget while colliding with the other, and
  GCM nonce reuse is retroactive over every row under that DEK. `main` builds a
  multi-thread tokio runtime and never forks, so this is a deployment constraint rather
  than a live bug. Supporting a forking model means reseeding after fork, or moving the
  nonce draw to `OsRng` (fork-safe, since the kernel holds the state) and paying a
  `getrandom` syscall per protected value.
- Masking is enforced only for traffic through this proxy.

## Deterministic key rotation and compromise recovery

DEKs rotate for free: every startup mints a new one and ciphertexts carry the key id that
opens them, so old and new coexist. The deterministic keys behind blind indexes, FPE and
tokens cannot work that way — the whole point of them is that the same input maps to the
same stored bytes forever. Changing one invalidates every index, pseudonym and token
already written under it.

**Decision: the proxy does not implement a dual-key read window.** It was considered and
rejected because it only helps one of the three deterministic transforms while taxing the
one path that is hot:

- **Blind index** — a dual-key read means rewriting `col = $1` into a disjunction over
  every live key version (`substring(col …) = idx_new OR substring(col …) = idx_old`).
  That is expressible, but it multiplies the index scans behind every searchable query for
  the entire duration of a re-index, and the planner sees a disjunction rather than a
  single equality.
- **FPE** — has no read window to widen. A value enciphered under the old key decrypts to
  plausible-looking garbage under the new one, with nothing in the stored form to say
  which key produced it. Trying both and guessing which output is "right" is not a thing
  the proxy can do correctly.
- **Tokens** — irreversible by construction. There is no read path at all, so there is
  nothing to accept under two keys.

Re-indexing therefore stays with the operator. What the proxy owes that operator is a
storage layout in which a rotation is *expressible*, and that is what it now has: each
name lives in its own KV secret at `{path}/index_keys/{name}` holding `current` (the
version writes use) plus a `versions` map. The proxy reads only `current`; the older
versions stay so the previous key material survives a rotation and the migration can find
it.

### Vault token lease, and why revocation needs a restart

The proxy authenticates once at startup with the configured static token. A watchdog task
asks Vault about that token once a minute (`auth/token/lookup-self`) and renews it
(`auth/token/renew-self`) when under ten minutes of lease remain, so a TTL'd token can be
used without it quietly expiring mid-run. A lease that is running out and cannot be
extended is logged at WARN on every check, naming the remaining TTL — deliberately loud,
because the key caches otherwise hide an expired token entirely: everything already cached
keeps serving and only the first cache miss fails, at ERROR, with nothing to connect it to
the token. Deployments end up using root tokens because of exactly that.

**Revoking the token, or rotating a key in Vault, has no effect on a running proxy.** The
DEK and index-key caches are grow-only and carry no TTL, so a key resolved once is served
from memory for the life of the process. This is a decision, not an omission: a cache TTL
would put a Vault round-trip on the relay path at unpredictable moments and make Vault a
per-request availability dependency, and it buys nothing here — deterministic index keys
*must not* change under a running column, and re-fetching a DEK returns the same DEK.

So the runbook is: **any Vault-side revocation or rotation is followed by a proxy
restart.** Until the restart, treat the running process as still holding every key it has
already resolved.

### If a deterministic key is exposed

Treat it as disclosure of the column's equality and frequency distribution: the blind
index becomes an offline oracle against the whole column, and FPE values become reversible
by whoever holds the key. Encryption of the underlying value is unaffected — the DEK is a
different key — so this is a linkability compromise, not a plaintext one.

1. **Stop the bleeding.** Revoke the Vault token or policy that leaked, then restart every
   proxy that used it — revocation does not reach a running one (see above). Read
   `{path}/index_keys/{name}` and confirm which versions existed at the time.
2. **Take the column out of search.** Set `searchable = false` (or drop `transform` to
   `"none"` with a mask) and restart. Writes stop emitting an index under the exposed key;
   equality queries stop rewriting. Reads still work — the blind index is a prefix, not
   part of the envelope.
3. **Mint the next version.** Add a new entry to `versions` and bump `current`. The proxy
   picks it up on restart; nothing is auto-minted over a stored key, so this is the only
   way the key changes.
4. **Re-index, offline.** For each row: read the value through a proxy still configured
   with the old key (or decrypt the envelope directly with the DEK), then write it back
   through a proxy configured with the new one. The proxy cannot drive this itself — it
   sees one statement at a time and has no authority to rewrite a table it was not asked
   about. Batch by primary key and expect it to be a full table pass.
5. **Re-enable search** and drop the superseded version from `versions` once no row can
   still carry an index under it.

FPE columns follow the same shape but the value itself changes, so anything downstream
holding the old pseudonym stops matching. Token columns cannot be re-indexed at all —
the original is gone — so a compromised token key means accepting that previously issued
tokens are correlatable, and future ones are not.

The honest summary: steps 4 and 5 are a migration the operator writes. What changed is
that the key material is versioned rather than stored under one unversioned name, so the
migration has something to point at, and a partially completed rotation is a legible state
rather than a lost key.

### Upgrading DBS1 rows to the bound envelope

`DBS1` values — everything written before the column binding — keep opening, under any
column, so an upgrade needs no migration step to stay *readable*. What they do not get is
the relocation protection: their tag was computed over the key id alone, and a tag cannot
be extended after the fact. A stored `DBS1` blob therefore still decrypts wherever its DEK
reaches, which is the whole point of moving to `DBS2`.

Closing that gap means re-encrypting, and re-encryption is a read-then-write through the
proxy — nothing else has the DEK and the column context together:

1. **Upgrade and restart.** From then on every write emits `DBS2`; reads accept both.
2. **Rewrite each protected column in batches**, through the proxy, keyed by primary key:
   `UPDATE t SET c = c WHERE id BETWEEN ? AND ?` does *not* work — the value never leaves
   the server. The rewrite has to `SELECT` the batch (the proxy decrypts), then `UPDATE`
   with the returned plaintext as a bound parameter (the proxy re-seals it, bound to the
   column). Batch small enough that one transaction is cheap to retry.
3. **Confirm the sweep.** `DBS2` is `\x44425332` at the head of the BYTEA column (after the
   32-byte blind index, for searchable columns), so
   `SELECT count(*) FROM t WHERE substring(c from 1 for 4) <> '\x44425332'` — offset by 32
   where an index prefix is present — counts what is left. Zero means the column is bound.
4. **Only then** treat cross-column relocation as detected for that column. Until the
   count is zero, a single un-upgraded row is a usable relocation source.

Rotating the DEK does not do this for you: DEKs roll per start, but existing rows are not
rewritten, and an old `DBS1` row keeps its old key id and its old (unbound) tag.

### Renaming a bound column is a re-encryption

The bound context is the configured `schema.table.column` string, so renaming a protected
column or table — in the database and in `[[column]]` — makes every `DBS2` value already
stored under the old name fail authentication. The proxy cannot tell that from a relocated
value, and it should not: "this ciphertext was written somewhere else" is exactly what the
binding is for.

So a rename is the same sweep as the `DBS1` upgrade above, in the opposite order: while
the proxy still has the **old** name configured, read the column out (it decrypts) and
hold the plaintext; rename; then write it back through a proxy configured with the new
name. Doing it the other way round leaves an unreadable column. Deterministic keys are
named the same way, so a rename also means the blind index / FPE / token key for that
column is looked up under a new name — copy the old key's material into the new name's
secret first, or the column is re-indexed under a freshly minted key and every stored
token stops matching.

### Binding a value to its row

The envelope binds `schema.table.column`, which stops cross-column and cross-table
relocation. Cross-*row* relocation within one column needs more, and it is available as an
opt-in: a table that declares a `row_key` seals its encrypted values as `DBS3`, whose
associated data is `key_id || len ‖ schema.table.column || len ‖ canonical(row_key)`.

The length prefixes are not tidiness. With three variable fields a plain concatenation is
forgeable — column `users.ssn` with row `42` and column `users.ssn4` with row `2` are the
same bytes — and the row key is usually the attacker's own row id, so they can choose one
that straddles the seam.

Start from what relocation detection needs, because it rules out the cheaper designs. The
verifier has to know, **independently of the copied bytes**, where those bytes belong. Any
identifier that travels with the ciphertext — a salt in the header, a token in a sibling
column — is copied along with it and proves nothing. So the identity has to be one the
application already treats as the row's name: its primary key. (An attacker who rewrites
the primary key has not relocated a value; they have renamed the row. That is exactly why
the key qualifies and a proxy-minted identifier does not.)

Two problems had to be solved rather than designed around:

- **The value is untyped and format-ambiguous.** `id = 42` arrives as `b"42"` from a
  text-format client and as four big-endian bytes from a binary one, and both appear in
  this repo's e2e suite. `RowDescription` now retains `atttypid` and the format code, and
  `proxy::rowkey` canonicalises per type to the value's ordinary text form. The supported
  set is small on purpose — integers, text, uuid — because each type needs a decoder that
  matches PostgreSQL's own output exactly; anything else is refused at startup, naming the
  column.
- **The key is usually not projected.** `SELECT ssn FROM users WHERE id = $1` does not
  return `id`. Injecting it into the target list and stripping it before relay would mean
  parsing and rewriting `SELECT`s, which this path exists to avoid — it matches on catalog
  OIDs precisely so `SELECT *`, CTEs, unions and cached prepared statements need no SQL
  understanding. So the query must project the key, and one that does not gets
  `RowKeyMissing` rather than the stored bytes.

**What a deployment accepts by declaring a row key.** Each of these is a refusal, not a
degradation:

- Client-generated keys only on protected tables. A `serial` key does not exist when the
  proxy rewrites the `INSERT`, so the value cannot be sealed against it.
- Single-row `UPDATE ... WHERE row_key = ?` for protected columns. A Bind carries one byte
  string per placeholder, so a multi-row update would need a different ciphertext per row
  and there is nowhere to put them.
- Every read of a protected column projects that table's row key.

**What it does not cover.** Only `transform = "encrypt"` binds a row. FPE and tokenization
map a plaintext to identical stored bytes in every row — the determinism that makes them
searchable and joinable — so there is no associated data to bind and adding one would
destroy the property they are chosen for. Config validation refuses a `row_key` on a table
whose columns are all deterministic, rather than letting it look like coverage.

**Migration.** Opt-in per table, and the *stored value* decides which AAD verifies it, so
`DBS2` rows keep opening after their table gains a key. Re-encrypt to make the binding
retroactive; until then a row written before the change is bound to its column only.

### Retiring the shared-map layout

Deployments predating the per-name layout kept every deterministic key in one shared KV
secret at `{path}/index_keys`. A name still found there is copied into its own versioned
secret on first touch and used from there — but the copy is not deleted, because deleting
key material as a side effect of a read path is not a decision the proxy gets to make
unprompted, and at that moment the destination write is not yet confirmed durable.

So the same key lives at two paths until an operator retires the old one. That is worth
doing: a policy granting read on the shared map still yields keys that are live at the new
paths, and the duplicate is invisible to anyone auditing `{path}/index_keys/*`. Each
migration announces itself with a WARN line naming the key, so a log capture from one full
pass over the workload tells you which names came from the legacy layout.

Cleanup is an operator step, run once the deployment has served every protected column at
least once (that is what forces each name to migrate):

1. **List both sides.** Read the shared map at `{path}/index_keys` and list the per-name
   secrets under `{path}/index_keys/`.
2. **Verify every name migrated.** For each name in the shared map, confirm
   `{path}/index_keys/{name}` exists and that its `current` version holds the *same* key
   material as the map. A name whose per-name secret is missing has not been touched
   since the upgrade — connect and issue one query against that column, then re-check.
   Never hand-copy it: a mistyped key is indistinguishable from a rotation and silently
   invalidates the column's index.
3. **Delete the shared secret and its history.** Deleting the latest version leaves the
   old versions readable, so remove the metadata:
   `bao kv metadata delete {mount}/{path}/index_keys`. In KV v2 the per-name secrets
   under `{path}/index_keys/` are separate secrets, not children of that record, so they
   are unaffected.
4. **Narrow the policy.** Drop any read capability naming the shared path, so a
   re-created secret cannot become a second source of truth.

If step 2 cannot be completed — a column that no longer exists, a name nothing queries —
the safe end state is to keep the shared map and its policy restricted rather than to
delete material that no per-name secret carries. Losing a deterministic key is
unrecoverable without a full re-index.

## Infra

- CI/release via forge (`rsvalerio/forge`): `ci.yml` and `bump.yml` are thin wrappers;
  deny/clippy/rustfmt configs copied from `forge/config`, `CONTRIBUTING.md` from
  `forge/templates`. Staying in sync is enforced, not remembered: `.forge-sync/manifest`
  lists the copies and `scripts/forge-sync-check.sh` (the `forge-sync` CI job,
  `make forge-sync`) diffs each one against the forge tag the workflows pin. Deliberate
  divergence is recorded as a waiver patch under `.forge-sync/waivers/` with a reason,
  so the exemption is the diff itself and a later forge-side change still fails.
- `e2e.yml` is repo-local rather than a forge wrapper: the forge gates run `cargo test`,
  which skips both e2e suites (they are `#[ignore]`d without a database). It supplies
  Postgres and a dev-mode OpenBao as job services and points the suites at them with
  `DBSEC_E2E_DSN` / `DBSEC_E2E_VAULT_ADDR`, so no containers are started by the build.
- Build commands via `ops` (`make check` → `ops verify qa`).
- Conventional commits + cocogitto (`cog.toml`, signed mode: no push hooks).
