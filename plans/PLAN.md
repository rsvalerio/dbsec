# dbsec — minimal Rust field-encryption proxy for PostgreSQL

A small library (`dbsec-core`) plus a thin proxy binary (`dbsec`) replacing Acra with the
bare minimum: transparent field-level encryption, searchable encryption, pseudonymization
and masking for PostgreSQL. Not a framework.

## Scope decisions

| Decision | Choice |
|---|---|
| Database | PostgreSQL only (wire protocol v3) |
| Shape | Library + thin proxy binary (~200-line `main`) |
| Crypto format | Fresh envelope — no Acra/Themis compatibility |
| SQL depth | Same as Acra: sqlparser rewrite of literals + extended-protocol Parse/Bind |
| TLS | Both hops via rustls, each independently optional |
| Keys | `KeySource` trait; OpenBao/Vault impl (Transit envelope), `FileKeySource` for dev |
| Config | Flat TOML: `[[column]]` entries |
| Searchable | Deterministic HMAC-SHA256 prefix + equality WHERE rewrite (Acra's approach) |
| Pseudonymization | Storage-free: FF1 FPE (format-shaped data) + HMAC tokens (strings) |
| Masking | Static per-column, read-path only (e.g. keep_last = 4) |
| Dropped | MySQL, Themis, acra-censor, poison records, zones, per-client identity, translator API |

## Ciphertext envelope

```
"DBS1" | key_id (16B) | nonce (12B) | AES-256-GCM ciphertext+tag
```

Searchable columns prepend `hmac_sha256(index_key, plaintext)[..32]`. Stored as BYTEA.
Non-magic values pass through untouched (gradual migration of existing plaintext).

## Core abstraction

`FieldTransform` trait — encrypt / tokenize-fpe / tokenize-hmac are the implementations;
blind-index and mask-on-read are read/write-path decorators. Everything else is plumbing.

## Data path

Client→DB: `Query` → sqlparser rewrite of INSERT/UPDATE literals and searchable WHERE
equality; `Parse` → remember param positions per statement; `Bind` → transform bound
params. Unparseable SQL passes through (logged loudly). Crypto errors fail closed.

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
   milestone 8 only adds the WHERE equality rewrite. INSERT without a column list,
   INSERT...SELECT, and non-literal expressions pass through with loud warnings;
   COPY on protected tables warns)*
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
   read and migrated on first touch. Every roundtrip is bounded by `[vault] timeout_secs`.
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
  emits) are understood, but function calls and other computed values are not. `COPY FROM`
  is not encrypted; warn or reject on protected tables.
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

### If a deterministic key is exposed

Treat it as disclosure of the column's equality and frequency distribution: the blind
index becomes an offline oracle against the whole column, and FPE values become reversible
by whoever holds the key. Encryption of the underlying value is unaffected — the DEK is a
different key — so this is a linkability compromise, not a plaintext one.

1. **Stop the bleeding.** Revoke the Vault token or policy that leaked. Read
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
