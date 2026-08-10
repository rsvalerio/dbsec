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
7. **Masking** — read-path mask transform + TOML mask specs.
8. **Searchable** — HMAC prefix + WHERE equality rewrite.
9. **Vault/OpenBao KeySource** — DEKs by key_id + blind-index/FPE/token-HMAC keys; DEK cache.
10. **Hardening** — cargo-fuzz on the frame parser; driver integration suite (sqlx,
    psycopg) over TLS against dockerized Postgres.

## Caveats (accepted trade-offs)

- Deterministic blind index / tokens leak equality and frequency patterns.
- sqlparser-rs won't parse all exotic PG syntax; those queries pass through unencrypted —
  log loudly. `COPY FROM` is not encrypted; warn or reject on protected tables.
- FF1 on tiny domains (<6 digits) is brute-forceable — refuse in config validation.
- Rotating the blind-index/FPE/token keys breaks determinism; only DEKs rotate freely.
- Masking is enforced only for traffic through this proxy.

## Infra

- CI/release via forge (`rsvalerio/forge`): `ci.yml` and `bump.yml` are thin wrappers;
  deny/clippy/rustfmt configs copied from `forge/config` (keep in sync).
  Note: forge has no `v1` tag yet — workflows fail until it's tagged.
- Build commands via `ops` (`make check` → `ops verify qa`).
- Conventional commits + cocogitto (`cog.toml`, signed mode: no push hooks).
