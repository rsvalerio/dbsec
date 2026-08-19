# dbsec vs the field

*Reviewed 2026-08-19 against dbsec v0.5.0.*

Why this document exists: dbsec was built to be an **embeddable Rust library
first** and a proxy second — a framework needs field-level encryption as a
linked-in feature, not as a Go daemon in the request path. This is the
feature-by-feature check of that claim against the products that solve the same
problem, and the record of which gaps are deliberate and which are debt.

The products compared:

- **[Acra](https://docs.cossacklabs.com/acra/)** (Cossack Labs, Go) — the closest
  functional peer: a SQL proxy (AcraServer) plus an HTTP/gRPC crypto service
  (AcraTranslator) and client-side SDKs (AcraWriter/AcraReader).
- **[CipherStash](https://cipherstash.com/)** (Rust core) — the closest
  *architectural* peer, and the one to benchmark the library goal against: a
  Rust client (`cipherstash-client`) embedded into per-language SDKs (Protect.js
  reaches it through Neon), plus an optional CipherStash Proxy and an `EQL`
  PostgreSQL extension.
- **pgcrypto / pgsodium** — in-database column encryption. Different trust model:
  keys live next to the data.
- **Vault/OpenBao Transit** — encryption as a service; the application calls out
  per value.
- **[AWS Database Encryption SDK](https://docs.aws.amazon.com/database-encryption-sdk/)** —
  library-only client-side field encryption with searchable "beacons". Included
  because it is the reference API shape for the library-first path.

## Feature matrix

| Capability | dbsec | Acra | CipherStash | pgcrypto/pgsodium | Vault Transit | AWS DB Enc SDK |
|---|---|---|---|---|---|---|
| Transparent field encryption through a SQL proxy | ✅ | ✅ | ✅ (Proxy) | ❌ | ❌ | ❌ |
| Same features from a linked-in library | ⚠️ partial | ✅ SDKs | ✅ (the primary shape) | n/a | ⚠️ per-value RPC | ✅ |
| Rust-native | ✅ | ❌ Go | ✅ core | ❌ C | ❌ | ❌ |
| Equality search over ciphertext | ✅ blind index | ✅ blind index | ✅ | ❌ | ❌ | ✅ beacons |
| Range / ordering search | ❌ | ❌ | ✅ ORE | ❌ | ❌ | ❌ |
| Prefix / `LIKE` / free-text match | ❌ | ❌ | ✅ match index | ❌ | ❌ | ❌ |
| Format-preserving pseudonymization | ✅ FF1, storage-free | ✅ (token store) | ⚠️ | ❌ | ✅ FPE (ent.) | ❌ |
| Irreversible tokens | ✅ HMAC | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| Read-path masking | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Ciphertext bound to its **column** | ✅ AAD | ~ zones | ✅ | ❌ | ❌ | ✅ signed context |
| Ciphertext bound to its **row** | ✅ `DBS3` opt-in | ❌ | ✅ per-value keys | ❌ | ❌ | ✅ |
| Per-value keys | ❌ (per-DEK) | ❌ | ✅ ZeroKMS | ❌ | ❌ | ⚠️ |
| Identity-aware / per-tenant keys | ❌ | ✅ zones | ✅ | ❌ | ⚠️ | ⚠️ |
| KMS-backed key storage | ✅ Vault/OpenBao | ✅ Vault/KMS/Redis/DB | ✅ ZeroKMS | ⚠️ in-DB | n/a | ✅ KMS |
| Automatic DEK rotation | ✅ per start | ✅ | ✅ | ❌ | ✅ | ✅ |
| Key-management CLI / re-encryption tooling | ❌ | ✅ `acra-keys` | ✅ | ❌ | ✅ | ⚠️ |
| Tamper-evident audit log | ❌ | ✅ signed | ✅ | ❌ | ✅ | ❌ |
| Metrics / observability | ❌ | ✅ | ✅ | n/a | ✅ | n/a |
| SQL firewall | ❌ dropped | ✅ AcraCensor | ❌ | ❌ | n/a | n/a |
| Poison records / intrusion detection | ❌ dropped | ✅ | ❌ | ❌ | n/a | n/a |
| MySQL | ❌ | ✅ | ❌ | n/a | n/a | n/a |
| PostgreSQL | ✅ | ✅ | ✅ | ✅ | n/a | ❌ (DynamoDB) |
| TLS on both hops | ✅ | ✅ | ✅ | n/a | ✅ | n/a |
| SCRAM channel binding through the proxy | ❌ documented | ✅ terminates auth | ⚠️ | n/a | n/a | n/a |
| No `unsafe` code | ✅ `forbid` | n/a | ⚠️ | ❌ | n/a | n/a |

`⚠️` means partial, unverified, or available only under a different shape than
the column reads.

## Where dbsec is ahead

- **Row binding.** A table that declares a `row_key` seals as `DBS3` with
  `key_id ‖ len‖schema.table.column ‖ len‖canonical(row_key)` as associated
  data, so a ciphertext moved between two rows of the same column stops
  authenticating. Acra has no equivalent; CipherStash reaches the same property
  by a different route (a key per value). See `plans/PLAN.md`, "Binding a value
  to its row".
- **Storage-free pseudonymization.** FF1 FPE is reversible with no token store
  at all, where Acra's reversible tokenization wants Redis or a table. One less
  stateful dependency for an embedded library.
- **`unsafe_code = "forbid"` workspace-wide** — a machine-checked claim a
  field-encryption library can actually make in a procurement conversation.
- **Fail-closed by construction**: startup refuses a missing config, a
  world-readable secret file, a plaintext `[vault] addr`, and a `control_dsn`
  without `sslmode=require`; crypto failures drop the session under every
  setting.
- **`on_unprotected` as a single, honest switch** over every case the rewrite
  cannot cover, enumerated rather than hand-waved.

## Where dbsec is behind

Deliberate (recorded in `plans/PLAN.md` scope decisions, not debt): MySQL, SQL
firewall, poison records, zones/per-client identity, an HTTP/gRPC crypto
service, SCRAM channel binding.

Actual gaps:

1. **No audit log.** The one dropped Acra feature worth reconsidering — both
   Acra and CipherStash ship a tamper-evident trail, and compliance stories
   usually require one. Nothing in `crates/` emits an audit record today.
2. **No metrics.** `tracing` only; no counters for sealed/opened values,
   `on_unprotected` hits, or key-cache misses.
3. **No key-rotation or re-encryption tooling.** Rotation of a deterministic key
   is documented in `plans/PLAN.md` as a migration the operator writes. Acra
   ships `acra-keys`; CipherStash handles it in the service.
4. **Equality search only.** No range or prefix matching. CipherStash's ORE and
   match indexes are the state of the art here; closing this is a large piece of
   work and is not currently planned.
5. **The library is not yet fully reusable** — the subject of the next section.

## The library goal, honestly assessed

The stated goal: `dbsec-core` should be an independent, reusable crate that
gives a Rust application the *same* protection the proxy gives, at code time
instead of at runtime, with minimal glue left to the caller.

**Status: partially met.** The README's framing — "a library does the work; the
binary is a thin tokio TCP wrapper around it" — no longer describes the split.
It is ~2,800 LOC of library against ~19,600 LOC of proxy, and several things a
library user cannot do without are inside the binary crate.

What already works. `dbsec-core` depends on no tokio, no sqlparser and no
`vaultrs`, and `transform::FieldTransform` is the right code-time abstraction:

```rust
fn seal(&self, plaintext: &[u8], row: Option<&RowKey>) -> Result<Vec<u8>, Error>;
fn open(&self, stored: &[u8], row: Option<&RowKey>) -> Result<Option<Vec<u8>>, Error>;
fn search_index(&self, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error>;
fn binds_row(&self) -> bool;
```

`EncryptTransform`, `FpeTransform`, `TokenTransform`, the envelope, the blind
index and `MaskSpec` are all there and all callable.

What a framework author must reimplement today, all of it security-critical:

| Missing from the library | Lives in | Cost of getting it wrong |
|---|---|---|
| Vault/OpenBao `KeySource` | `crates/proxy/src/vault.rs` | The library ships only `FileKeySource`, whose own docs say "dev/test". The README's headline "Vault/OpenBao-backed keys" is not a library feature. |
| Row-key canonicalization | `crates/proxy/src/rowkey.rs` | `0007`, `+7` and `7` must canonicalize identically, as must uuid case/brace/hyphen forms. Diverge and library-written values never open through the proxy. |
| PostgreSQL identifier folding | `crates/proxy/src/encrypt/` | It builds the `CellContext` string baked into every AAD. Drift silently breaks decryption. |
| Column policy model (`TransformKind`, column/table specs, `columns::build`) | `crates/proxy/src/{config,columns}.rs` | Carries the `schema.table.column` key-naming convention. Name a key wrong and cross-column relocation protection is silently lost — no error, ever. |
| A façade (`seal`/`open`/`search_term` by column) | nowhere | Every embedder hand-wires `Ciphers` + `Arc<dyn KeySource>` + `CellContext` + transform choice, which is exactly where the three failures above happen. |

And the split runs the wrong way in two places: `pgwire` (the PostgreSQL wire
codec, ~540 LOC) sits in the *library* where only the proxy uses it, while the
KMS integration sits in the *binary*. *(The wire codec moved out to
`dbsec-pgwire` in TASK-0192.04; row-key canonicalization and identifier folding
moved into `dbsec-core` in TASK-0192.01.)*

The refactor that closes this is tracked as TASK-0192 and its children
(TASK-0192.01 … TASK-0192.07).

## Reference points for the library API

If dbsec-core is to be as easy to adopt as the peers, these are the shapes worth
copying:

- **AWS Database Encryption SDK** — a table/attribute policy object plus
  `encrypt_record` / `decrypt_record`, with "beacons" (blind indexes) declared in
  the same policy rather than wired by hand. Closest to the façade dbsec needs.
- **CipherStash Protect** — encryption declared per model field, search handled
  by asking the library for the searchable term rather than by the caller
  building it. Also the proof that one Rust core can serve both an embedded SDK
  and a proxy without the proxy owning half the logic.
- **Acra's AcraWriter/AcraReader** — the split dbsec is aiming at (proxy and
  client-side library reaching the same stored format), which dbsec already has
  at the format level: values written by the library and by the proxy are the
  same envelope.
