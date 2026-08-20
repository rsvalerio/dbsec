# dbsec-core

Field-level encryption, pseudonymization and masking for PostgreSQL columns,
as a Rust library. The [`dbsec`](https://github.com/rsvalerio/dbsec) proxy is
built on this crate and writes the same bytes, so one table can serve an
application that links the library and clients that go through the proxy.

- AES-256-GCM envelopes bound to their **column** and, opt-in, to their **row**
  — a ciphertext moved elsewhere stops authenticating.
- Equality search over ciphertext through a blind index.
- FF1 format-preserving pseudonymization (storage-free) and irreversible HMAC
  tokens.
- Read-path masking.
- Keys behind a `KeySource` trait you implement over your KMS — or take
  [`dbsec-vault`](https://crates.io/crates/dbsec-vault) for HashiCorp Vault /
  OpenBao; `unsafe_code = "forbid"`.

```toml
[dependencies]
dbsec-core = { version = "0.5", features = ["derive"] }
```

```rust
use dbsec_core::{protector::Protector, Protect};

#[derive(Protect, Clone)]
#[dbsec(table = "users", row_key = "id", sealed_derive(sqlx::FromRow))]
struct User {
    id: i64,
    #[dbsec(searchable)]               email: String,
    #[dbsec(fpe, mask(keep_last = 4))] phone: String,
    display_name: String,
}

let p = Protector::new(User::policy(), keys)?;   // keys: Arc<dyn KeySource>
let sealed = user.seal(&p)?;                      // UserSealed: email Vec<u8>, phone String
// INSERT ... VALUES ($1, $2, $3, $4) binding sealed.id, &sealed.email, ...
// SELECT ... WHERE substring(email from 1 for 32) = $1  with User::email_term(&p, b"a@b.io")?
let user = row.open(&p)?;                         // row: UserSealed, e.g. via sqlx::query_as
let shown = user.masked(&p)?;                     // phone = "********4567"
```

Without the derive, `Protector` offers the same by column name: `seal`, `open`,
`search_term`, `mask`. The crate docs carry a complete runnable example, the
stored-format table, and what the library does *not* protect (equality
leakage of deterministic transforms, masking only where it is called).

## Features

| Feature | Adds |
|---|---|
| *(none)* | The crypto, the policy model and `Protector`. No serde, no TOML, no proc macro. |
| `serde` | `Deserialize` on `MaskSpec` and the policy types, so a policy shared with the proxy can be read from its TOML. |
| `keyfile` | `FileKeySource`, a TOML keyfile for development and tests. |
| `derive` | `#[derive(Protect)]`. |

## Compatibility

The stable surface is the stored format — envelope layouts, AAD construction,
blind-index / FPE / token derivations, the `schema.table.column` key-naming
convention. A change to any of those is a major version. MSRV is declared in
`Cargo.toml` and checked in CI.

License: Apache-2.0.
