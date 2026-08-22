# dbsec-derive

`#[derive(Protect)]` for [`dbsec-core`](https://crates.io/crates/dbsec-core):
declare the field-encryption policy on the struct that holds the data, and get
seal / open / search / mask for the whole record.

Use it through `dbsec-core`'s `derive` feature rather than depending on this
crate directly:

```toml
[dependencies]
dbsec-core = { version = "0.6", features = ["derive"] }
```

```rust
#[derive(Protect, Clone)]
#[dbsec(table = "users", row_key = "id", sealed_derive(sqlx::FromRow))]
struct User {
    id: i64,
    #[dbsec(searchable)]               email: String,
    #[dbsec(fpe, mask(keep_last = 4))] phone: String,
    display_name: String,
}
```

The macro generates `UserSealed` (the same record in its stored form),
`User::policy()`, `seal`, `open` / `open_lenient`, an `email_term` per
searchable field, and `masked`. Every operation goes through the `Protector`,
so the derive introduces no second convention — and a struct that disagrees
with the protector's policy on a column's stored form is refused at `seal`
rather than silently mis-sealed.

See the [`dbsec-core` docs](https://docs.rs/dbsec-core) for the attribute
grammar and the threat model.

License: Apache-2.0.
