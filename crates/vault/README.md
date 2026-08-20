# dbsec-vault

A [`dbsec-core`](https://crates.io/crates/dbsec-core) `KeySource` backed by
HashiCorp Vault or OpenBao: DEKs are minted through Transit and stored wrapped
in KV v2; deterministic keys (blind index, FPE, tokens) live one-per-name in KV
v2, created with check-and-set so concurrent minters cannot overwrite each
other, and a failed read is never taken as "no key yet".

```rust
let setup = VaultConfig { addr: "https://bao.internal:8200".into(), token: Some(token), ..VaultConfig::default() }
    .resolve()?;                                            // validates the address, resolves the token
let keys = Arc::new(VaultKeySource::connect(&setup).await?); // one fresh DEK per process
let protector = Protector::new(policy, keys.clone())?;
tokio::spawn(keys.clone().token_watch(shutdown));           // keeps a TTL'd token renewed
```

Needs a multi-thread tokio runtime: `KeySource` is synchronous, and a cache
miss bridges to the async client with `block_in_place`, bounded by
`timeout_secs`. Caches are grow-only by design — restart after a Vault-side
revocation or rotation. See the crate docs for the storage layout and the
operational notes.

License: Apache-2.0.
