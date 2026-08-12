---
id: TASK-0010
title: >-
  SEC-5: the Vault token is a plain String on a Debug-deriving config, never
  zeroized
status: Done
assignee:
  - TASK-0053
created_date: '2026-08-11 19:12'
updated_date: '2026-08-12 16:51'
labels:
  - code-review-rust
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/vault.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:78-114`

**What**: `VaultConfig` holds the Vault/OpenBao token as `token: Option<String>` and derives `Debug` and `Clone`:

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub addr: String,
    pub token: Option<String>,
    ...
}
```

`Config` (line 10) also derives `Debug` and owns a `VaultConfig`, so any `{:?}` of the config — a debug log, an `expect` message, a panic payload, a future `tracing::debug!(?config, ...)` — prints the token verbatim. Beyond the derive:

- `VaultConfig::token()` (line 102) returns an owned `String`; the `token_file` branch reads the file into a `String`, `.trim()`s it, and returns a fresh copy. Neither the file contents nor the returned token is zeroized.
- `VaultKeySource::connect` (`crates/proxy/src/vault.rs:47-90`) clones the whole `VaultConfig` into the struct it keeps for the process lifetime, so a second copy of the token stays resident.
- `Config::validate` (line 218) calls `vault.token()?` purely to check the token is resolvable, producing and dropping yet another copy.

Contrast the DEK handling in the same crate, which does this correctly — `Key` is `Zeroizing`, and `decode_key_b64`/`decode_key_hex` (`vault.rs:170-189`) explicitly zeroize their intermediate buffers.

**Why it matters**: The Vault token is the credential that unwraps every DEK and reads every deterministic index key. It is the highest-value secret the process holds and it is the only one held in plain, cloned, `Debug`-printable `String`s. A single `?config` in a future log line, or a core dump, exposes it. This is the one type in the crate where the existing `zeroize` dependency is not applied.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The token field is a secret-carrying type whose Debug impl redacts the value (manual impl, secrecy::SecretString, or a newtype over Zeroizing<String>)
- [x] #2 The token_file read path zeroizes the file contents and any intermediate String
- [x] #3 Config::validate no longer materializes a throwaway copy of the token just to check resolvability, or the copy it makes is zeroized
- [x] #4 A test asserts that formatting Config/VaultConfig with {:?} does not contain the token value
<!-- AC:END -->
