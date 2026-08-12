---
id: TASK-0048
title: >-
  SEC-8: install_crypto_provider discards the install result, so the proxy may
  run TLS on a provider it did not choose
status: To Do
assignee:
  - TASK-0056
created_date: '2026-08-11 21:05'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - tls
dependencies: []
modified_files:
  - crates/proxy/src/tls.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/tls.rs:33-38`

**What**: The process-wide rustls provider is installed on a best-effort basis and the outcome is thrown away:

```rust
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
```

`install_default` returns `Result<(), Arc<CryptoProvider>>` and fails when a default is already installed, handing back the provider that won. The `let _ =` drops that, and the function returns `()` either way — so `TlsContext::from_config` cannot tell whether the proxy's TLS is running on `aws-lc-rs` or on something else.

The comment two lines above explains exactly why this is not theoretical: "The dependency graph enables both `aws-lc-rs` (our rustls) and `ring` (vaultrs via reqwest), so rustls cannot pick a default automatically." Both providers are linked in. Whichever installs first wins, and the `Once` only guarantees this call site runs once — it says nothing about reqwest's lazy initialization having already run. With `[vault]` configured, `VaultKeySource::connect` builds a `VaultClient` during startup, on a path that can reach reqwest's TLS setup.

**Why it matters**: The provider decides the cipher suites, key exchange groups and signature algorithms for both TLS hops — the client-facing listener and the verify-full connection to the real Postgres. Which one the proxy actually got is currently unobservable: not asserted, not logged, not testable. A crate this security-focused should not have its TLS primitives selected by dependency-initialization order, and should certainly not be unable to report which selection it ended up with.

The second-order problem is that this silently defeats any future policy. Restricting cipher suites or requiring a FIPS-validated provider is done by building a customised `CryptoProvider` and installing it — and that install would fail the same silent way, leaving the proxy on the default policy while the config claims otherwise.

The fix is small: keep the `Result`, and either fail startup when the installed default is not the intended provider, or at minimum log at warn which provider is in force. `install_crypto_provider` returning `Result<(), Error>` fits the existing `TlsContext::from_config` signature, which is already fallible and already returns `Error::TlsConfig`.

Related: [[task-0042]] covers the missing error-path coverage in the rest of this module.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 install_crypto_provider inspects the install_default result instead of discarding it
- [ ] #2 A provider other than the intended one being already installed is either a startup error or a warn-level log naming the provider actually in force
- [ ] #3 install_crypto_provider's return type lets TlsContext::from_config propagate the failure through the existing Error::TlsConfig path
- [ ] #4 A test asserts the outcome is observable — a second install attempt with a different provider is reported rather than silently ignored
<!-- AC:END -->
