---
id: TASK-0063
title: 'SEC-29: the downstream TLS private key is read with no permission check'
status: Done
assignee:
  - TASK-0067
created_date: '2026-08-12 16:50'
updated_date: '2026-08-12 19:11'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/tls.rs
  - crates/proxy/tests/common/mod.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs`, `crates/proxy/src/tls.rs`

**What**: TASK-0053 (wave4) added `check_secret_file_mode` in `crates/proxy/src/config.rs` and wired it into `Config::validate` for the two files TASK-0019 named: `keys_file` and `[vault] token_file`. Both are now refused when group- or world-readable.

`[tls.downstream] key` — the PEM private key the proxy presents to clients — is the third secret file in the config and was left out, because no wave-4 member covered it and the reject-vs-warn call is genuinely different for it.

**Why it matters**: A world-readable TLS private key lets any local user impersonate the proxy to its clients and decrypt a passively captured session that did not negotiate forward secrecy. It is the same SEC-29 rule and the helper to enforce it already exists — one call in `Config::validate` plus a mode on the `[tls.downstream]` fixture in `crates/proxy/tests/common/mod.rs`, which writes `key.pem` through `fs::write` and so inherits the umask.

Worth deciding rather than mechanically extending: unlike a master keyfile, a TLS key is sometimes deliberately group-readable so a service group can read it, so this may want `warn` where `keys_file` gets `reject`. That decision is why wave4 filed it instead of absorbing it.

**Origin**: discovered during TASK-0053 while fixing TASK-0019.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 [tls.downstream] key is refused or warned about when group- or world-readable on unix, using the existing check_secret_file_mode helper
- [x] #2 The reject-vs-warn choice is documented alongside the check
- [x] #3 A test covers the chosen behaviour, and the e2e fixture writes key.pem with a mode that satisfies it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Resolved reject-vs-warn as **reject**, matching check_secret_file_mode for keys_file/token_file. Reasoning (also recorded in the helper doc in crates/proxy/src/config.rs): the proxy is the only reader of its own downstream key, so a group-readable copy buys a service group nothing while handing every local member the ability to impersonate the proxy and decrypt captured non-PFS sessions; a deployment that must share the key gives the other service its own 0600 copy. A startup warning also scrolls past while the exposure is permanent. Implementation: one check_secret_file_mode call in Config::validate, run whether or not any [[column]] is configured (the key is presented in plain-relay mode too); the certificate beside it is public and deliberately unchecked. Tests: config::tests::the_downstream_tls_key_must_be_readable_only_by_its_owner covers 0600 accepted (with a 0644 cert, pinning that the cert is not checked) and 0640/0644 refused with the mode named. crates/proxy/tests/common/mod.rs now chmods key.pem to 0600. tls.rs load_key documents that the permission policy lives at config-validation time and is not restated there.
<!-- SECTION:NOTES:END -->
