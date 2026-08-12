---
id: TASK-0042
title: >-
  TEST-6: every error path in tls.rs is uncovered — bad certs, an empty CA
  bundle and an invalid hostname are never exercised
status: Done
assignee:
  - TASK-0056
created_date: '2026-08-11 19:36'
updated_date: '2026-08-12 16:28'
labels:
  - code-review-rust
  - tests
dependencies: []
modified_files:
  - crates/proxy/src/tls.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/tls.rs:171-182`

**What**: `tls.rs` has one test, and it covers a four-line pure function:

```rust
#[test]
fn upstream_host_strips_port_and_brackets() { ... }
```

Everything that can fail is untested. `TlsContext::from_config` (`tls.rs:41-80`) has five distinct error constructions, and `load_certs` / `load_key` (`tls.rs:95-109`) three more:

| Site | Condition |
|---|---|
| `tls.rs:50` | cert/key pair rejected by rustls (mismatched key, unsupported algorithm) |
| `tls.rs:60` | a CA entry rustls refuses to add to the root store |
| `tls.rs:71` | `hostname` not a valid `ServerName` |
| `tls.rs:97` | CA/cert file missing or unopenable |
| `tls.rs:99` | file present but not parseable PEM |
| `tls.rs:101` | file parses but contains zero certificates |
| `tls.rs:107` | key file missing or not a parseable private key |

The happy paths are covered indirectly by `session.rs`'s tests, which build a real `TlsContext` for both hops from an rcgen certificate — so the gap is specifically the failure side. [[task-0020]] covers the untested `vault.rs` and `resolve.rs`; `tls.rs` is a third module in the same crate with the same shape of gap and is not mentioned there.

**Why it matters**: These errors are the ones an operator actually meets, and they are all startup-time — a wrong path in `dbsec.toml`, a key that does not match its certificate, a CA bundle that is really a certificate, a `hostname` with a stray scheme or port. Their entire job is to produce a message that says which file and what is wrong with it, and that message is exactly what an untested `format!` arm gets wrong. The `certs.is_empty()` arm at `tls.rs:100-102` is the notable one: it exists specifically to convert a silent success (an empty root store, or a `ServerConfig` with no chain) into a refusal to start, and nothing verifies it still does.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 load_certs is tested for a missing file, an unparseable file and a syntactically valid file containing no certificates, asserting the Error::TlsConfig message names the path
- [x] #2 load_key is tested for a missing and an unparseable key file
- [x] #3 TlsContext::from_config is tested for a mismatched cert/key pair and an invalid upstream hostname
- [x] #4 The upstream hostname default is tested end to end — [tls.upstream] without hostname derives the name from the upstream address
<!-- AC:END -->
