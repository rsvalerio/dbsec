---
id: TASK-0252
title: >-
  SEC-5: Dsn derives Clone and is never zeroized, so the control password is
  held in three heap copies for the life of the process
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/resolve.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:71`

**What**:
```rust
#[derive(Clone, Deserialize)]
pub struct Dsn(String);
```
`Config::validate` clones it into `ProtectedConfig.control_dsn` (config.rs:632), `serve` clones it again into `Refresher.dsn` (main.rs:643/651), and the original stays in `config.control_dsn`; none of the three is `Zeroizing`. The sibling secrets (`dbsec_vault::Secret`, the keyfile buffer, the raw config text at config.rs:536) are all zeroized on drop. TASK-0047 added redaction only; TASK-0205 is the same held-in-N-places shape for the Vault token.

**Why it matters**: the process is hardened against core dumps (hardening.rs) precisely because it holds secrets; the control password is the one secret still sitting un-wiped in three allocations.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Dsn wraps Zeroizing<String> (or dbsec_vault::Secret) and drops Clone, or the resolved DSN is moved into exactly one owner (Refresher) and Config.control_dsn is taken after validation
- [ ] #2 as_str() remains the only accessor to the raw string
<!-- AC:END -->
