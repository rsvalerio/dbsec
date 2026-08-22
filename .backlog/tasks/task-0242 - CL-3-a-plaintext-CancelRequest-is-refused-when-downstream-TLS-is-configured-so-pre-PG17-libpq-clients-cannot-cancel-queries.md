---
id: TASK-0242
title: >-
  CL-3: a plaintext CancelRequest is refused when downstream TLS is configured,
  so pre-PG17 libpq clients cannot cancel queries
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - cognitive-load
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:407`

**What**:
```rust
Startup::Cancel | Startup::Protocol(_) => {
    if tls.acceptor.is_some() && client.is_plain() {
        return Err(Error::PlaintextRejected);
    }
```
CancelRequest is treated exactly like a startup packet for the plaintext check. A cancel arrives on a new connection, and libpq's `PQcancel`/`PQrequestCancel` (everything before PostgreSQL 17's `PQcancelBlocking`) send it raw with no SSLRequest; PostgreSQL itself accepts a plaintext CancelRequest regardless of `hostssl` rules. `pgwire/src/lib.rs:86` documents the variant as "forward upstream, then both sides close" with no TLS caveat.

**Why it matters**: with `[tls.downstream]` set, psql Ctrl-C, JDBC `Statement.cancel()`, psycopg `cancel()` are silently dropped at the proxy: a `PlaintextRejected` warning, client EOF, backend query keeps running. The packet carries only the already-relayed 32-bit cancel key, so letting it through exposes nothing the proxy protects.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Startup::Cancel is forwarded upstream whether or not the client hop is TLS (or the refusal is a documented deliberate choice with a README note on PG<17 cancel)
- [ ] #2 A test sends a plaintext CancelRequest to a proxy configured with [tls.downstream] and asserts the 16-byte packet reaches the fake upstream
<!-- AC:END -->
