---
id: TASK-0103
title: >-
  Auth passthrough breaks SCRAM channel binding and always refuses GSS
  encryption
status: To Do
assignee:
  - TASK-0124
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:04'
labels:
  - security-review
  - protocol
  - tls
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs` (auth passthrough architecture), `:211` (GSSENC refused).

**What**: the proxy never terminates or re-originates authentication — it relays SASL frames verbatim between two independent TLS sessions. `SCRAM-SHA-256-PLUS` binds to TLS endpoint data, which differs per hop, so when both hops are TLS the server advertises `-PLUS`, TLS-aware clients select it, and authentication fails; `channel_binding=require` clients cannot connect at all. Separately, a client preferring GSSAPI encryption is answered `N` and falls back — to plaintext when downstream TLS is unconfigured. Verified by architecture trace; SCRAM facet is SPECULATIVE (not driven through a live handshake).

**Why it matters**: deployments lose the MITM-detection that channel binding provides (and `channel_binding=require` clients break), and GSS-preferring clients get a quiet transport downgrade relative to talking to PostgreSQL directly. Inherent to a TLS-terminating relay, but currently undocumented.

**Fix shape**: document the channel-binding and GSSENC limitations; consider re-originating SCRAM or proxying channel-binding data if `-PLUS` support is needed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The channel-binding and GSSENC limitations are documented for operators
- [ ] #2 A decision is recorded on whether channel_binding=require needs to be supported
<!-- AC:END -->
