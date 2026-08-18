---
id: TASK-0103
title: >-
  Auth passthrough breaks SCRAM channel binding and always refuses GSS
  encryption
status: Done
assignee:
  - TASK-0124
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:52'
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
- [x] #1 The channel-binding and GSSENC limitations are documented for operators
- [x] #2 A decision is recorded on whether channel_binding=require needs to be supported
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Documented in wave TASK-0124: README.md "Deploying the proxy" gains an operator-facing note on auth passthrough (channel_binding=prefer/disable, configure [tls.downstream] if a client may prefer GSSENC); plans/PLAN.md caveats record the decision — channel_binding=require is NOT supported and re-originating SCRAM is rejected, since it would make the proxy hold client credentials; per-hop verify-full TLS stands in for channel binding. crates/proxy/src/session.rs module docs and the GSSENC arm carry the same record at the code.
<!-- SECTION:NOTES:END -->
