---
id: TASK-0046
title: >-
  ASYNC-6: one transient accept() error terminates the whole proxy instead of
  shedding load
status: To Do
assignee:
  - TASK-0051
created_date: '2026-08-11 21:04'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - async
  - availability
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:144-146`

**What**: The accept loop propagates every `accept()` error out of `serve()`:

```rust
accepted = listener.accept() => {
    let (socket, peer) = accepted?;
    ...
}
```

`?` here returns from `serve()`, `main` logs "proxy exited with error", and the process exits `ExitCode::FAILURE`. But most of what `accept()` returns is transient and per-connection, not fatal to the listener:

- `EMFILE` / `ENFILE` — the process or system is out of file descriptors
- `ECONNABORTED` — the peer went away between the SYN and the accept
- `ENOBUFS` / `ENOMEM` — kernel buffer pressure

None of these say anything about the listening socket, which is still bound and still valid. The conventional shape is to log-and-continue on transient errors (with a short backoff for the descriptor-exhaustion cases, so the loop does not spin at 100% CPU re-failing), and to exit only on errors that genuinely invalidate the listener.

**Why it matters**: This turns a load spike into an outage that does not self-heal. `EMFILE` is the expected outcome of the exhaustion path already tracked in [[task-0009]]: that task notes each session costs two sockets plus an upstream backend connection with no admission control, so a connection burst walks the process straight into the descriptor limit. What happens at that moment is decided here — and what happens is that the proxy **exits**, dropping every healthy in-flight session with it, rather than refusing the one connection it cannot serve and continuing.

The failure is also worse than losing the proxy, because the proxy is the only thing enforcing encryption. A dbsec that is down is an application that either fails hard or, if anything is configured to fall back to the database directly, writes plaintext. An availability bug in this position has a confidentiality tail.

The two findings are complementary and neither subsumes the other: [[task-0009]] stops the process from reaching exhaustion, this one stops exhaustion from being fatal when it is reached anyway (an `ulimit` set outside the proxy's control, a descriptor leak elsewhere, a neighbouring process on the same host).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Transient accept() errors (EMFILE, ENFILE, ECONNABORTED, ENOBUFS, ENOMEM) are logged and the accept loop continues instead of returning from serve()
- [ ] #2 Descriptor-exhaustion errors back off briefly before the next accept so the loop cannot spin hot re-failing
- [ ] #3 Errors that genuinely invalidate the listener still terminate serve() with a non-zero exit, and the distinction is documented at the call site
- [ ] #4 A test drives the accept loop past a simulated transient accept error and asserts a subsequent connection is still served
<!-- AC:END -->
