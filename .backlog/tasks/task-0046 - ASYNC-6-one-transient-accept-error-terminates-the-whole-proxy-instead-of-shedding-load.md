---
id: TASK-0046
title: >-
  ASYNC-6: one transient accept() error terminates the whole proxy instead of
  shedding load
status: Done
assignee:
  - TASK-0051
created_date: '2026-08-11 21:04'
updated_date: '2026-08-12 10:46'
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
- [x] #1 Transient accept() errors (EMFILE, ENFILE, ECONNABORTED, ENOBUFS, ENOMEM) are logged and the accept loop continues instead of returning from serve()
- [x] #2 Descriptor-exhaustion errors back off briefly before the next accept so the loop cannot spin hot re-failing
- [x] #3 Errors that genuinely invalidate the listener still terminate serve() with a non-zero exit, and the distinction is documented at the call site
- [x] #4 A test drives the accept loop past a simulated transient accept error and asserts a subsequent connection is still served
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0051 (branch code-review/TASK-0051).

- AC #1: `main::accept_loop` no longer `?`s the accept result. Transient errors are logged and the loop continues.
- AC #2: `is_per_connection_accept_error` (ECONNABORTED / ECONNRESET / ECONNREFUSED / EINTR) retries immediately; everything else — which is where EMFILE/ENFILE/ENOBUFS/ENOMEM land — sleeps `ACCEPT_BACKOFF` (100ms) first, so the loop cannot spin hot re-failing.
- AC #3: `is_fatal_accept_error` (EINVAL → `ErrorKind::InvalidInput`, EOPNOTSUPP → `ErrorKind::Unsupported`) returns from `serve` with a non-zero exit, and `MAX_CONSECUTIVE_ACCEPT_ERRORS` (32 consecutive failures with no successful accept in between) is the backstop for a broken listener whose errno has no stable `ErrorKind`. The whole distinction is documented on `is_fatal_accept_error`, at the call site.

  Note on classification: the exhaustion errnos (EMFILE 24, ENFILE 23, ENOBUFS, ENOMEM) have no stable `ErrorKind` and their numeric values differ across unix platforms, so the split is written as "fatal is a small allowlist, everything else sheds load", with the consecutive-failure ceiling rather than a hardcoded errno table. This is the hyper/tokio-conventional shape and keeps the code portable.
- AC #4: `accept_loop` is generic over a new private `Accept` trait implemented for `TcpListener`, which lets `main::tests::accept_loop_survives_a_transient_accept_error` inject a simulated EMFILE (`Error::from_raw_os_error(24)`) on the first accept and then assert a subsequent connection is still served end to end. `accept_loop_gives_up_when_the_listener_is_invalid` and `accept_error_classification_matches_the_documented_split` cover the fatal side.
<!-- SECTION:NOTES:END -->
