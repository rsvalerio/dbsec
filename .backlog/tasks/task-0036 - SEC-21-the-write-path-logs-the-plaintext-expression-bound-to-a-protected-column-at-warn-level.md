---
id: TASK-0036
title: >-
  SEC-21: the write path logs the plaintext expression bound to a protected
  column at warn level
status: Done
assignee:
  - TASK-0049
created_date: '2026-08-11 19:34'
updated_date: '2026-08-12 16:25'
labels:
  - code-review-rust
  - security
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:501-507`, `crates/proxy/src/encrypt.rs:176-182`

**What**: When `seal_expr` meets an expression it cannot recognise as a literal, it logs the expression itself before passing it through:

```rust
let Some(plaintext) = literal_plaintext(expr, transform.wire()) else {
    tracing::warn!(
        expr = %expr,
        "unsupported expression for a protected column; passing through unencrypted"
    );
```

`expr` is the sqlparser AST node re-rendered as SQL, and it is by construction the value bound to a **protected** column — the exact data the column was configured to keep out of plaintext. `INSERT INTO users (email) VALUES (lower('alice@example.com'))` emits `expr=lower('alice@example.com')` into the log.

The same module logs the sqlparser error on an unparseable statement:

```rust
tracing::warn!(error = %e, "unparseable SQL; passing through unencrypted");
```

`ParserError::ParserError` messages embed the offending token (`Expected: ..., found: <token> at Line: N, Column: M`), so a statement that fails to parse mid-literal puts a fragment of that literal into the log too.

Both are `warn!`, which passes the default `EnvFilter` fallback of `"info"` (`crates/proxy/src/main.rs:63-67`), so this is on by default in every deployment.

**Why it matters**: The product's stated invariant is that a configured column is never at rest in plaintext. Logs are at rest: they are written to disk, shipped to a central aggregator, indexed, retained on a different schedule than the database, and readable by an operator population that deliberately does not have decryption keys. A proxy that encrypts `email` in Postgres and then writes the same address to stdout has moved the exposure rather than removed it, and moved it somewhere with weaker access control. This is also precisely the input an attacker can steer: any expression shape `literal_plaintext` does not recognise (a function call, a concatenation, a `DEFAULT`) triggers the log line, so plaintext exfiltration to the log is client-controllable. Related: [[task-0001]] covers the passthrough itself; this is about what the warning discloses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The unsupported-expression warning identifies the column and the expression *shape* (e.g. the AST discriminant or function name) without emitting any literal value
- [x] #2 The unparseable-SQL warning does not carry the sqlparser message verbatim, or the message is stripped of the offending token before logging
- [x] #3 Every remaining tracing call in the encrypt path is audited for payload-bearing fields, and the audit result is recorded in the module docs
- [x] #4 A test asserts that sealing a protected column's unsupported expression does not put the plaintext into the emitted event
<!-- AC:END -->
