---
id: TASK-0018
title: >-
  READ-5: a rewritten Query is re-serialized from the AST, silently replacing
  the client's SQL text
status: To Do
assignee:
  - TASK-0049
created_date: '2026-08-11 19:14'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - correctness
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:184-193`

**What**: When any statement in a Query changes, the *whole* text is discarded and rebuilt from sqlparser's `Display`:

```rust
if changed {
    outcome.rewritten =
        Some(statements.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "));
}
```

Two things happen here that the surrounding code does not acknowledge:

1. **Every statement is re-rendered, not just the changed one.** A multi-statement simple-protocol batch where statement 3 touches a protected column sends statements 1, 2, 4, … back through `Display` too. Anything sqlparser parses but does not render byte-identically is quietly altered on a statement the proxy had no reason to touch.
2. **The join is `"; "` regardless of the original separators**, and comments, whitespace, string-literal quoting style, and dollar-quoting are all lost — `Display` emits sqlparser's canonical form, not the input.

The crate already treats the parser as untrusted in one direction: unparseable SQL passes through with a warning (line 179). But "sqlparser parsed it" is being taken as "sqlparser will render it back equivalently", and those are different claims. A round-trip divergence in a construct the proxy does not model — a CTE, a window frame, an operator sqlparser normalizes, a dollar-quoted body — changes the statement the database executes with no warning at all.

**Why it matters**: This is the one path where the proxy rewrites SQL the client wrote and cannot detect that it got it wrong. Unlike the passthrough cases in [[task-0001]], which fail loudly into a log line, a bad round-trip produces a syntactically valid statement with different semantics, executed against production data. The narrow mitigation is to stop re-rendering statements that did not change; the broader one is a round-trip check (re-parse the rendered text and compare ASTs) before sending, failing the session on divergence rather than guessing.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Statements that were not modified are relayed as their original text rather than re-rendered from the AST
- [ ] #2 The rewritten text is validated before it goes on the wire — re-parsed and compared, or another check that catches a Display round-trip divergence — and a divergence fails the session
- [ ] #3 The reliance on sqlparser's Display fidelity is documented in the module docs alongside the existing passthrough caveats
- [ ] #4 A test covers a multi-statement Query where only one statement is protected, asserting the others are byte-identical on the wire
<!-- AC:END -->
