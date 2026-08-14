---
id: TASK-0116
title: >-
  A dollar-quote tag containing a digit is mis-lexed, so the whole Query loses
  its source text and every statement is re-rendered
status: Triage
assignee: []
created_date: '2026-08-14 16:49'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Rule**: READ-5 (make invariants explicit), SEC-37 (the hand-rolled lexer over untrusted SQL is neither fuzzed nor property-tested)

**File**: `crates/proxy/src/encrypt.rs:1661` (`skip_dollar_quoted`), `crates/proxy/src/encrypt.rs:1600` (`statement_ranges`), `crates/proxy/src/encrypt.rs:1554` (`reassemble`)

**What**: `skip_dollar_quoted` accepts a tag only when every byte satisfies `is_ident_byte(b) && !b.is_ascii_digit()`. PostgreSQL's rule is different: a dollar-quote tag follows identifier rules, so digits are legal after the first character — `$tag1$ … $tag1$` is a valid dollar-quoted string.

The rejection is not a clean bail-out. `skip_dollar_quoted` returns `Some(start + 1)`, so the scan walks *into* the body and re-interprets whatever it finds there as SQL. Two outcomes, both wrong:

1. `SELECT $tag1$a;b$tag1$` — `statement_ranges` returns `Some`, having split the statement at the `;` **inside the quoted body**. sqlparser sees one statement. Whether that mismatch is caught depends only on whether the counts happen to differ.
2. `INSERT INTO users (id, email) VALUES (1, 'a@b.c'); SELECT $tag1$hello$tag1$ /* keep me */` — the scan reaches the closing `$hello$`-looking run, treats it as an *opening* tag, finds no match, and `statement_ranges` returns `None`.

Case 2 confirmed by test: the rewritten Query comes back as

```
INSERT INTO users (id, email) VALUES (1, '\x4442533101…'); SELECT $tag1$hello$tag1$
```

— the `/* keep me */` comment is gone, and the warn line *"could not map statements back to their source text; re-rendering all of them"* fires.

**Why it matters**: `reassemble`'s whole purpose is that only statements the rewrite actually changed are re-rendered, because sqlparser's `Display` is not a contractual round-trip. Falling back re-renders **every** statement in the Query through `render_validated`, so a statement the proxy had no reason to touch can now fail its own round-trip check and raise `Error::RewriteDiverged`, which is fatal to the session. Comments, whitespace and quoting style are lost for the whole batch. And case 1 leaves `statement_ranges` producing ranges that do not correspond to the parsed statements — the `ranges.len() == statements.len()` guard is a count check, not an alignment check, so a coincidental match splices rendered SQL at the wrong offsets with nothing re-parsing the assembled result.

More broadly: `statement_ranges` / `skip_quoted` / `skip_dollar_quoted` / `skip_block_comment` are a second, hand-written SQL lexer running on client-controlled text, and it is only covered by hand-picked unit tests. It is the one component whose disagreement with sqlparser is not detected by `render_validated`.

<!-- scan confidence: both cases reproduced by test -->

**Suggested direction**: match PostgreSQL's tag rule (first byte an identifier start, remaining bytes identifier characters including digits); make an unrecognised `$` sequence advance without entering the body; and add a proptest that `statement_ranges`, when it returns `Some`, yields ranges whose text re-parses to the same statement list sqlparser produced from the whole input.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 skip_dollar_quoted accepts a tag whose non-leading characters include digits, matching PostgreSQL identifier rules
- [ ] #2 A Query mixing a rewritten INSERT with a $tag1$…$tag1$ statement preserves the untouched statement's source text, comments included
- [ ] #3 A ; inside a dollar-quoted body with a digit-bearing tag does not split the statement
- [ ] #4 A property test asserts statement_ranges' ranges re-parse to the same statement list sqlparser produces for the whole text
<!-- AC:END -->
