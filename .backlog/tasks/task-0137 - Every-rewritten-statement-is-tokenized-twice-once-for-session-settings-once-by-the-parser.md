---
id: TASK-0137
title: >-
  Every rewritten statement is tokenized twice: once for session settings, once
  by the parser
status: Done
assignee:
  - TASK-0140
created_date: '2026-08-18 09:37'
updated_date: '2026-08-18 14:27'
labels:
  - code-review-rust
  - performance
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs` (`settings_moved`, `rewrite_sql`)

**What**: TASK-0122 added a `sqlparser::tokenizer::Tokenizer` pass over every client SQL
text so that `SET SCHEMA` and `set_config('search_path', …)` — neither of which the AST
can show — are still seen. `parse_sql` then tokenizes the same text again from scratch,
and `settings_moved` additionally collects the tokens into a `Vec<&Token>` and allocates
a lowercased `String` per candidate word via `keyword`.

**Why it matters**: lexing is on the hot path of every rewritten Query and Parse frame,
and it is now paid twice per statement plus two vectors of borrows. Correctness came
first — the token stream is the only place all four spellings are visible — but the
duplicate pass is avoidable.

**Fix shape**: tokenize once and hand the tokens to the parser
(`sqlparser::parser::Parser::with_tokens` / `new(...).with_tokens(...)`) instead of
letting it re-tokenize, or gate the settings scan behind a cheap ASCII-case-insensitive
`set` / `set_config` substring probe so texts that cannot move a setting skip it. Either
way keep `settings_moved`'s per-statement grouping, which is what stops a `SET` at the
end of a batch retroactively unsealing the writes in front of it.

**Origin**: discovered during TASK-0122 while fixing TASK-0091.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A rewritten statement is tokenized once, or the settings scan is skipped for text that cannot move a setting
- [x] #2 The per-statement grouping of setting moves is preserved, with its regression test still passing
<!-- AC:END -->
