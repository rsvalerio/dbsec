---
id: TASK-0132
title: >-
  A parenthesized (nested) join hides its protected tables from the predicate
  scope
status: To Do
assignee:
  - TASK-0139
created_date: '2026-08-17 20:35'
updated_date: '2026-08-18 09:59'
labels:
  - code-review-rust
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs` (`QueryRewriter::scope`)

**What**: `scope()` walks a `TableWithJoins`' relation and its joins' relations and keeps
only `TableFactor::Table`. sqlparser parses a parenthesized join —
`FROM (users JOIN orders ON orders.id = users.id)` — as a single
`TableFactor::NestedJoin { table_with_joins, .. }`, which the loop skips. Every protected
table inside the parentheses is therefore invisible to the scope, so a predicate over one
resolves to nothing: it is neither rewritten nor routed through `on_unprotected`.

Verified against the current source with a throwaway test: under
`on_unprotected = "reject"`, both

```sql
SELECT 1 FROM (users JOIN orders ON orders.id = users.id) WHERE users.email = 'a@b.io'
SELECT 1 FROM (users JOIN orders ON orders.id = users.id) WHERE users.email LIKE 'a%'
```

are relayed verbatim (`FrameAction::Relay`) — no blind-index rewrite on the first, no
ErrorResponse on the second.

**Why it matters**: the same silent-no-rows failure the module exists to prevent, reached
by adding one pair of parentheses. The equality matches nothing (reads as "no such user")
and the unrewritable shape is not refused even in fail-closed mode, so `reject` does not
actually fail closed for this syntax. Unlike the ambiguous-column and `UPDATE ... FROM`
gaps closed in wave 16, this one applies to every statement kind that owns a FROM clause.

**Fix shape**: make `scope()` recurse into `TableFactor::NestedJoin`, and give the same
treatment to the two other walks that iterate FROM factors —
`rewrite_select`'s join-condition pass and `QueryRewriter::rewrite_derived_tables` — so a
join constraint or derived table inside the parentheses is rewritten too. Blast radius is
wider than a one-line guard (it changes which relations are in scope for every statement
kind), so it wants its own tests rather than riding another wave's diff.

**Origin**: discovered during TASK-0121 (wave 16) while fixing TASK-0086.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A searchable equality over a protected table inside a parenthesized join is rewritten to blind-index form
- [ ] #2 An unrewritable predicate over such a table routes through the on_unprotected gate instead of being relayed
- [ ] #3 Tests cover both, including a join constraint and a derived table nested inside the parentheses
<!-- AC:END -->
