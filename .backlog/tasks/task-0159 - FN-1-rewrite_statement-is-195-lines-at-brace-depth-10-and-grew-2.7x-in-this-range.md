---
id: TASK-0159
title: >-
  FN-1: rewrite_statement is 195 lines at brace depth 10 and grew 2.7x in this
  range
status: Done
assignee:
  - TASK-0180
created_date: '2026-08-19 08:30'
updated_date: '2026-08-19 10:22'
labels:
  - code-review-rust
  - complexity
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:787`

**What**: `rewrite_statement` was 73 lines at `71935b1`; it is now 195 lines with maximum brace
depth 10 (`match` -> `Update` arm -> `if let TableFactor::Table` -> `if let Some(columns)` ->
`match spec` -> `Some(spec)` -> `match found` -> `None` arm). Every other statement kind in the
same match already delegates (`Insert` -> `rewrite_insert`, `Query` -> `rewrite_query`), so
`Update`, `Delete` and `Copy` are outliers against the module's own pattern. The `Copy` arm
carries 40 lines of comment inline in a match arm.

**Why it matters**: this is the single function that decides, per statement kind, whether a
write is sealed or relayed in plaintext, and it is now the largest and most deeply nested
function in the module the split was meant to make reviewable. The row-key logic buried at
depth 8 is exactly the code path with no test — depth is why it is easy to miss.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 rewrite_statement is a dispatch match <= 50 lines; Update/Delete/Copy become their own fns alongside rewrite_insert
- [x] #2 No extracted function exceeds nesting depth 4; the spec/found pyramid becomes let-else guards or a named helper
- [x] #3 Behaviour is unchanged and the existing tests pass without edits
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
rewrite_statement is now a 16-line dispatch match; Update/Delete/Copy/Merge/Prepare each became their own fn alongside rewrite_insert (rewrite_update, rewrite_delete, rewrite_copy + refuse_copy_table/rewrite_copy_query, refuse_merge, refuse_prepare), plus free helpers delete_tables/delete_tables_mut. The 40-line COPY comment is now the doc of rewrite_copy_query. AC#2 substitution: the "spec/found pyramid" the task describes no longer exists — earlier waves moved the row-key logic into seal.rs update_row/AssignmentScope. The equivalent remaining pyramid (if let TableFactor::Table -> if let Some(columns)) became the let-else helper update_columns, so no extracted fn nests deeper than 3. Behaviour unchanged: all 295+ existing tests pass without edits. rewrite_update takes &mut Statement rather than its four fields because clippy::too_many_arguments (deny) rejects the 6-argument form.
<!-- SECTION:NOTES:END -->
