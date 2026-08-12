---
id: TASK-0049
title: code-review-plan-wave0
status: In Progress
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-12 16:25'
labels:
  - code-review-wave
dependencies:
  - TASK-0001
  - TASK-0002
  - TASK-0017
  - TASK-0018
  - TASK-0036
  - TASK-0037
  - TASK-0045
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/config.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Write path fail-open coverage: every site where a write to a protected column is silently or near-silently left in plaintext, plus the strict/fail-closed switch they all need and the SQL-text fidelity of the rewrite that carries them.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0050 wave1 (crates/proxy/src/encrypt.rs); TASK-0052 wave3, TASK-0053 wave4, TASK-0056 wave7 (crates/proxy/src/config.rs)

Branch: code-review/TASK-0049

Merged onto main (4 commits, fast-forward). Six of seven members are Done.

Left open: TASK-0037, whose AC #2 still wants `= ANY($1)` — the bound-array form — rewritten
to a blind-index match. The safe half shipped (it is now a warn/refuse site rather than a
silent empty result); the rewrite needs a Bind-time array codec and is filed as TASK-0062
(Triage). The wave parent stays In Progress until that lands.

Also fixed in-wave, found while writing the COPY coverage: sqlparser cannot parse
`COPY ... FROM STDIN` without a terminator (it tries to consume the TSV payload, which on
the wire arrives later as CopyData frames), so the COPY site was unreachable and COPY was
being reported as unparseable SQL. `encrypt::parse_sql` now retries once with a `;`.
<!-- SECTION:NOTES:END -->
