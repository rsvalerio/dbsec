---
id: TASK-0151
title: >-
  SEC-11: row_key_in_predicate matches an unqualified name, so UPDATE ... FROM
  binds the joined relation's key
status: Triage
assignee: []
created_date: '2026-08-19 08:28'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/scope.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:52`

**What**: the `Eq` arm compares `column_name(e)` against the row key name, and `column_name`
reduces a `CompoundIdentifier` to its **last** ident, discarding the qualifier. `Statement::Update`
carries a `from`, so `UPDATE users u SET ssn = 'x' FROM audit a WHERE a.id = 1 AND u.id = 99`
matches `a.id` first (the `And` arm tries `left` via `.or_else`) and seals against row key `1`
while the statement writes row `99`. No scope resolution is done on this predicate, unlike
every other predicate walk in the module.

**Why it matters**: the value is sealed against a row it does not land in, so it is permanently
unreadable and surfaces at read time as `Error::Decrypt` — a false tamper alarm and a killed
session. It is attacker-influenceable: anyone who can shape the FROM relation or its predicate
chooses which key the proxy binds.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An unqualified ident is accepted only when unambiguous in scope; a qualified one only when the qualifier names the target table or its alias
- [ ] #2 A test asserts UPDATE users u SET ssn = ... FROM audit a WHERE a.id = 1 AND u.id = 99 binds 99 or is signalled, never 1
<!-- AC:END -->
