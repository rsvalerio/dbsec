---
id: TASK-0216
title: >-
  ERR-2: seven public parsers and startup_kind have no doc comment or no #
  Errors section, and the two header validators disagree on whether a fixed-size
  header is passed by value or by reference
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - api-design
dependencies: []
modified_files:
  - crates/pgwire/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/pgwire/src/lib.rs:93` (`startup_kind`, no doc), `:129` (`frame_body_len`, no `# Errors`), `:162` (`parse_row_description`), `:184` (`parse_data_row`), `:223` (`parse_parse`, no doc), `:229` (`encode_parse`, no doc), `:291` (`parse_bind`, no doc), `:351` (`take_cstr`, no `# Errors`); `:112` vs `:129` (signature inconsistency)

**What**: This is a published crate (`dbsec-pgwire`) whose `Error` is documented as "document which variants each public function may return" territory — and `startup_body_len`, `encode_data_row`, `encode_bind` and `result_format_codes` do exactly that with a `# Errors` section. The remaining public fallible functions do not: `frame_body_len`, `parse_row_description`, `parse_data_row`, `parse_parse`, `parse_bind` and `take_cstr` return `Result<_, Error>` with no `# Errors` section, and `startup_kind`, `parse_parse`, `encode_parse` and `parse_bind` have no doc comment at all (`cargo doc` renders them as bare signatures). Separately, `startup_body_len(len_field: [u8; 4])` takes its header by value while `frame_body_len(header: &[u8; FRAME_HEADER_LEN])` takes it by reference and then copies four bytes out by hand (`let mut len_field = [0u8; 4]; len_field.copy_from_slice(&header[1..])`) where `header[1..].try_into()` or `split_first()` would do — the two sibling validators present different calling conventions for the same job (READ-6).

**Why it matters**: `clippy::missing_errors_doc` is in `pedantic`, so the workspace `all = deny` does not catch this, and the crate's README-facing docs are the only place a consumer learns that `parse_bind` can fail with the same variant as a backend message. The ad-hoc copy in `frame_body_len` is the one place in the file that manually moves bytes instead of slicing.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every public fn returning Result has a # Errors section naming the variant(s) and condition(s)
- [ ] #2 startup_kind, parse_parse, encode_parse and parse_bind have a summary doc comment
- [ ] #3 startup_body_len and frame_body_len take their fixed-size header the same way (both by value or both by reference), and frame_body_len slices the length field without a manual copy
- [ ] #4 cargo clippy -p dbsec-pgwire -- -W clippy::missing_errors_doc -W clippy::missing_docs_in_private_items is clean for public items (or missing_docs is enabled for the crate)
<!-- AC:END -->
