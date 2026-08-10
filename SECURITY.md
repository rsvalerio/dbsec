# Security Policy

<!--
Shared template. Copy into the consuming repository and replace {{REPO}} with its name.
Delete the "Scope notes" section if the project has no scope caveats worth stating — an
empty heading reads worse than no heading.
-->

## Supported versions

Only the latest release is supported with security updates.

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.

Instead, report privately via
**[GitHub Security Advisories](https://github.com/rsvalerio/{{REPO}}/security/advisories/new)**
("Report a vulnerability" on the repo's Security tab).

Please include:

- A description of the issue and its impact
- Steps to reproduce (or a proof of concept)
- Affected version / commit

You can expect an acknowledgment within a few days. Once a fix is released, the advisory
will be published with credit to the reporter (unless you prefer to remain anonymous).

## Scope notes

- Reports about deployments that ignore the project's documented hardening guidance may be
  considered out of scope — but err on the side of reporting.
- Vulnerabilities in third-party dependencies should be reported upstream. If the project
  is exposed in a way the upstream advisory does not cover, report it here as well.
