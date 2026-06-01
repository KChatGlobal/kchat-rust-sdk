# Security Policy

The KChat Rust SDK implements part of an end-to-end encryption (E2EE) stack
based on [Messaging Layer Security (MLS)](https://datatracker.ietf.org/wg/mls/about/).
We take the security of this project seriously and appreciate responsible
disclosure of vulnerabilities.

## Supported Versions

Security fixes are provided for the latest released `0.2.x` line. Older
versions may not receive patches; please upgrade to the latest release.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, use one of the following private channels:

1. **GitHub private vulnerability reporting** (preferred) — open a report via
   the **"Report a vulnerability"** button on the
   [Security tab](https://github.com/KChatGlobal/kchat-rust-sdk/security/advisories/new)
   of this repository.
2. **Email** — contact the maintainers at **security@kchat.com**.
   <!-- TODO(maintainers): confirm or replace this with the official security contact. -->

Please include as much of the following as possible to help us triage quickly:

- The affected crate(s) and version or commit.
- A description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions or a proof-of-concept.
- Any suggested mitigation, if known.

## Disclosure Process

- We will acknowledge your report within **3 business days**.
- We aim to provide an initial assessment within **7 business days**.
- We will keep you informed of remediation progress and coordinate a disclosure
  timeline with you. Please allow us reasonable time to release a fix before any
  public disclosure.
- With your permission, we are happy to credit you in the release notes and
  security advisory.

## Scope

This policy covers the crates in this repository:

- `kchat-mls`
- `kchat-mls-uniffi`
- `kchat-mls-napi`
- `uq-openmls`
- `kchat-storage-provider`

Vulnerabilities in upstream dependencies (for example
[OpenMLS](https://github.com/openmls/openmls)) should be reported to the
respective project, though we welcome a heads-up if they affect this SDK.

Thank you for helping keep KChat and its users safe.
