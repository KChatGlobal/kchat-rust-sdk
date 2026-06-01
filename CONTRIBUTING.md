# Contributing to KChat Rust SDK

Thanks for your interest in contributing! This document explains how to set up
your environment, the standards we follow, and how to propose changes.

By participating in this project you agree to abide by our
[Code of Conduct](#code-of-conduct).

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Building & Testing](#building--testing)
- [Coding Standards](#coding-standards)
- [Commit Messages](#commit-messages)
- [Pull Requests](#pull-requests)
- [Reporting Bugs](#reporting-bugs)
- [Security Issues](#security-issues)
- [License](#license)
- [Code of Conduct](#code-of-conduct)

## Ways to Contribute

- Report bugs and request features via [GitHub Issues](https://github.com/KChatGlobal/kchat-rust-sdk/issues).
- Improve documentation.
- Submit bug fixes or new features through pull requests.

> This crate is part of an end-to-end encryption stack. If you believe you have
> found a security vulnerability, **do not** open a public issue — follow the
> [Security Policy](./SECURITY.md) instead.

## Development Setup

Prerequisites (see the [README](./README.md#prerequisites) for the full list):

- **Rust** (latest stable) via [rustup](https://rustup.rs/). The toolchain is
  pinned in [`rust-toolchain.toml`](./rust-toolchain.toml) and includes
  `rustfmt` and `clippy`.
- For the Node.js bindings (`kchat-mls-napi`): Node.js `>= 10.20.0` and
  `yarn` 4.x (shipped via Corepack), plus `@napi-rs/cli`.
- For the mobile bindings (`kchat-mls-uniffi`): `cargo-swift` (iOS) and
  `cargo-ndk` + Android NDK (Android).

Clone the repository and verify the workspace builds:

```bash
git clone https://github.com/KChatGlobal/kchat-rust-sdk.git
cd kchat-rust-sdk
cargo build --workspace
```

## Building & Testing

Before pushing, make sure the following all pass locally:

```bash
# Format check (rustfmt config lives in rustfmt.toml: edition 2024, max_width 100)
cargo fmt --all -- --check

# Lints — warnings are treated as errors
cargo clippy --workspace --all-targets -- -D warnings

# Tests
cargo test --workspace
```

Build a single crate while iterating:

```bash
cargo build -p kchat-mls
cargo build -p kchat-mls-napi
```

## Coding Standards

- Format all code with `cargo fmt` (do not hand-format around the tooling).
- Keep `cargo clippy` clean; justify any `#[allow(...)]` with a comment.
- Prefer minimal, focused changes. Avoid unrelated refactors in the same PR.
- Add or update tests for any behavioral change. Never weaken or delete an
  existing test to make a change pass without explicit reviewer agreement.
- Public API changes (especially in `kchat-mls-uniffi` and `kchat-mls-napi`)
  must be called out in the PR description, since they affect generated Swift,
  Kotlin, and TypeScript bindings.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Use a
type prefix and an imperative summary:

```
<type>(<scope>): <short summary>
```

Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`.
Use `!` (e.g. `feat(napi)!: ...`) and a `BREAKING CHANGE:` footer for changes
that alter a public API or binding surface.

Examples:

```
fix(storage): retry sqlite busy errors during migration
feat(napi)!: use BigInt for u64 epoch fields
```

## Pull Requests

1. Fork the repository and create a branch off the default branch.
2. Make your change with accompanying tests and documentation.
3. Ensure `cargo fmt --all -- --check`, `cargo clippy ... -D warnings`, and
   `cargo test --workspace` all pass.
4. Open a PR with a clear description of **what** changed and **why**, and link
   any related issue.
5. Keep the PR focused; smaller PRs are reviewed faster.

By submitting a pull request, you agree that your contribution is licensed
under the project's dual license (see [License](#license)).

## Reporting Bugs

When filing a bug, please include:

- The affected crate and version.
- A minimal reproduction or failing test if possible.
- Expected vs. actual behavior.
- Your platform, Rust version (`rustc --version`), and — for bindings — the
  Node.js / Swift / Kotlin toolchain version.

## Security Issues

Please report vulnerabilities privately. See [SECURITY.md](./SECURITY.md).

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT OR Apache-2.0, without any additional terms or conditions.

See [`LICENSE-APACHE`](./LICENSE-APACHE), [`LICENSE-MIT`](./LICENSE-MIT), and
[`NOTICE`](./NOTICE).

## Code of Conduct

We are committed to providing a welcoming and harassment-free experience for
everyone. We expect all contributors to be respectful in issues, pull requests,
and all other project spaces. Unacceptable behavior may be reported to the
maintainers at the contact listed in [SECURITY.md](./SECURITY.md). Maintainers
may remove, edit, or reject contributions that do not align with these
principles.
