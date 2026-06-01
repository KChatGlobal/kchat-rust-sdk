# KChat Rust SDK

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-stable%20(edition%202024)-orange.svg)](https://www.rust-lang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

A Cargo workspace containing the Rust SDK that powers the [Messaging Layer Security (MLS)](https://datatracker.ietf.org/wg/mls/about/) end-to-end encryption layer for KChat. The SDK wraps [OpenMLS](https://github.com/openmls/openmls) with KChat-specific business logic and exposes the same core to Swift, Kotlin and Node.js through cross-language bindings.

## Workspace Layout

The workspace is composed of five crates under `crates/`:

- **`kchat-storage-provider`** — SQLite-backed implementation of the OpenMLS `StorageProvider` trait. Uses `rusqlite` with `r2d2` connection pooling and `refinery` migrations (see `crates/kchat-storage-provider/migrations`).
- **`uq-openmls`** — Thin wrapper around OpenMLS exposing the core MLS primitives (group creation, welcome processing, proposal/commit handling, fork resolution) used by KChat. Also wires the SQLite storage provider into an `OpenMlsProvider`.
- **`kchat-mls`** — High-level KChat MLS logic on top of `uq-openmls`: group lifecycle management, batch message processing, group-status persistence, and tree-hash bookkeeping.
- **`kchat-mls-uniffi`** — [UniFFI](https://mozilla.github.io/uniffi-rs/) bindings that produce a Swift package and Kotlin/Android JNI libraries from `kchat-mls`. Crate type: `staticlib`, `cdylib`, `lib`.
- **`kchat-mls-napi`** — [NAPI-RS](https://napi.rs/) bindings that expose `kchat-mls` to Node.js as a native addon (`@kchat/mls-napi`).

Dependency graph:

```
kchat-mls-uniffi ─┐
                  ├─► kchat-mls ─► uq-openmls ─► kchat-storage-provider ─► OpenMLS
kchat-mls-napi  ─┘
```

## Prerequisites

- **Rust** (latest stable) via [rustup](https://rustup.rs/), with `edition = "2024"` support.
- **SQLite** toolchain — bundled via `rusqlite`'s `bundled` / `bundled-sqlcipher-vendored-openssl` features, no system install required.
- For mobile bindings (`kchat-mls-uniffi`):
  - [`cargo-swift`](https://github.com/antoniusnaumann/cargo-swift) for iOS packaging.
  - [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK for Android.
- For Node.js bindings (`kchat-mls-napi`):
  - Node.js 10.20+ with Node-API v6 support (required by the `napi6` feature).
  - `yarn` 4.x (the crate ships with `yarn@4.9.1` via Corepack).
  - `@napi-rs/cli`.

## Build

Build the entire workspace:

```bash
cargo build --workspace
```

Build a single crate:

```bash
cargo build -p kchat-mls
cargo build -p uq-openmls
cargo build -p kchat-storage-provider
```

Run the test suite:

```bash
cargo test --workspace
```

## Mobile Bindings (`kchat-mls-uniffi`)

The `kchat-mls-uniffi` crate produces a `mls_mobile_sdk_rs` library plus a `uniffi-bindgen` binary used to generate foreign-language bindings.

### iOS

From `crates/kchat-mls-uniffi/`:

```bash
make build-ios
```

Internally this runs `scripts/mls_uniffi_build_ios.sh`, which calls `cargo swift package -y -p ios --release -n ios` and writes the Swift package / XCFramework to `./ios`. The deployment target defaults to iOS 16.0 and can be overridden with `IOS_DEPLOYMENT_TARGET`.

### Android

From `crates/kchat-mls-uniffi/`:

```bash
make build-android
```

This runs `scripts/mls_uniffi_build_android.sh`, which:

1. Builds `kchat-mls-uniffi` in release mode for the host.
2. Generates Kotlin bindings via `uniffi-bindgen` into `./android`.
3. Cross-compiles JNI libraries for `arm64-v8a` and `x86_64` with `cargo-ndk` into `./android/com/kchat/mls/jniLibs`.

## Node.js Bindings (`kchat-mls-napi`)

From `crates/kchat-mls-napi/`:

```bash
yarn install
yarn build         # release build
yarn build:debug   # debug build
```

The package is published as `@kchat/mls-napi`. Supported targets are declared in `crates/kchat-mls-napi/package.json`:

- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`

## OpenMLS Patch

The workspace pins OpenMLS to the KChat fork via `[patch.crates-io]` in the root `Cargo.toml`:

```toml
[patch.crates-io]
openmls               = { git = "https://github.com/KChatGlobal/openmls.git", branch = "main" }
openmls_basic_credential = { git = "https://github.com/KChatGlobal/openmls.git", branch = "main" }
openmls_traits        = { git = "https://github.com/KChatGlobal/openmls.git", branch = "main" }
openmls_rust_crypto   = { git = "https://github.com/KChatGlobal/openmls.git", branch = "main" }
```

The fork enables fork-resolution and additional storage extensions required by KChat.

## Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for
development setup, coding standards, and the pull-request process. Before
opening a PR, make sure the following pass:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

By contributing you agree to abide by the project's Code of Conduct (see
[`CONTRIBUTING.md`](./CONTRIBUTING.md#code-of-conduct)).

## Security

This SDK is part of an end-to-end encryption stack. If you discover a security
vulnerability, **please do not open a public issue** — follow the responsible
disclosure process in [`SECURITY.md`](./SECURITY.md).

## License

Copyright (c) 2025 KChat.com.

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([`LICENSE-MIT`](./LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

See [`NOTICE`](./NOTICE) for third-party attributions.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
