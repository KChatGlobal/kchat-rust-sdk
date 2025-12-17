# Rust Project with UniFFI

This crate demonstrates how to use `uniffi-rs` to generate Swift/Android bindings for a Rust library

## Prerequisites

Ensure you have the following installed:
- Rust (latest stable version): Install via [rustup](https://rustup.rs/)
- `uniffi-rs` crate, `cargo-swift` tools, and `cargo-ndk` tools

## Setup

1. **Install UniFFI**

Update `Cargo.toml` to include the `uniffi-rs` crate:
```toml
...
[dependencies]
uniffi = { version = "0.29.1", features = ["cli", "tokio"] }
...
```

2. **Project Structure**

Ensure your project has the following structure:
```
.
├── Cargo.toml
├── src
│   └── lib.rs
└── uniffi-bindgen.rs
└── uniffi.toml
```

- `Cargo.toml`: Configures the Rust crate and dependencies.
- `src/lib.rs`: Contains the Rust code with UniFFI annotations.
- `uniffi-bindgen.rs`: Entry-point
- `uniffi.toml`: Configuration for UniFFI bindings.

3. **Configure UniFFI**

Create or edit `uniffi.toml` in the project root to specify the bindings:
```toml
[bindings.swift]
output_dir = "bindings/swift"
```

4. **Write Rust Code with UniFFI Annotations**

Check : [Link](https://mozilla.github.io/uniffi-rs/latest/proc_macro/functions.html)

5. **Package for Swift**

Use `cargo swift` to create a Swift-compatible package:
```bash
  cargo swift package -p ios -n MobileSdkRs --release
```
This generates an XCFramework or Swift package in the `MobileSdkRs` directory, depending on your configuration.

6. **Package for Kotline**

Use `cargo ndk` to build binaries for Android from a Rust codebase
```bash
  cargo ndk --manifest-path ./crates/kchat-mls-uniffi/Cargo.toml -t armeabi-v7a -t arm64-v8a -t x86_64 -o ./generated/com/kchat/mls/jniLibs build --release
```

Generate foreign bindings by using a cdylib file built
```bash
  cargo build
  cargo run --bin uniffi-bindgen generate --library target/debug/libmobile_sdk_rs.dylib --language kotlin --out-dir ./generated --no-format
```
