#!/usr/bin/env bash

set -eo pipefail

ANDROID_DIR=./android

cd ../..

# Host library extension: .so on Linux, .dylib on macOS, .dll on Windows
case "$(uname -s)" in
  Linux*)   LIB_EXT=.so ;;
  Darwin*)  LIB_EXT=.dylib ;;
  *)        LIB_EXT=.so ;;
esac
LIB_PATH="target/release/libmls_mobile_sdk_rs${LIB_EXT}"

# Clean
rm -rf $ANDROID_DIR

# Build Rust
cargo build --release -p kchat-mls-uniffi

# Generate Kotlin bindings
cargo run -p kchat-mls-uniffi --bin uniffi-bindgen generate \
  --library "$LIB_PATH" \
  --language kotlin \
  --out-dir "$ANDROID_DIR" \
  --no-format

# Build with cargo-ndk for all targets
cargo ndk \
  --manifest-path ./crates/kchat-mls-uniffi/Cargo.toml \
  -t arm64-v8a \
  -t x86_64 \
  -o "$ANDROID_DIR"/com/kchat/mls/jniLibs \
  build --release
