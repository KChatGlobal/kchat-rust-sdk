#!/usr/bin/env bash

set -eo pipefail

ANDROID_DIR=./android

cd ../..

# Clean
rm -rf $ANDROID_DIR

# Build Rust
cargo build --release -p kchat-mls-uniffi

# Generate Kotlin bindings
cargo run -p kchat-mls-uniffi --bin uniffi-bindgen generate \
  --library target/release/libmls_mobile_sdk_rs.dylib \
  --language kotlin \
  --out-dir "$ANDROID_DIR" \
  --no-format

# Build with cargo-ndk for all targets
cargo ndk \
  --manifest-path ./crates/kchat-mls-uniffi/Cargo.toml \
  -t armeabi-v7a \
  -t arm64-v8a \
  -t x86_64 \
  -o "$ANDROID_DIR"/com/kchat/mls/jniLibs \
  build --release
