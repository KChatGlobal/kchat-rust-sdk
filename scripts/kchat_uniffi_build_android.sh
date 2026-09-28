#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
android_dir="$repo_root/crates/kchat-uniffi/android"
cd "$repo_root"

case "$(uname -s)" in
  Darwin*) library_extension=dylib ;;
  Linux*) library_extension=so ;;
  *) echo "Unsupported host for kchat-uniffi Android build" >&2; exit 1 ;;
esac

cargo build --release -p kchat-uniffi

cargo run -p kchat-uniffi --bin uniffi-bindgen -- generate \
  --library "$repo_root/target/release/libkchat_mobile_sdk_rs.$library_extension" \
  --language kotlin \
  --out-dir "$android_dir" \
  --no-format

cargo ndk \
  --manifest-path "$repo_root/crates/kchat-uniffi/Cargo.toml" \
  -t arm64-v8a \
  -t x86_64 \
  -o "$android_dir/com/kchat/sdk/jniLibs" \
  build --release
