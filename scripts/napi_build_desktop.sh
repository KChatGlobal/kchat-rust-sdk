#!/usr/bin/env bash
# Build all desktop N-API targets from macOS and create one npm-compatible tarball.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
crate_dir="${1:?Pass kchat-mls-napi or kchat-napi}"
case "$crate_dir" in
  kchat-mls-napi) cargo_package=kchat_mls_napi; library=kchat_mls_napi ;;
  kchat-napi) cargo_package=kchat-napi; library=kchat_napi ;;
  *) echo "Unsupported N-API crate: $crate_dir" >&2; exit 1 ;;
esac
if [[ "$(uname -s)" != Darwin ]]; then
  echo "Run on macOS with Xcode command-line tools, Rust, Python 3 + pip, Perl, Node.js and Corepack installed." >&2
  exit 1
fi

target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd)"
cache_dir="${KCHAT_NAPI_BUILD_CACHE:-${KCHAT_MLS_NAPI_BUILD_CACHE:-$target_dir/kchat-mls-napi-build}}"
mkdir -p "$cache_dir"
cache_dir="$(cd "$cache_dir" && pwd)"
tools_dir="$cache_dir/tools"
export PYTHONPATH="$tools_dir${PYTHONPATH:+:$PYTHONPATH}"
export PATH="$cache_dir/bin:$tools_dir/bin:$PATH"
export CARGO_ZIGBUILD_CACHE_DIR="$cache_dir/zigbuild"
export ZIG_GLOBAL_CACHE_DIR="$cache_dir/zig-global"
export ZIG_LOCAL_CACHE_DIR="$cache_dir/zig-local"
export XWIN_CACHE_DIR="$cache_dir/xwin"

# Keep cross-compilers local to target/, without changing global Python packages.
if [[ ! -x "$tools_dir/bin/cargo-xwin" || ! -x "$tools_dir/bin/cargo-zigbuild" || ! -x "$tools_dir/ziglang/zig" ]]; then
  python3 -m pip install --target "$tools_dir" \
    'cargo-xwin==0.23.1' 'cargo-zigbuild==0.24.0' 'ziglang==0.17.0' ninja
fi
export CARGO_ZIGBUILD_ZIG_PATH="$tools_dir/ziglang/zig"

clang="$(xcrun --find clang)"
rustup component add llvm-tools-preview
rust_host="$(rustc -vV | sed -n 's/^host: //p')"
rust_bin="$(rustc --print sysroot)/lib/rustlib/$rust_host/bin"
mkdir -p "$cache_dir/bin"
ln -sf "$clang" "$cache_dir/bin/clang-cl"
ln -sf "$rust_bin/llvm-ar" "$cache_dir/bin/llvm-lib"
ln -sf "$rust_bin/llvm-ar" "$cache_dir/bin/llvm-ar"
ln -sf "$rust_bin/rust-lld" "$cache_dir/bin/lld-link"

rustup target add aarch64-apple-darwin x86_64-apple-darwin \
  x86_64-pc-windows-msvc x86_64-unknown-linux-gnu

echo "Building macOS arm64 and x64..."
cargo build --locked --release -p "$cargo_package" --target-dir "$target_dir" \
  --target aarch64-apple-darwin --target x86_64-apple-darwin

echo "Generating $crate_dir JavaScript loader and TypeScript declarations..."
(
  cd "$repo_root/crates/$crate_dir"
  export YARN_NODE_LINKER=node-modules
  if [[ ! -x node_modules/.bin/napi ]]; then
    YARN_ENABLE_SCRIPTS=false corepack yarn install --immutable
  fi
  corepack yarn build --target "$rust_host" --target-dir "$target_dir"
)

echo "Building Linux x64 (glibc 2.28)..."
cargo-zigbuild zigbuild --locked --release -p "$cargo_package" \
  --target-dir "$target_dir" --target x86_64-unknown-linux-gnu.2.28

echo "Preparing Windows x64 OpenSSL..."
# Initialize the MSVC SDK using cargo-xwin before compiling OpenSSL.
cargo-xwin env --target x86_64-pc-windows-msvc > "$cache_dir/xwin-env.sh"
openssl_source="$(cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc | python3 -c '
import json, pathlib, sys
p = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "openssl-src")
print(pathlib.Path(p["manifest_path"]).parent / "openssl")
')"
openssl_dir="$cache_dir/$(basename "$(dirname "$openssl_source")")-windows-msvc"
if [[ ! -f "$openssl_dir/libcrypto.lib" || ! -f "$openssl_dir/libssl.lib" ]]; then
  mkdir -p "$openssl_dir/include"
  cp -R "$openssl_source/include/." "$openssl_dir/include/"
  wrapper="$cache_dir/bin/clang-msvc"
  {
    printf '#!/usr/bin/env bash\nexec %q --target=x86_64-pc-windows-msvc ' "$clang"
    printf '%s ' '-fms-compatibility' '-D_MT' '-D_CRT_SECURE_NO_WARNINGS' '-D_CRT_NONSTDC_NO_DEPRECATE' '-Wno-deprecated-declarations' '-Wno-microsoft-enum-forward-reference' '-Wno-ignored-attributes'
    for include in crt/include sdk/include/ucrt sdk/include/um sdk/include/shared; do
      printf -- '-isystem %q ' "$XWIN_CACHE_DIR/xwin/$include"
    done
    printf '"$@"\n'
  } > "$wrapper"
  chmod +x "$wrapper"
  (
    cd "$openssl_dir"
    CC=clang-msvc AR=llvm-ar RANLIB=true \
      perl "$openssl_source/Configure" mingw64 no-shared no-module no-tests \
      no-comp no-zlib no-zlib-dynamic no-ssl3 no-md2 no-rc5 \
      no-weak-ssl-ciphers no-camellia no-idea no-seed no-capieng no-asm
    make -j "$(getconf _NPROCESSORS_ONLN)" build_libs
    cp libcrypto.a libcrypto.lib
    cp libssl.a libssl.lib
  )
fi

echo "Building Windows x64 (MSVC, static CRT/OpenSSL)..."
OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=1 OPENSSL_LIBS=ssl:crypto \
  OPENSSL_LIB_DIR="$openssl_dir" \
  OPENSSL_INCLUDE_DIR="$openssl_dir/include" \
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static" \
  cargo-xwin build --locked --release -p "$cargo_package" \
    --target-dir "$target_dir" --target x86_64-pc-windows-msvc

echo "Packaging all four targets..."
python3 - "$repo_root" "$target_dir" "$crate_dir" "$library" <<'PY'
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile

root, target = map(pathlib.Path, sys.argv[1:3])
crate_dir, library = sys.argv[3:5]
source = root / "crates" / crate_dir
manifest = json.loads((source / "package.json").read_text())
binary = manifest["napi"]["binaryName"]
head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip())
now = datetime.datetime.now(datetime.timezone.utc)
label = f"desktop-{head[:7]}{'-dirty' if dirty else ''}-{now:%Y%m%dT%H%M%S%fZ}"
out = target / f"{binary}-release" / label
package = out / "package"
package.mkdir(parents=True)
for name in ["index.js", "index.d.ts", "package.json", "README.md"]:
    shutil.copy2(source / name, package / name)
shutil.copytree(source / "scripts", package / "scripts")
for name in ["LICENSE-APACHE", "LICENSE-MIT", "NOTICE"]:
    shutil.copy2(root / name, package / name)

targets = {
    "aarch64-apple-darwin": (f"lib{library}.dylib", "darwin-arm64"),
    "x86_64-apple-darwin": (f"lib{library}.dylib", "darwin-x64"),
    "x86_64-pc-windows-msvc": (f"{library}.dll", "win32-x64-msvc"),
    "x86_64-unknown-linux-gnu": (f"lib{library}.so", "linux-x64-gnu"),
}
hashes = {}
for triple, (library, platform) in targets.items():
    destination = package / f"{binary}.{platform}.node"
    shutil.copy2(target / triple / "release" / library, destination)
    hashes[destination.name] = hashlib.sha256(destination.read_bytes()).hexdigest()

info = {
    "package": manifest["name"], "version": manifest["version"],
    "git_head": head, "contains_uncommitted_changes": dirty,
    "built_at_utc": now.isoformat(), "targets": list(targets),
    "cargo_lock_sha256": hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest(),
    "binaries_sha256": hashes, "linux_minimum_glibc": "2.28",
    "windows_build": "MSVC ABI; static CRT and OpenSSL; assembly disabled",
    "runtime_verification": "Not run by this build script",
}
(package / "BUILD-INFO.json").write_text(json.dumps(info, indent=2) + "\n")
archive = out / f"{binary}-{manifest['version']}-{label}.tgz"
with tarfile.open(archive, "w:gz") as tar:
    tar.add(package, arcname="package")
checksums = [f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}"]
checksums += [f"{digest}  package/{name}" for name, digest in hashes.items()]
(out / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
print(f"Package: {archive}")
print(f"Checksums: {out / 'SHA256SUMS'}")
PY
