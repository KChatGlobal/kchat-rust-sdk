#!/usr/bin/env bash
set -euo pipefail

export IPHONEOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-16.0}"
cd "$(dirname "${BASH_SOURCE[0]}")/../crates/kchat-uniffi"

cargo swift package -y -p "ios@${IPHONEOS_DEPLOYMENT_TARGET%%.*}" --release --lib-type static -n ios
