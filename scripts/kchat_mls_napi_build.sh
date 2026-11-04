#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/napi_build_desktop.sh" kchat-mls-napi
