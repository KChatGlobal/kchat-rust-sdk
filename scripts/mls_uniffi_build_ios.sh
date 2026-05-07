#!/usr/bin/env bash

set -eo pipefail

IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-16.0}"
export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

cargo swift package -y -p "ios@${IOS_DEPLOYMENT_TARGET}" --release -n ios
