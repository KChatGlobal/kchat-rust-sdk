#!/usr/bin/env bash

set -eo pipefail

# IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-16.0}"
# export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

IOS_DIR=./ios

cargo swift package -y -p "ios" --release -n ios
