#!/usr/bin/env bash

set -eo pipefail

IOS_DIR=./ios

cargo swift package -y -p ios --release -n ios
