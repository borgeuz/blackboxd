#!/usr/bin/env bash
# build-all.sh — convenience wrapper around `make build-all`.
#
# Useful for CI environments where invoking make directly is awkward.
# Exits non-zero on the first failed target.
set -euo pipefail

cd "$(dirname "$0")/.."
exec make build-all "$@"
