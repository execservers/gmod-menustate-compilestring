#!/usr/bin/env bash
# Compatibility wrapper: all required hosts must be CA-verified, or exit 1.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go run scripts/collect-github-pins.go
