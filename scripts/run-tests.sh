#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Build first if binaries are missing
[ -x ndpid ] || scripts/build-daemon.sh

echo "==> Running tests..."
pytest test/ -v "$@"
