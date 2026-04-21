#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building ndpi-observe..."
make -j"$(nproc)"
echo "==> Build complete: ndpid ndpid-simple ndpictl"
