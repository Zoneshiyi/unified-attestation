#!/usr/bin/env bash
# 用 cargo-component 编译所有 appraiser 到 wasm component（target/wasm32-wasip1/release/）。
#
# 安装 cargo-component：cargo install cargo-component --locked
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-component >/dev/null 2>&1; then
  echo "需要先安装 cargo-component：cargo install cargo-component --locked"
  exit 1
fi

cargo component build --release \
  -p mock-appraiser \
  -p cca-appraiser \
  -p cca-hydra-appraiser \
  -p csv-appraiser \
  -p csv-hydra-appraiser \
  -p tdx-appraiser \
  -p tdx-hydra-appraiser
ls -lh "$ROOT/target/wasm32-wasip1/release/"*.wasm
