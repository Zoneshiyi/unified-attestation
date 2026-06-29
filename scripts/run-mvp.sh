#!/usr/bin/env bash
# 端到端跑通 mock 模式（gRPC 链路 + RP 触发）：
#   1. 生成密钥对（首次运行）
#   2. 编译 mock 组件
#   3. 启动 verifier
#   4. 启动 attester
#   5. RP 触发完整流程并校验 EAR
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh

cargo build

cargo run -p verifier -- --config config/verifier.toml &
VERIFIER_PID=$!
cargo run -p attester -- --config config/attester.toml &
ATTESTER_PID=$!
trap 'kill $VERIFIER_PID $ATTESTER_PID 2>/dev/null || true' EXIT

# 等服务起来
sleep 3

cargo run -p relying-party -- \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type mock \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear.jwt
