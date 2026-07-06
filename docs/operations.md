# 操作手册

构建、运行、调试用的命令清单。

## 前置依赖

- Rust 1.90.0（见 `rust-toolchain.toml`）
- `cargo install cargo-component --locked`（编 wasm appraiser 用）
- `rustup target add wasm32-wasip1`
- `openssl`（生成 ES256 密钥对）

## 通用脚本


| 脚本                            | 用途                           | 依赖                             |
| ----------------------------- | ---------------------------- | ------------------------------ |
| `scripts/run-mvp.sh`          | mock 模式端到端（无 TEE 依赖）         | —                              |
| `scripts/gen-keys.sh`         | 生成 ES256 密钥对到 `config/keys/` | openssl                        |
| `scripts/build-appraisers.sh` | 编译所有 wasm appraiser          | cargo-component, wasm32-wasip1 |


`config/keys/` 与 `config/hydra-shrubs/` 由脚本生成，已加入 `.gitignore`。

各 TEE 端到端测试步骤需在对应硬件环境下手动执行，命令清单见各 TEE 文档：

- CCA / CCA + hydra：[docs/cca.md](cca.md)
- Hygon CSV / CSV + hydra：[docs/csv.md](csv.md)
- TDX / TDX + hydra：[docs/tdx.md](tdx.md)
- iTrustee：需 iTrustee TEE 硬件 + libqca.so + libteeverifier.so（测试命令见下文）
- VirtCCA：需 VirtCCA TEE 硬件 + libvccaattestation.so + OpenSSL（测试命令见下文）

### iTrustee 端到端测试

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-itrustee.toml > /tmp/verifier-itrustee.log 2>&1 &
./target/release/attester --config config/attester-itrustee.toml > /tmp/attester-itrustee.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type itrustee \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-itrustee.jwt
```

### VirtCCA 端到端测试

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-virtcca.toml > /tmp/verifier-virtcca.log 2>&1 &
./target/release/attester --config config/attester-virtcca.toml > /tmp/attester-virtcca.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type virtcca \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-virtcca.jwt
```

## 工具


| 命令                                                                         | 用途                          |
| -------------------------------------------------------------------------- | --------------------------- |
| `cargo run -p hydra --bin setup_keys -- <root_count> <path_len> [out_dir]` | trusted setup，生成 PK/VK      |
| `cargo run -p hydra --example shrubs_roots`                                | 根据设备列表计算可信 root hex         |
| `sha256sum target/wasm32-wasip1/release/*.wasm`                            | 计算 appraiser sha256（更新白名单用） |


