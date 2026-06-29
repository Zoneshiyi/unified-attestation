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

## 工具


| 命令                                                                         | 用途                          |
| -------------------------------------------------------------------------- | --------------------------- |
| `cargo run -p hydra --bin setup_keys -- <root_count> <path_len> [out_dir]` | trusted setup，生成 PK/VK      |
| `cargo run -p hydra --example shrubs_roots`                                | 根据设备列表计算可信 root hex         |
| `sha256sum target/wasm32-wasip1/release/*.wasm`                            | 计算 appraiser sha256（更新白名单用） |


