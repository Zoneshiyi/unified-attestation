# 配置参考

各 binary 的配置文件键值。常用模板均放在 `config/`：复制改名即可。

## verifier

| key | 默认值 | 说明 |
|---|---|---|
| `listen` | — | gRPC 监听地址，例 `127.0.0.1:8080` |
| `wasm.allow_unsigned` | `false` | 调试逃生通道；生产必须 `false` |
| `wasm.registry_dir` | `data/components` | 已注册组件持久化目录 |
| `wasm.trusted_component_hashes` | `[]` | 受信任组件 sha256 白名单（小写 hex） |
| `ear.signing_key_path` | — | EAR JWT 签名私钥（PEM, ES256） |
| `policy.cca.ta_store` | — | ccatoken trust anchor store JSON 路径 |
| `policy.cca.rv_store` | — | reference value store JSON 路径 |
| `policy.cca.trusted_subjects` | `[]` | 可信 realm 主体白名单 |
| `policy.csv.enabled` | `false` | 是否启用 host 端 CSV 验签 |
| `policy.csv.cert_dir` | `/opt/hygon/csv` | HSK/CEK 离线缓存目录 |
| `policy.csv.allow_kds_fetch` | `false` | 离线未命中时是否走 KDS 在线拉取 |
| `policy.csv.trusted_chip_ids` | `[]` | 可信 chip_id 白名单 |
| `policy.hydra.trusted_roots_hex` | `[]` | 可信 shrubs root 列表（小写 hex） |
| `policy.tdx.pccs_url` | `https://api.trustedservices.intel.com` | host 端按 fmspc 拉 collateral 用 |
| `policy.tdx.trusted_mr_td_hex` | `[]` | 可信 mr_td 列表 |
| `policy.tdx.trusted_mr_seam_hex` | `[]` | 可信 SEAM 测量 |
| `policy.tdx.trusted_mr_config_id_hex` | `[]` | init_data_hash 列表 |
| `policy.tdx.accept_tcb_status` | `[]` | 接受的 TCB status |

`wasm.allow_unsigned = false` 时，`trusted_component_hashes` 必须至少配一项，
否则 verifier 启动失败。新 build 后用 `sha256sum target/wasm32-wasip1/release/*.wasm`
更新白名单。

policy 的 `*_hex` 列表均空 → 对应 policy 跳过。生产部署中至少：

- CCA：`ta_store` + `rv_store` + `trusted_subjects`
- CSV：`enabled = true` + `cert_dir`（或 `allow_kds_fetch = true`） + `trusted_chip_ids`
- hydra：`trusted_roots_hex`
- TDX：`pccs_url` + 四项 `trusted_*_hex` / `accept_tcb_status` 全填

## attester

| key | 默认值 | 说明 |
|---|---|---|
| `listen` | — | attester gRPC 监听地址，例 `127.0.0.1:9000` |
| `tee_type` | — | `mock` / `cca` / `cca-hydra` / `csv` / `csv-hydra` / `tdx` / `tdx-hydra` |
| `wasm_component_path` | — | 本地 wasm 组件路径 |
| `aa_endpoint` | `http://127.0.0.1:8006` | guest-components api-server-rest 地址（cca / cca-hydra / csv / csv-hydra / tdx / tdx-hydra 用） |
| `zk.proving_key_path` | — | hydra 模式必填 |
| `zk.verifying_key_path` | — | hydra 模式必填 |
| `zk.whitelist.devices` | — | 设备 (pk, sk, ar) 列表 |
| `zk.whitelist.self_index` | — | 当前 attester 在 devices 中的下标 |

`zk.whitelist.self_index` 须落在 shrubs root 列表的可达 Merkle path 上；
落单位置（即 leaf 自身就是某个 shrubs root）会被 `find_shrubs_path` 拒绝。
合法性由 `cargo run -p hydra --example shrubs_roots` 标注。

## 二进制参数

| 二进制 | 参数 | 说明 |
|---|---|---|
| `verifier` | `-c, --config <path>` | 默认 `config/verifier.toml` |
| `attester` | `-c, --config <path>` | 默认 `config/attester.toml` |
| `relying-party` | `--attester <url>` `--verifier <url>` `--tee-type <kebab>` `--pubkey <path>` `[--ear-out <path>]` | 前四项必填，`--ear-out` 可选保存 EAR 到文件 |

## 模板对照

| 文件 | 用途 | tee_type |
|---|---|---|
| `verifier.toml` / `attester.toml` | mock 模式 | `mock` |
| `verifier-cca.toml` / `attester-cca.toml` | CCA-only | `cca` |
| `verifier-cca-hydra.toml` / `attester-cca-hydra.toml` | CCA + hydra 叠加 | `cca-hydra` |
| `verifier-csv.toml` / `attester-csv.toml` | Hygon CSV | `csv` |
| `verifier-csv-hydra.toml` / `attester-csv-hydra.toml` | CSV + hydra 叠加 | `csv-hydra` |
| `verifier-tdx.toml` / `attester-tdx.toml` | TDX | `tdx` |
| `verifier-tdx-hydra.toml` / `attester-tdx-hydra.toml` | TDX + hydra 叠加 | `tdx-hydra` |
