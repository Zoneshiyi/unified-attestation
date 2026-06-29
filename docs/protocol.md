# 协议层

verifier ↔ attester ↔ relying-party 三方共享的协议契约，定义在 `protos/attestation.proto`，
通过 `tonic-build` 在编译期生成 Rust 代码，由 `protos` crate 暴露。该 crate 不含业务逻辑，
只承载 gRPC service / message。

## 流程总览（RATS background-check）

```
RP --GetEvidence(tee_type, nonce)--> attester --AA/TEE--> evidence
RP <-(evidence, wasm_component)-- attester
RP --Verify(tee_type, nonce, evidence, wasm_component)--> verifier
RP <-(EAR JWT)-- verifier
RP 本地验签 EAR + 比对 eat_nonce == 本地 nonce
```

nonce 由 RP 自行生成（建议 32 字节随机），不依赖 verifier 签发 challenge token。
重放窗口由 RP 持有 nonce 与 EAR 的关联负责，verifier 无状态。

## gRPC 服务

| 服务 | 方法 | 调用方 | 说明 |
|---|---|---|---|
| `AttesterService` | `GetEvidence` | RP → attester | 推 nonce 收 evidence |
| `VerifierService` | `Verify` | RP → verifier | 提交 evidence 拿 EAR |

各 message 字段定义见 `protos/attestation.proto`。

`VerifyRequest.wasm` 是 `oneof`，二选一：
- 首次提交：`wasm_component`（wasm 字节流）
- 后续复用：`wasm_component_id`（首次提交后 verifier 返回的稳定 ID）

## TeeType 枚举

| proto 值 | kebab 名（claims 中用） | 备注 |
|---|---|---|
| `MOCK = 1` | `mock` | 跳过真实校验 |
| `CCA = 2` | `cca` | ARM CCA |
| `CCA_HYDRA = 3` | `cca-hydra` | CCA + hydra zk |
| `TDX = 4` | `tdx` | Intel TDX |
| `TDX_HYDRA = 5` | `tdx-hydra` | TDX + hydra zk |
| `CSV = 6` | `csv` | Hygon CSV |
| `CSV_HYDRA = 7` | `csv-hydra` | CSV + hydra zk |

attester 配置中的 `tee_type` 为 kebab 字符串；request 中的 `tee_type` 用 proto enum 数值，
由 RP 客户端 `parse_tee_type` 二者互译。attester 收到不同于自身配置的 `tee_type` 直接拒收。

## Nonce 编码

| 用途 | 编码 |
|---|---|
| `GetEvidenceRequest.nonce` / `VerifyRequest.nonce` | 原始字节（proto `bytes`） |
| RP 端日志 / EAR `eat_nonce` | base64url no-pad 字符串 |
| CCA evidence JSON 中的 `nonce` 字段 | base64url no-pad |
| AA REST `runtime_data` 参数 | 标准 base64 |
| hydra `challenge` public input | `nonce_to_scalar(raw_bytes)` |

attester 与 wasm appraiser 必须按相同规则编 / 解，否则 nonce 比对会失败。

## EAR 输出

verifier 签发的 EAR 是 ES256 JWT。顶层 claims：

```text
iss            = "unified-attestation-verifier"
iat            = unix 秒
eat_nonce      = base64url(RP nonce)
tee_type       = "mock" | "cca" | "cca-hydra" | "csv" | "csv-hydra" | "tdx" | "tdx-hydra"
component_id   = wasm 组件 ID
submods        = wasm 返回的 claims map
trust_vector   = { instance_identity, configuration, executables }
```

RP 持有 verifier 公钥即可本地验签 + 解码 + 比对 `eat_nonce == 本地 nonce`：

```bash
relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type mock \
    --pubkey config/keys/ear_public.pem
```

`executables < 2` 视为不可信。
