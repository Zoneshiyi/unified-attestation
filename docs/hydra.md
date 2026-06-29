# hydra 子模块

最小 Groth16 over BLS12-381 + shrubs whitelist 累积器，用于 CCA + hydra
叠加路径中证明设备身份在白名单里、不暴露具体索引。

## 组成

- `circuit::AttestationCircuit`：ark-relations 电路，约束设备身份 +
  Merkle path + nonce 槽位
- `shrubs_tree`：whitelist 累积器（移植自 hydra `hydra-sys/src/shurbstree.rs`）
- `poseidon`：BLS12-381 Fr 上的标准 Poseidon 参数 + native sponge hash
- `nonce::nonce_to_scalar`：`Fr::from_le_bytes_mod_order(blake2s_256(nonce))`，
  attester 与 wasm 双方必须用此函数，不允许各自实现
- `verify`：`verify_groth16` + `decode_public_inputs`，wasm32-wasip1 兼容
- `prove` / `setup`：仅 std 启用（attester 用）

`#![no_std]` + `extern crate alloc`，关闭 default features 后可交叉编译至
wasm32-wasip1（仅暴露 verify 路径）。

## Public input 顺序

电路 `new_input` 调用顺序，attester 与 wasm 必须严格一致：

```
[ pk, root[0..N], output, time, period, challenge ]
```

- `pk`：attester 设备公钥的 Fr 表达
- `root[0..N]`：shrubs 累积器的可信 root 列表（与 verifier policy 比对）
- `output = H(H(H(pk, ar), time), period)`
- `time` / `period`：时间戳 + 周期长度（demo 中固定 86400）
- `challenge`：`nonce_to_scalar(nonce)`，电路内不约束，由 wasm 在 verify 通过
  后比对 `expected_report_data`

## 约束逻辑

```
m    = H(ar, sk)
leaf = H(m, pk)
for (sib, tag) in zip(path, tags):
    leaf = H(leaf, sib) if tag else H(sib, leaf)
assert leaf ∈ root[]
assert output == H(H(H(pk, ar), time), period)
```

`tag` / `path` 长度由 setup 时 `path_len` 决定，电路形状被 setup 凝固。

## Trusted setup

```bash
cargo run -p hydra --bin setup_keys --release -- <root_count> <path_len> [out_dir]
```

`root_count` × `path_len` 必须与 attester 配置中 device 数推出来的 shrubs
形状一致，否则 prove 会失败。`shrubs_roots` example 列出每个 self_index 的合法性：

```bash
cargo run -p hydra --example shrubs_roots --release
```

## 已知小坑

`shrubs_tree::find_shrubs_path` 对落在 shrubs root 边界上的 leaf 返回 `None`
——这些 leaf 自身即 shrubs root，没有 path。`shrubs_roots` example 会标注
哪些 self_index 合法。
