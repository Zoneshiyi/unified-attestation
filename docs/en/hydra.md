# hydra Sub-Module

Minimal Groth16 over BLS12-381 + shrubs whitelist accumulator for proving device identity in a whitelist without revealing the specific index, used in hydra stacking paths.

## Components

- `circuit::AttestationCircuit`: ark-relations circuit constraining device identity + Merkle path + nonce slot
- `shrubs_tree`: whitelist accumulator (ported from hydra `hydra-sys/src/shurbstree.rs`)
- `poseidon`: standard Poseidon parameters on BLS12-381 Fr + native sponge hash
- `nonce::nonce_to_scalar`: `Fr::from_le_bytes_mod_order(blake2s_256(nonce))`. Both attester and wasm must use this function; no independent implementations
- `verify`: `verify_groth16` + `decode_public_inputs`, wasm32-wasip1 compatible
- `prove` / `setup`: only enabled with std (attester use)

- `device_vc`: on-chain device VC storage (`blockchain` feature, disabled by default). Implements device credential on-chain publishing and querying via EVM contract + `cast` CLI

`#![no_std]` + `extern crate alloc`. With default features disabled, cross-compiles to wasm32-wasip1 (only exposes verify path).

## Public Input Order

The circuit's `new_input` call order must be strictly consistent between attester and wasm:

```
[ pk, root[0..N], output, time, period, challenge ]
```

- `pk`: Fr representation of the attester device public key
- `root[0..N]`: trusted root list of the shrubs accumulator (compared against verifier policy)
- `output = H(H(H(pk, ar), time), period)`
- `time` / `period`: timestamp + period length (fixed at 86400 in demo)
- `challenge`: `nonce_to_scalar(nonce)`, not constrained inside the circuit; wasm compares against `expected_report_data` after verify passes

## Constraint Logic

```
m    = H(ar, sk)
leaf = H(m, pk)
for (sib, tag) in zip(path, tags):
    leaf = H(leaf, sib) if tag else H(sib, leaf)
assert leaf ∈ root[]
assert output == H(H(H(pk, ar), time), period)
```

`tag` / `path` length is determined by `path_len` at setup time. The circuit shape is frozen by setup.

## Trusted Setup

```bash
cargo run -p hydra --bin setup_keys --release -- <root_count> <path_len> [out_dir]
```

`root_count` × `path_len` must match the shrubs shape derived from the device count in the attester config, otherwise prove will fail. The `shrubs_roots` example annotates the legality of each self_index:

```bash
cargo run -p hydra --example shrubs_roots --release
```

## On-Chain Device VC Storage (blockchain feature)

Optional, not compiled by default (`--features blockchain` enabled). Allows the verifier to publish device VCs to a `DeviceVCRecord` contract on an EVM-compatible chain after successful verification, enabling independent querying by relying-parties.

### Contract Interface

`contracts/DeviceVCRecord.sol`:

- `storeVC(bytes32 devicePubkeyHash, string vcJson)` — store device VC (owner only)
- `getVC(bytes32 devicePubkeyHash) returns (string, uint256)` — query latest VC
- `vcCount(bytes32 devicePubkeyHash) returns (uint256)` — VC record count

Multiple writes per device are allowed (refreshing after expiry); queries return the latest one.

### Rust SDK

`hydra/src/device_vc.rs`, interacting via `cast` CLI (Foundry), no blockchain SDK dependencies:

- `publish_device_vc_to_chain(record, config)` → `cast send` → returns tx hash
- `query_device_vc_from_chain(device_pubkey, config)` → `cast call` → returns VC JSON
- `build_background_check_record(...)` → constructs a `DeviceVCRecord` including W3C VC + DID Document
- `DeviceVCCache` → local JSON file cache (upsert / expire / load / save)

### Configuration

Environment variables (all must be set):

```bash
export CHAIN_RPC_URL=<EVM RPC URL>
export CHAIN_CONTRACT_ADDRESS=<DeviceVCRecord contract address>
export CHAIN_PRIVATE_KEY=<verifier private key>
```

### Usage

```bash
# Build (with blockchain functionality)
cargo build --release --features blockchain -p verifier -p relying-party

# Deploy contract
forge create --rpc-url "$CHAIN_RPC_URL" --private-key "$CHAIN_PRIVATE_KEY" \
  contracts/DeviceVCRecord.sol:DeviceVCRecord

# verifier auto-publishes to chain after successful verification (env vars must be set)

# RP queries on-chain VC
./relying-party query-vc <device_pubkey_hex>
```

`query-vc` is only available when compiled with `blockchain` feature.

## Known Quirks

`shrubs_tree::find_shrubs_path` returns `None` for leaves that fall on shrubs root boundaries — these leaves are themselves shrubs roots and have no path. The `shrubs_roots` example annotates which self_index values are valid.
