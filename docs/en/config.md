# Configuration Reference

Configuration keys for each binary. Common templates are available under `config/`: copy and rename.

## verifier

| key | default | description |
|---|---|---|
| `listen` | — | gRPC listen address, e.g. `127.0.0.1:8080` |
| `wasm.allow_unsigned` | `false` | Debug escape hatch; must be `false` in production |
| `wasm.registry_dir` | `data/components` | Persistent directory for registered components |
| `wasm.trusted_component_hashes` | `[]` | Trusted component sha256 whitelist (lowercase hex) |
| `ear.signing_key_path` | — | EAR JWT signing private key (PEM, ES256) |
| `policy.cca.ta_store` | — | ccatoken trust anchor store JSON path |
| `policy.cca.rv_store` | — | reference value store JSON path |
| `policy.cca.trusted_subjects` | `[]` | Trusted realm subject whitelist (cca-hydra only) |
| `policy.cca.trusted_rim_hex` | `[]` | Trusted Realm Initial Measurement list (hex) |
| `policy.csv.enabled` | `false` | Enable host-side CSV verification |
| `policy.csv.cert_dir` | `/opt/hygon/csv` | HSK/CEK offline cache directory |
| `policy.csv.allow_kds_fetch` | `false` | Fetch from KDS online when cache miss |
| `policy.csv.trusted_chip_ids` | `[]` | Trusted chip_id whitelist |
| `policy.hydra.trusted_roots_hex` | `[]` | Trusted shrubs root list (lowercase hex) |
| `policy.tdx.pccs_url` | `https://api.trustedservices.intel.com` | Host-side PCCS/PCS URL for fetching collateral by fmspc |
| `policy.tdx.trusted_mr_td_hex` | `[]` | Trusted mr_td list |
| `policy.tdx.trusted_mr_seam_hex` | `[]` | Trusted SEAM measurement |
| `policy.tdx.trusted_mr_config_id_hex` | `[]` | init_data_hash list |
| `policy.tdx.accept_tcb_status` | `[]` | Accepted TCB status values |
| `policy.itrustee.trusted_uuids` | `[]` | Trusted TA UUID list (empty = skip) |
| `policy.itrustee.trusted_ta_img_hex` | `[]` | Trusted TA measurement list (hex, empty = skip) |
| `policy.virtcca.trusted_rim_hex` | `[]` | Trusted RIM list (hex, empty = skip) |

When `wasm.allow_unsigned = false`, `trusted_component_hashes` must have at least one entry, otherwise the verifier will fail to start. After a new build, use `sha256sum target/wasm32-wasip1/release/*.wasm` to update the whitelist.

When policy `*_hex` lists are all empty, the corresponding policy check is skipped. In production deployments, at minimum:

- CCA: `ta_store` + `rv_store` + `trusted_subjects` + `trusted_rim_hex`
- CSV: `enabled = true` + `cert_dir` (or `allow_kds_fetch = true`) + `trusted_chip_ids`
- hydra: `trusted_roots_hex`
- TDX: `pccs_url` + all four `trusted_*_hex` / `accept_tcb_status` filled
- iTrustee: `trusted_uuids` + `trusted_ta_img_hex` (native verification requires libteeverifier.so)
- VirtCCA: `trusted_rim_hex` (native verification requires libvccaattestation.so)

## attester

| key | default | description |
|---|---|---|
| `listen` | — | attester gRPC listen address, e.g. `127.0.0.1:9000` |
| `tee_type` | — | `mock` / `cca` / `cca-hydra` / `csv` / `csv-hydra` / `tdx` / `tdx-hydra` / `itrustee` / `virtcca` |
| `wasm_component_path` | — | Local wasm component path |
| `aa_endpoint` | `http://127.0.0.1:8006` | guest-components api-server-rest address (for CCA/CSV/TDX/iTrustee/VirtCCA) |
| `zk.proving_key_path` | — | Required for hydra mode |
| `zk.verifying_key_path` | — | Required for hydra mode |
| `zk.whitelist.devices` | — | Device (pk, sk, ar) list |
| `zk.whitelist.self_index` | — | Index of this attester in the devices list |

`zk.whitelist.self_index` must fall on a reachable Merkle path of the shrubs root list; positions on root boundaries (where the leaf itself is a shrubs root) will be rejected by `find_shrubs_path`. Legality is annotated by `cargo run -p hydra --example shrubs_roots`.

## Binary Arguments

| Binary | Arguments | Description |
|---|---|---|
| `verifier` | `-c, --config <path>` | Default `config/verifier.toml` |
| `attester` | `-c, --config <path>` | Default `config/attester.toml` |
| `relying-party` | `--attester <url>` `--verifier <url>` `--tee-type <kebab>` `--pubkey <path>` `[--ear-out <path>]` | First four required, `--ear-out` optionally saves EAR to file |

## Template Reference

| Files | Usage | tee_type |
|---|---|---|
| `verifier.toml` / `attester.toml` | mock mode | `mock` |
| `verifier-cca.toml` / `attester-cca.toml` | CCA-only | `cca` |
| `verifier-cca-hydra.toml` / `attester-cca-hydra.toml` | CCA + hydra | `cca-hydra` |
| `verifier-csv.toml` / `attester-csv.toml` | Hygon CSV | `csv` |
| `verifier-csv-hydra.toml` / `attester-csv-hydra.toml` | CSV + hydra | `csv-hydra` |
| `verifier-tdx.toml` / `attester-tdx.toml` | TDX | `tdx` |
| `verifier-tdx-hydra.toml` / `attester-tdx-hydra.toml` | TDX + hydra | `tdx-hydra` |
| `verifier-itrustee.toml` / `attester-itrustee.toml` | iTrustee | `itrustee` |
| `verifier-virtcca.toml` / `attester-virtcca.toml` | VirtCCA | `virtcca` |
