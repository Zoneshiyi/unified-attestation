# CCA Path

ARM CCA remote attestation: hardware root signature + nonce binding. CCA real verification runs on the verifier host (consistent with trustmee-artifact), while the wasm appraiser only does field passthrough and application-level nonce comparison.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant RP as relying-party
    participant At as attester
    participant AA as attestation-agent<br/>(REST)
    participant TEE as ARM CCA Hardware<br/>(RMM)
    participant V as verifier host
    participant W as wasm appraiser<br/>(cca)

    RP->>RP: generate 32B random nonce
    RP->>At: GetEvidence { tee_type=cca, nonce }

    At->>AA: GET /aa/evidence?runtime_data=base64(nonce)
    AA->>TEE: request CCA token (challenge=nonce)
    TEE-->>AA: CCA token (CBOR + COSE-Sign1)
    AA-->>At: CCA token (base64)

    Note over At: evidence = { cca_token_b64, nonce }
    At-->>RP: { evidence, wasm_component }

    RP->>V: Verify { tee_type=cca, nonce, evidence, wasm_component }

    V->>V: ccatoken::Evidence::decode (CBOR)
    V->>V: e.verify(ta_store)<br/>COSE-Sign1 / IAK / RAK chain
    V->>V: e.appraise(rv_store)<br/>platform / realm measurement
    V->>V: realm_claims.challenge == padded(nonce)

    V->>W: evaluate(evidence, expected_report_data=nonce)
    W-->>V: claims { subject, token_size, ... }

    V->>V: policy.cca.trusted_subjects comparison
    V-->>RP: EAR JWT (ES256)

    RP->>RP: verify EAR signature locally + compare eat_nonce
```

## Data Flow

```
RP:
  generate 32B random nonce
  GetEvidence(tee_type=cca, nonce) -> attester
  Verify(tee_type=cca, nonce, evidence, wasm_component) -> verifier

attester:
  AA REST GET /aa/evidence?runtime_data=<base64(nonce)> -> CCA token
  evidence = { cca_token_b64, nonce }

verifier host:
  ccatoken::Evidence::decode -> CBOR decode
  e.verify(&ta_store)         -> COSE-Sign1 / IAK / RAK chain
  e.appraise(&rv_store)       -> platform / realm measurement comparison
  realm_tvec.instance_identity == Affirming
  realm_claims.challenge == expected_report_data (nonce padded to 64 B)
  -> On success, extract CCA measurements and inject into evidence JSON:
     · cca_realm_initial_measurement  (RIM, hex)
     · cca_realm_personalization_value  (perso, hex)
     · cca_platform_instance_id  (hex)
     · cca_platform_implementation_id  (hex)
     · cca_platform_lifecycle  ("secured" / "recoverable" / "not_secured")
     · cca_platform_sw_components  (array)

wasm appraiser (cca):
  parse evidence JSON, verify nonce binding, passthrough host-injected fields to claims
  output: tee_type, verification, nonce_bound, token_size + 6 CCA measurement fields above
```

## Configuration

verifier-side `[policy.cca]`:

| key | description |
|---|---|
| `ta_store` | ccatoken trust anchor store JSON path, containing IAK public keys |
| `rv_store` | reference value store JSON path, containing platform/realm expected measurements |
| `trusted_subjects` | trusted realm subject whitelist (for cca-hydra) |
| `trusted_rim_hex` | trusted RIM list (hex). When non-empty, `cca_realm_initial_measurement` must match |

If `ta_store` / `rv_store` are missing, host-side verification is skipped (demo only). When `trusted_rim_hex` is empty, RIM comparison is skipped. In production, configure it to confirm the expected Realm image is running.

attester-side `aa_endpoint` points to guest-components `api-server-rest` (default `http://127.0.0.1:8006`).

## End-to-End Test

Requires ARM CCA hardware + guest-components attestation-agent + api-server-rest.

```bash
# 1. Generate ES256 key pair (first time)
bash scripts/gen-keys.sh

# 2. Build all wasm appraisers + host binaries
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

# 3. Start guest-components AA (prepare separately)
ttrpc-aa &
api-server-rest --features attestation &

# 4. Start verifier + attester
./target/release/verifier --config config/verifier-cca.toml > /tmp/verifier-cca.log 2>&1 &
./target/release/attester --config config/attester-cca.toml > /tmp/attester-cca.log 2>&1 &
sleep 2

# 5. RP triggers full flow
./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type cca \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-cca.jwt
```

## CCA + hydra Stacking

With `tee_type = cca-hydra`, the attester carries both a CCA token and a Groth16 proof, sharing the same nonce. Verification order:

1. Host-side ccatoken full verification (same as CCA-only)
2. Inside wasm appraiser:
   - CCA field `nonce == base64url(expected_report_data)`
   - hydra public_inputs last == `nonce_to_scalar(expected_report_data)`
   - Groth16 verify

The verifier adds `[policy.hydra] trusted_roots_hex` and compares the `roots_hex` returned by wasm.

`trusted_roots_hex` is computed by `cargo run -p hydra --example shrubs_roots`.

```mermaid
sequenceDiagram
    autonumber
    participant RP as relying-party
    participant At as attester
    participant AA as attestation-agent
    participant TEE as ARM CCA Hardware
    participant ZK as hydra prover<br/>(inside attester)
    participant V as verifier host
    participant W as wasm appraiser<br/>(cca-hydra)

    RP->>RP: generate 32B random nonce
    RP->>At: GetEvidence { tee_type=cca-hydra, nonce }

    par CCA hardware proof
        At->>AA: GET /aa/evidence?runtime_data=base64(nonce)
        AA->>TEE: request CCA token
        TEE-->>AA: CCA token
        AA-->>At: CCA token
    and device identity ZK proof
        At->>ZK: prove(devices, self_index, nonce)
        ZK-->>At: Groth16 proof + public_inputs
    end

    Note over At: evidence = { cca_token_b64, nonce, proof, public_inputs }
    At-->>RP: { evidence, wasm_component }

    RP->>V: Verify { tee_type=cca-hydra, nonce, evidence, wasm_component }

    V->>V: ccatoken host verification (same as CCA-only)

    V->>W: evaluate(evidence, expected_report_data=nonce)
    W->>W: CCA field nonce == base64url(nonce)
    W->>W: public_inputs[last] == nonce_to_scalar(nonce)
    W->>W: Groth16 verify(proof, public_inputs)
    W-->>V: claims { roots_hex, ... }

    V->>V: policy.cca + policy.hydra.trusted_roots_hex
    V-->>RP: EAR JWT
```

### End-to-End Test (cca-hydra)

Based on the CCA-only steps, add one hydra trusted setup step and change the startup configs to `*-cca-hydra.toml`:

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party -p hydra

# trusted setup (4 devices → 3 roots, 1-step Merkle path), first run
cargo run -p hydra --bin setup_keys --release -- 3 1 config/hydra-shrubs

# compute trusted root list (output can be directly used in policy.hydra.trusted_roots_hex of verifier-cca-hydra.toml)
cargo run -p hydra --example shrubs_roots --release

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-cca-hydra.toml > /tmp/verifier-cca-hydra.log 2>&1 &
./target/release/attester --config config/attester-cca-hydra.toml > /tmp/attester-cca-hydra.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type cca-hydra \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-cca-hydra.jwt
```
