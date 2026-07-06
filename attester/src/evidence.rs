//! Evidence construction.
//!
//! All TEE paths collect evidence through the guest-components api-server-rest HTTP interface:
//! `GET /aa/evidence?runtime_data=<base64(nonce)>` → returns raw TEE evidence bytes.
//!
//! - mock: fixed payload + nonce passthrough (no TEE hardware required)
//! - cca / csv / tdx: AA returns raw evidence (CCA token / CSV report / TDX quote),
//!   attester base64-encodes and wraps it
//! - itrustee / virtcca: AA returns JSON (report + optional log), attester appends the nonce field
//! - *-hydra: TEE evidence + Groth16 proof, sharing the same nonce. The nonce enters both
//!   the TEE evidence (as runtime_data) and the Groth16 circuit's last public input.
//!   Both sides check against expected_report_data in the wasm appraiser.

use crate::config::{WhitelistConfig, ZkConfig};
use anyhow::{Context, Result};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hydra::{Fr, circuit::AttestationCircuit, nonce, poseidon, prove, shrubs_tree};
use protos::TeeType;
use serde_json::json;
use std::io::Read;

/// Build evidence for a given tee_type. Dispatches to the appropriate TEE-specific builder.
///
/// For hydra-stacking paths, the TEE evidence and Groth16 proof are merged into a single
/// JSON object. The same nonce binds both layers — if either is missing, the wasm appraiser
/// will reject at the expected_report_data check.
pub async fn build_evidence(
    tee_type: TeeType,
    nonce_bytes: &[u8],
    zk: Option<&ZkConfig>,
    aa_endpoint: &str,
) -> Result<Vec<u8>> {
    let nonce_b64 = B64URL.encode(nonce_bytes);
    let nonce_b64 = nonce_b64.as_str();
    match tee_type {
        TeeType::Mock => Ok(serde_json::to_vec(&json!({
            "payload": {
                "device_id": "mock-device-001",
                "challenge_b64": nonce_b64,
                "note": "stage-1 mock evidence",
            },
            "issued_at": now_secs(),
        }))?),
        TeeType::Cca => {
            let cca_part = build_cca_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&cca_part)?)
        }
        TeeType::Csv => {
            let csv_part = build_csv_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&csv_part)?)
        }
        // Hydra-stacking paths: merge TEE evidence + ZK proof into one JSON object
        TeeType::CsvHydra => {
            let csv_part = build_csv_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = csv_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::CcaHydra => {
            let cca_part = build_cca_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = cca_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::Tdx => {
            let tdx_part = build_tdx_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&tdx_part)?)
        }
        TeeType::TdxHydra => {
            let tdx_part = build_tdx_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = tdx_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::Itrustee => {
            let part = build_itrustee_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&part)?)
        }
        TeeType::Virtcca => {
            let part = build_virtcca_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&part)?)
        }
        TeeType::Unspecified => anyhow::bail!("tee_type unspecified"),
    }
}

/// Build a Groth16 proof and serialize public inputs.
///
/// Public input serialization order (must match circuit.rs new_input calls exactly):
/// [pk, root[0..N], output, time, period, challenge]
///
/// The wasm appraiser decodes at the same offsets: pi_count - 5 → root_count,
/// pi_count - 1 → challenge (nonce scalar). Any mismatch in root_count or nonce position
/// will cause the appraiser to reject.
fn build_hydra_part(zk: &ZkConfig, nonce_b64: &str) -> Result<serde_json::Value> {
    // Load trusted setup artifacts (generated by `setup_keys` tool)
    let pk_bytes = std::fs::read(&zk.proving_key_path)
        .with_context(|| format!("read pk {}", zk.proving_key_path.display()))?;
    let vk_bytes = std::fs::read(&zk.verifying_key_path)
        .with_context(|| format!("read vk {}", zk.verifying_key_path.display()))?;

    // Encode nonce → BLS12-381 Fr via blake2s_256 + from_le_bytes_mod_order.
    // Both attester and wasm must use hydra::nonce::nonce_to_scalar — no independent impls.
    let nonce_bytes = B64URL.decode(nonce_b64).context("decode challenge nonce")?;
    let challenge_scalar = nonce::nonce_to_scalar(&nonce_bytes);

    // time + period are fixed inputs to output = H(H(H(pk,ar), time), period).
    // 86400 = seconds in a day → "valid for one day" semantics in the circuit.
    // The current wasm appraiser does not enforce time/period; used only for output comparison.
    let time = Fr::from(now_secs() as u64);
    let period = Fr::from(86_400u64);

    let wl = &zk.whitelist;
    let (circuit, root_list_for_pi) = build_whitelist_circuit(wl, time, period, challenge_scalar)?;

    let pk_field = circuit.pk;
    let output = circuit.output;

    // ponytail: deterministic seed (timestamp ^ constant) for demo debug reproducibility.
    // Production should use OsRng for cryptographic security.
    let mut rng = StdRng::seed_from_u64(now_secs() as u64 ^ 0xa5a5_a5a5);
    let proof_bytes = prove::prove(&pk_bytes, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("prove failed: {e}"))?;

    // Serialize public inputs in the exact order expected by the wasm appraiser.
    // Order: [pk, root[0..root_count], output, time, period, challenge]
    let mut pi_bytes = Vec::new();
    pk_field
        .serialize_compressed(&mut pi_bytes)
        .map_err(|e| anyhow::anyhow!("serialize pk: {e}"))?;
    for r in &root_list_for_pi {
        r.serialize_compressed(&mut pi_bytes)
            .map_err(|e| anyhow::anyhow!("serialize root: {e}"))?;
    }
    for fr in [output, time, period, challenge_scalar] {
        fr.serialize_compressed(&mut pi_bytes)
            .map_err(|e| anyhow::anyhow!("serialize public input: {e}"))?;
    }

    let evidence = json!({
        "vk_b64": B64.encode(&vk_bytes),
        "proof_b64": B64.encode(&proof_bytes),
        "public_inputs_b64": B64.encode(&pi_bytes),
    });

    Ok(evidence)
}

/// Full shrubs whitelist mode: build tree from configured device list, locate self_index path.
///
/// Flow:
/// 1. Convert device list to Merkle leaves: leaf = H(H(ar, sk), pk)
/// 2. Build shrubs accumulator → root list
/// 3. Locate Merkle path + tag for self_index in root list
/// 4. Compute output = H(H(H(pk, ar), time), period)
/// 5. Assemble AttestationCircuit (pk, sk, ar, time, period, output, root, path, tag, challenge)
fn build_whitelist_circuit(
    wl: &WhitelistConfig,
    time: Fr,
    period: Fr,
    challenge_scalar: Fr,
) -> Result<(AttestationCircuit, Vec<Fr>)> {
    // Guard: must have at least one device, self_index must be in range
    if wl.devices.is_empty() {
        anyhow::bail!("zk.whitelist.devices must not be empty");
    }
    if wl.self_index >= wl.devices.len() {
        anyhow::bail!(
            "zk.whitelist.self_index out of range: {} >= {}",
            wl.self_index,
            wl.devices.len()
        );
    }

    // Build Merkle leaves from device (pk, sk, ar) triples.
    // Leaf hash order must match circuit.rs steps 1-2: m=H(ar,sk), leaf=H(m,pk).
    // Changing the order here would break shrubs root ↔ circuit leaf alignment.
    let leaves: Vec<Fr> = wl
        .devices
        .iter()
        .map(|d| {
            let pk = Fr::from(d.pk);
            let sk = Fr::from(d.sk);
            let ar = Fr::from(d.ar);
            poseidon::hash_pair(poseidon::hash_pair(ar, sk), pk)
        })
        .collect();

    // Build shrubs accumulator → root list
    let mut root_list = Vec::new();
    shrubs_tree::create_batch_devices(&mut root_list, &leaves);

    // Find the Merkle path and direction tags for this attester's self_index.
    // Returns None if the self_index falls on a shrubs root boundary — those positions
    // have no path and cannot participate in the circuit.
    let (path_values, tag_values) =
        shrubs_tree::find_shrubs_path(&root_list, &leaves, 0, wl.self_index).ok_or_else(|| {
            anyhow::anyhow!(
                "self_index {} has no shrubs path (likely sits on a shrubs root \
                 boundary; pick a different index)",
                wl.self_index
            )
        })?;

    // Compute output commitment: output = H(H(H(pk, ar), time), period)
    let dev = &wl.devices[wl.self_index];
    let pk = Fr::from(dev.pk);
    let sk = Fr::from(dev.sk);
    let ar = Fr::from(dev.ar);
    let r1 = poseidon::hash_pair(pk, ar);
    let r2 = poseidon::hash_pair(r1, time);
    let output = poseidon::hash_pair(r2, period);

    let circuit = AttestationCircuit {
        pk,
        sk,
        ar,
        time,
        period,
        output,
        root: root_list.clone(),
        path: path_values,
        tag: tag_values,
        challenge: challenge_scalar,
    };
    Ok((circuit, root_list))
}

/// Call guest-components api-server-rest to fetch evidence.
///
/// The nonce is passed as the runtime_data query parameter. AA internally writes it into
/// the evidence's report_data / challenge field per TEE convention.
///
/// Returns the raw evidence bytes produced by AA. Each TEE path is responsible for
/// wrapping these bytes in its own format (base64-encoding binary payloads, appending
/// the nonce field, etc.).
fn fetch_aa_evidence(nonce_b64: &str, aa_endpoint: &str) -> Result<Vec<u8>> {
    let nonce_raw = B64URL.decode(nonce_b64).context("decode challenge nonce")?;
    let runtime_data_b64 = B64.encode(&nonce_raw);
    let url = format!("{}/aa/evidence?runtime_data={}", aa_endpoint, runtime_data_b64);
    let response = ureq::get(&url).call().with_context(|| format!("GET {}", url))?;
    let mut buf = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut buf)
        .context("read AA evidence body")?;
    Ok(buf)
}

/// CCA: wrap the raw CCA token (CBOR/COSE bytes) in base64 + nonce.
fn build_cca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let cca_token = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "cca_token_b64": B64.encode(&cca_token),
        "nonce": nonce_b64,
    }))
}

/// CSV: wrap the raw CSV evidence in base64 + nonce.
fn build_csv_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let csv_evidence = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "csv_evidence_b64": B64.encode(&csv_evidence),
        "nonce": nonce_b64,
    }))
}

/// TDX: wrap the raw TDX quote in base64. Collateral is fetched by verifier host, not attester.
fn build_tdx_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let quote_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "quote_b64": B64.encode(&quote_bytes),
    }))
}

/// iTrustee: AA returns a JSON object `{report, ima_log}`. Append the nonce field.
fn build_itrustee_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse itrustee AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

/// VirtCCA: AA returns a JSON object `{evidence, dev_cert, event_log}`. Append the nonce field.
fn build_virtcca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse virtcca AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

/// Current Unix timestamp in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
