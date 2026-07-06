//! Combined Hygon CSV + hydra appraiser.
//!
//! Same structure as cca-hydra. Real CSV signature verification is done by
//! the verifier host (csv-rs). This component performs:
//! 1. CSV evidence nonce binding (`nonce == base64url(expected_report_data)`)
//! 2. hydra public_inputs last element == nonce_to_scalar(expected_report_data)
//! 3. Groth16 verify
//!
//! Evidence schema (JSON, union of CSV and hydra fields):
//! ```text
//! {
//!   "csv_evidence_b64":  "<base64(Hygon CSV evidence JSON)>",
//!   "nonce":             "<base64url, same as the challenge>",
//!   "vk_b64":            "<base64(VerifyingKey)>",
//!   "proof_b64":         "<base64(Groth16 Proof)>",
//!   "public_inputs_b64": "<base64(N × 32-byte Fr sequence)>"
//! }
//! ```

use base64::Engine;
use hydra::{
    nonce::nonce_to_scalar,
    verify::{decode_public_inputs, fr_to_bytes, verify_groth16},
};
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct Evidence {
    csv_evidence_b64: String,
    nonce: String,
    vk_b64: String,
    proof_b64: String,
    public_inputs_b64: String,
}

/// Decode a standard base64 string, returning a String error on failure.
fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    // expected_report_data is required for this appraiser.
    let report_data = match expected_report_data.as_deref() {
        Some(b) => b,
        None => {
            return json!({"error": "expected_report_data is required"}).to_string();
        }
    };

    // Parse the evidence JSON.
    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("invalid evidence json: {e}")}).to_string(),
    };

    // ---- Step 1: CSV nonce binding ----
    let expected_nonce_b64url =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(report_data);
    if parsed.nonce != expected_nonce_b64url {
        return json!({
            "tee_type": "csv-hydra",
            "verification": "failed",
            "error": "csv nonce mismatch",
        })
        .to_string();
    }
    let csv_evidence = match b64(&parsed.csv_evidence_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("csv_evidence: {e}")}).to_string(),
    };

    // ---- Step 2: hydra public inputs decode + nonce binding ----
    let vk_bytes = match b64(&parsed.vk_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("vk: {e}")}).to_string(),
    };
    let proof_bytes = match b64(&parsed.proof_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("proof: {e}")}).to_string(),
    };
    let pi_bytes = match b64(&parsed.public_inputs_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("public_inputs: {e}")}).to_string(),
    };
    let public_inputs = match decode_public_inputs(&pi_bytes) {
        Ok(v) => v,
        Err(e) => return json!({"error": e}).to_string(),
    };
    let pi_count = public_inputs.len();
    // public input layout: [pk, root[0..N], output, time, period, challenge]
    // 5 = number of non-root slots (pk / output / time / period / challenge), N >= 1
    if pi_count < 6 {
        return json!({"error": "public_inputs too short for hydra schema"}).to_string();
    }
    let root_count = pi_count - 5;
    // Extract root hex digests (positions 1 through 1+root_count).
    let roots_hex: Vec<String> = public_inputs[1..1 + root_count]
        .iter()
        .map(|fr| hex::encode(fr_to_bytes(fr)))
        .collect();

    // Verify the last public input matches the challenge derived from report_data.
    let expected_challenge = nonce_to_scalar(report_data);
    if public_inputs.last() != Some(&expected_challenge) {
        return json!({
            "tee_type": "csv-hydra",
            "verification": "failed",
            "error": "zk nonce mismatch in public_inputs",
        })
        .to_string();
    }

    // ---- Step 3: Groth16 verify ----
    let ok = match verify_groth16(&vk_bytes, &proof_bytes, &public_inputs) {
        Ok(v) => v,
        Err(e) => return json!({"error": e}).to_string(),
    };

    // Extract subject from the evidence JSON root.
    let full: serde_json::Value =
        serde_json::from_slice(&evidence).unwrap_or(serde_json::Value::Null);
    let subject = full
        .get("chip_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Build claims with hydra verification details and CSV measurements.
    let mut claims = json!({
        "tee_type": "csv-hydra",
        "verification": if ok { "passed" } else { "failed" },
        "groth16": {
            "ok": ok,
            "public_input_count": pi_count,
            "vk_bytes": vk_bytes.len(),
            "proof_bytes": proof_bytes.len(),
        },
        "csv_evidence_size": csv_evidence.len(),
        "challenge_bound_in_public_input": true,
        "nonce_bound": true,
        "roots_hex": roots_hex,
        "subject": subject,
    });
    // Pass through host-injected CSV measurement fields.
    if let Some(obj) = claims.as_object_mut() {
        passthrough_csv(&full, obj, "chip_id");
        passthrough_csv(&full, obj, "measurement");
        passthrough_csv(&full, obj, "policy_nodbg");
        passthrough_csv(&full, obj, "policy_noks");
    }
    claims.to_string()
}

/// Copy a value from the evidence JSON root into claims, if present.
fn passthrough_csv(
    evidence: &serde_json::Value,
    claims: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    if let Some(v) = evidence.get(key) {
        claims.insert(key.to_string(), v.clone());
    }
}

struct Component;

impl Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        evidence: Vec<u8>,
        expected_report_data: OptionalData,
        _expected_init_data_hash: OptionalData,
    ) -> String {
        // Convert OptionalData enum to Option<Vec<u8>> for easier handling.
        let report_data = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report_data)
    }
}

export!(Component);
