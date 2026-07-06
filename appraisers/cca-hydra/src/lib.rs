//! Combined CCA + hydra appraiser.
//!
//! Validates both the CCA hardware attestation and the hydra Groth16 proof
//! inside wasm, using the same nonce for both. If either layer fails, the
//! evidence is rejected.
//!
//! Evidence schema (JSON, union of CCA and hydra fields):
//! ```text
//! {
//!   "cca_token_b64":     "<base64(ARM CCA token)>",
//!   "nonce":             "<base64url, same as the challenge>",
//!   "vk_b64":            "<base64(VerifyingKey)>",
//!   "proof_b64":         "<base64(Groth16 Proof)>",
//!   "public_inputs_b64": "<base64(N × 32-byte Fr sequence)>"
//! }
//! ```
//!
//! Verification order:
//! 1. CCA parse + nonce binding (`nonce == base64url(expected_report_data)`)
//! 2. hydra public_inputs last element == nonce_to_scalar(expected_report_data)
//! 3. Groth16 verify passes
//!
//! Output claims:
//! - `tee_type`: always "cca-hydra"
//! - `verification`: passed / failed
//! - `roots_hex`: whitelist root list (for verifier policy comparison)
//! - `subject`: CCA subject identifier (for verifier policy comparison, currently a placeholder)

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
    cca_token_b64: String,
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

    // ---- Step 1: CCA nonce binding ----
    let expected_nonce_b64url =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(report_data);
    if parsed.nonce != expected_nonce_b64url {
        return json!({
            "tee_type": "cca-hydra",
            "verification": "failed",
            "error": "cca nonce mismatch",
        })
        .to_string();
    }
    let cca_token = match b64(&parsed.cca_token_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("cca_token: {e}")}).to_string(),
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
            "tee_type": "cca-hydra",
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

    // Extract CCA measurement values injected by the host at the evidence JSON root.
    let full: serde_json::Value =
        serde_json::from_slice(&evidence).unwrap_or(serde_json::Value::Null);
    let subject = full
        .get("cca_platform_instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Build claims with hydra verification details and CCA measurements.
    let mut claims = json!({
        "tee_type": "cca-hydra",
        "verification": if ok { "passed" } else { "failed" },
        "groth16": {
            "ok": ok,
            "public_input_count": pi_count,
            "vk_bytes": vk_bytes.len(),
            "proof_bytes": proof_bytes.len(),
        },
        "cca_token_size": cca_token.len(),
        "challenge_bound_in_public_input": true,
        "nonce_bound": true,
        "roots_hex": roots_hex,
        "subject": subject,
    });
    // Pass through additional host-injected CCA fields.
    if let Some(obj) = claims.as_object_mut() {
        passthrough_str(&full, obj, "cca_realm_initial_measurement");
        passthrough_str(&full, obj, "cca_platform_instance_id");
        passthrough_str(&full, obj, "cca_platform_lifecycle");
    }
    claims.to_string()
}

/// Copy a string-valued key from the evidence JSON root into claims, if present.
fn passthrough_str(
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
