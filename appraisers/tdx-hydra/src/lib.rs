//! Combined TDX + hydra appraiser.
//!
//! Validates both the TDX hardware attestation and the hydra Groth16 proof
//! inside wasm, using the same nonce for both. If either layer fails, the
//! evidence is rejected.
//!
//! Evidence schema (JSON, union of TDX and hydra fields):
//! ```text
//! {
//!   "quote_b64":         "<base64(TDX quote)>",
//!   "collateral_b64":    "<base64(serde_json::to_vec(QuoteCollateralV3))>",
//!   "now_secs":          1700000000,
//!   "vk_b64":            "<base64(VerifyingKey)>",
//!   "proof_b64":         "<base64(Groth16 Proof)>",
//!   "public_inputs_b64": "<base64(N × 32-byte Fr sequence)>"
//! }
//! ```
//!
//! Verification order:
//! 1. dcap-qvl full chain verification (TDX quote + collateral)
//! 2. quote.report_data[..32] == expected_report_data (challenge nonce binding)
//! 3. quote.mr_config_id == expected_init_data_hash (if passed through by host)
//! 4. hydra public_inputs last element == nonce_to_scalar(expected_report_data)
//! 5. Groth16 verify passes
//!
//! Output claims:
//! - `tee_type`: always "tdx-hydra"
//! - `verification`: passed / failed
//! - TDX measurement / TCB fields (same as tdx appraiser)
//! - `roots_hex`: whitelist root list (for verifier policy comparison)

use base64::Engine;
use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::Quote;
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

use exports::unified_attestation::verifier::verifier_interface::{
    Guest, GuestVerifier, OptionalData,
};

#[derive(Debug, Deserialize)]
struct Evidence {
    quote_b64: String,
    collateral_b64: String,
    now_secs: u64,
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

/// Build a "failed" claims JSON with the given error message.
fn err(msg: impl Into<String>) -> String {
    json!({"tee_type": "tdx-hydra", "verification": "failed", "error": msg.into()}).to_string()
}

fn evaluate_impl(
    evidence: Vec<u8>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> String {
    // expected_report_data is required for this appraiser.
    let report_data = match expected_report_data.as_deref() {
        Some(b) => b,
        None => return err("expected_report_data is required"),
    };

    // Parse the evidence JSON.
    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid evidence json: {e}")),
    };

    // ---- Step 1: TDX chain verification ----
    let quote_bin = match b64(&parsed.quote_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("quote: {e}")),
    };
    let collateral_bin = match b64(&parsed.collateral_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("collateral: {e}")),
    };
    let collateral: QuoteCollateralV3 = match serde_json::from_slice(&collateral_bin) {
        Ok(v) => v,
        Err(e) => return err(format!("collateral parse: {e}")),
    };
    let verified =
        match dcap_qvl::verify::rustcrypto::verify(&quote_bin, &collateral, parsed.now_secs) {
            Ok(v) => v,
            Err(e) => return err(format!("dcap verify: {e:?}")),
        };
    let quote = match Quote::parse(&quote_bin) {
        Ok(v) => v,
        Err(e) => return err(format!("parse quote: {e:?}")),
    };
    let td = match quote.report.as_td10() {
        Some(v) => v,
        None => return err("not a TDX quote"),
    };

    // ---- Step 2: TDX nonce binding (first 32 bytes of report_data == nonce, rest must be zero) ----
    let cmp_len = report_data.len().min(td.report_data.len());
    if &td.report_data[..cmp_len] != report_data
        || td.report_data[cmp_len..].iter().any(|b| *b != 0)
    {
        return err("report_data does not match expected (challenge nonce)");
    }

    // ---- Step 3: init_data_hash binding against mr_config_id ----
    if let Some(expected) = expected_init_data_hash {
        let cmp_len = expected.len().min(td.mr_config_id.len());
        if &td.mr_config_id[..cmp_len] != expected.as_slice() {
            return err("mr_config_id does not match expected_init_data_hash");
        }
    }

    // ---- Step 4: hydra public inputs decode + nonce binding ----
    let vk_bytes = match b64(&parsed.vk_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("vk: {e}")),
    };
    let proof_bytes = match b64(&parsed.proof_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("proof: {e}")),
    };
    let pi_bytes = match b64(&parsed.public_inputs_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("public_inputs: {e}")),
    };
    let public_inputs = match decode_public_inputs(&pi_bytes) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let pi_count = public_inputs.len();
    // public input layout: [pk, root[0..N], output, time, period, challenge]
    // 5 = number of non-root slots (pk / output / time / period / challenge), N >= 1
    if pi_count < 6 {
        return err("public_inputs too short for hydra schema");
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
        return err("zk nonce mismatch in public_inputs");
    }

    // ---- Step 5: Groth16 verify ----
    let ok = match verify_groth16(&vk_bytes, &proof_bytes, &public_inputs) {
        Ok(v) => v,
        Err(e) => return err(e),
    };

    // Build passed claims with TDX and hydra verification details.
    json!({
        "tee_type": "tdx-hydra",
        "verification": if ok { "passed" } else { "failed" },
        "tcb_status": verified.status,
        "advisory_ids": verified.advisory_ids,
        "mr_td": hex::encode(td.mr_td),
        "mr_seam": hex::encode(td.mr_seam),
        "mr_signer_seam": hex::encode(td.mr_signer_seam),
        "mr_config_id": hex::encode(td.mr_config_id),
        "report_data": hex::encode(td.report_data),
        "groth16": {
            "ok": ok,
            "public_input_count": pi_count,
        },
        "roots_hex": roots_hex,
    })
    .to_string()
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
        expected_init_data_hash: OptionalData,
    ) -> String {
        // Convert both OptionalData enums to Option<Vec<u8>> for easier handling.
        let report = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        let init = match expected_init_data_hash {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report, init)
    }
}

export!(Component);
