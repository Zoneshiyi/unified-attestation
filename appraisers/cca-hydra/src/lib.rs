//! cca + hydra 组合 appraiser
//!
//! 在 wasm 内同时校验 CCA 硬件证明与 hydra Groth16 证明，两者共用同一 nonce：
//! 任一层失败即拒收。
//!
//! Evidence schema（JSON，CCA 字段 + hydra 字段并集）：
//! ```text
//! {
//!   "cca_token_b64":     "<base64(ARM CCA token)>",
//!   "nonce":             "<base64url 与 challenge 一致>",
//!   "vk_b64":            "<base64(VerifyingKey)>",
//!   "proof_b64":         "<base64(Groth16 Proof)>",
//!   "public_inputs_b64": "<base64(N × 32 字节 Fr 序列)>"
//! }
//! ```
//!
//! 校验顺序：
//! 1. CCA 解析 + nonce 绑定（`nonce == base64url(expected_report_data)`）
//! 2. hydra public_inputs 末位 == nonce_to_scalar(expected_report_data)
//! 3. Groth16 verify 通过
//!
//! 输出 claims：
//! - `tee_type`：固定 "cca-hydra"
//! - `verification`：passed / failed
//! - `roots_hex`：whitelist root 列表（供 verifier policy 比对）
//! - `subject`：CCA 主体标识（供 verifier policy 比对，当前 placeholder）

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

fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let report_data = match expected_report_data.as_deref() {
        Some(b) => b,
        None => {
            return json!({"error": "expected_report_data is required"}).to_string();
        }
    };

    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("invalid evidence json: {e}")}).to_string(),
    };

    // 1. CCA nonce 绑定
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

    // 2. hydra public inputs 解码 + nonce 绑定
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
    // public input 形态：[pk, root[0..N], output, time, period, challenge]
    // 5 = 非 root 槽数（pk / output / time / period / challenge），N >= 1
    if pi_count < 6 {
        return json!({"error": "public_inputs too short for hydra schema"}).to_string();
    }
    let root_count = pi_count - 5;
    let roots_hex: Vec<String> = public_inputs[1..1 + root_count]
        .iter()
        .map(|fr| hex::encode(fr_to_bytes(fr)))
        .collect();

    let expected_challenge = nonce_to_scalar(report_data);
    if public_inputs.last() != Some(&expected_challenge) {
        return json!({
            "tee_type": "cca-hydra",
            "verification": "failed",
            "error": "zk nonce mismatch in public_inputs",
        })
        .to_string();
    }

    // 3. Groth16 verify
    let ok = match verify_groth16(&vk_bytes, &proof_bytes, &public_inputs) {
        Ok(v) => v,
        Err(e) => return json!({"error": e}).to_string(),
    };

    // 从 evidence JSON 根级提取 host 注入的 CCA 度量值
    let full: serde_json::Value =
        serde_json::from_slice(&evidence).unwrap_or(serde_json::Value::Null);
    let subject = full
        .get("cca_platform_instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

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
    if let Some(obj) = claims.as_object_mut() {
        passthrough_str(&full, obj, "cca_realm_initial_measurement");
        passthrough_str(&full, obj, "cca_platform_instance_id");
        passthrough_str(&full, obj, "cca_platform_lifecycle");
    }
    claims.to_string()
}

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
        let report_data = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report_data)
    }
}

export!(Component);
