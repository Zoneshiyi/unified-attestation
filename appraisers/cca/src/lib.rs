//! CCA 验证组件
//!
//! 解析 attester 提交的 CCA evidence，校验 nonce 绑定，返回 claims 供 verifier policy 比对。
//!
//! Evidence schema（JSON）：
//! ```text
//! {
//!   "cca_token_b64": "<base64(ARM CCA 硬件签名 attestation token)>",
//!   "nonce": "<base64url nonce，与 challenge 一致>"
//! }
//! ```
//!
//! 组件输出的 claims：
//! - `tee_type`：固定 "cca"
//! - `verification`：nonce 校验结果（passed / failed）
//! - `nonce_bound`：nonce 是否成功绑定
//! - `token_size`：CCA token 字节数（供排查）

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct CcaEvidence {
    cca_token_b64: String,
    nonce: String,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let parsed: CcaEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("invalid evidence json: {e}")}).to_string();
        }
    };

    let cca_token = match base64::engine::general_purpose::STANDARD.decode(&parsed.cca_token_b64) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("cca_token base64: {e}")}).to_string();
        }
    };

    let nonce_ok = match expected_report_data.as_deref() {
        Some(report_data) => {
            let expected_nonce =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(report_data);
            parsed.nonce == expected_nonce
        }
        None => false,
    };

    // 透传 host 端已注入的 CCA 度量值（从 evidence JSON 根级字段读取）
    let full: serde_json::Value = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Null,
    };

    let mut claims = json!({
        "tee_type": "cca",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "token_size": cca_token.len(),
    });
    if let Some(obj) = claims.as_object_mut() {
        passthrough(&full, obj, "cca_realm_initial_measurement");
        passthrough(&full, obj, "cca_realm_personalization_value");
        passthrough(&full, obj, "cca_platform_instance_id");
        passthrough(&full, obj, "cca_platform_implementation_id");
        passthrough(&full, obj, "cca_platform_lifecycle");
        passthrough(&full, obj, "cca_platform_sw_components");
    }
    claims.to_string()
}

/// 从 evidence JSON 根级读取 key，如存在则写入 claims。
fn passthrough(
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
