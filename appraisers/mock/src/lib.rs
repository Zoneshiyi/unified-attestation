//! Mock 验证组件。打通 host ↔ component 链路用，不做真实校验。
//!
//! 行为：
//! - 解析 evidence JSON，提取若干字段
//! - 把 expected_report_data 原样转发到 claims 中
//! - 永远返回 verification = passed

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Default, Deserialize)]
struct MockEvidence {
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    issued_at: i64,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let parsed: MockEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            return json!({ "error": format!("invalid evidence json: {e}") }).to_string();
        }
    };

    let challenge_b64 = expected_report_data
        .as_deref()
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
        .unwrap_or_default();

    json!({
        "tee_type": "mock",
        "verification": "passed",
        "payload": parsed.payload,
        "challenge_binding_data": challenge_b64,
        "issued_at": parsed.issued_at,
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
        _expected_init_data_hash: OptionalData,
    ) -> String {
        let expected_report_data = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, expected_report_data)
    }
}

export!(Component);
