//! Hygon CSV 验证组件
//!
//! 与 cca-appraiser 同形态：CSV 真验签由 verifier host 完成（依赖 csv-rs +
//! openssl，无法跨 wasm32），本组件仅做字段透传与 nonce 绑定校验。
//!
//! Evidence schema（JSON）：
//! ```text
//! {
//!   "csv_evidence_b64": "<base64(Hygon CSV evidence JSON,含 attestation_report + cert_chain + serial_number)>",
//!   "nonce": "<base64url nonce>"
//! }
//! ```
//!
//! claims：
//! - `tee_type`：固定 "csv"
//! - `verification`：passed / failed（基于 nonce 绑定）
//! - `nonce_bound`：bool
//! - `evidence_size`：原始 evidence 字节数

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct CsvEvidence {
    csv_evidence_b64: String,
    nonce: String,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let parsed: CsvEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("invalid evidence json: {e}")}).to_string(),
    };

    let csv_evidence = match base64::engine::general_purpose::STANDARD.decode(&parsed.csv_evidence_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("csv_evidence base64: {e}")}).to_string(),
    };

    let nonce_ok = match expected_report_data.as_deref() {
        Some(report_data) => {
            let expected_nonce =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(report_data);
            parsed.nonce == expected_nonce
        }
        None => false,
    };

    json!({
        "tee_type": "csv",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "evidence_size": csv_evidence.len(),
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
        let report_data = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report_data)
    }
}

export!(Component);
