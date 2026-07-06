//! VirtCCA 验证组件
//!
//! VirtCCA 真验签依赖原生 OpenSSL + CBOR/COSE 证书链（Huawei Root CA），
//! wasm 内不做重签名验签。本组件校验 nonce 绑定并透传 host 端注入的验证结果。
//!
//! Evidence schema（attester 封装后）：
//! ```text
//! {
//!   "evidence": [<CBOR/COSE token 字节数组>],
//!   "dev_cert": [<设备证书 DER 字节数组>],
//!   "nonce": "<base64url nonce>",
//!   "ima_log": [<可选>],
//!   "event_log": [<可选>]
//! }
//! ```
//!
//! host 端验证通过后会注入以下字段到 evidence JSON 根层：
//! - `virtcca_rim`：RIM（hex）
//! - `virtcca_rpv`：RPV（hex）
//! - `virtcca_challenge`：challenge（hex）
//! - `virtcca_is_platform`：是否有 platform token
//! - `virtcca_platform_sw_components`：平台软件组件列表
//!
//! claims：
//! - `tee_type`：固定 "virtcca"
//! - `verification`：passed / failed（基于 nonce 绑定）
//! - `nonce_bound`：bool
//! - `token_size` / `cert_size` / `ima_log_size` / `event_log_size`：字节大小

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct VirtccaEvidence {
    evidence: Vec<u8>,
    dev_cert: Vec<u8>,
    nonce: String,
    #[serde(default)]
    ima_log: Option<Vec<u8>>,
    #[serde(default)]
    event_log: Option<Vec<u8>>,
    // host 端注入字段（可选）
    #[serde(default)]
    virtcca_rim: Option<String>,
    #[serde(default)]
    virtcca_rpv: Option<String>,
    #[serde(default)]
    virtcca_challenge: Option<String>,
    #[serde(default)]
    virtcca_is_platform: Option<bool>,
    #[serde(default)]
    virtcca_platform_sw_components: Option<serde_json::Value>,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let parsed: VirtccaEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("invalid evidence json: {e}")}).to_string();
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

    let token_size = parsed.evidence.len();
    let cert_size = parsed.dev_cert.len();
    let ima_log_size = parsed.ima_log.as_ref().map(|v| v.len());
    let event_log_size = parsed.event_log.as_ref().map(|v| v.len());

    let mut claims = json!({
        "tee_type": "virtcca",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "token_size": token_size,
        "cert_size": cert_size,
    });
    if let Some(obj) = claims.as_object_mut() {
        if let Some(ref v) = parsed.virtcca_rim {
            obj.insert("rim".into(), v.clone().into());
        }
        if let Some(ref v) = parsed.virtcca_rpv {
            obj.insert("rpv".into(), v.clone().into());
        }
        if let Some(ref v) = parsed.virtcca_challenge {
            obj.insert("challenge_hex".into(), v.clone().into());
        }
        if let Some(v) = parsed.virtcca_is_platform {
            obj.insert("is_platform".into(), v.into());
        }
        if let Some(ref v) = parsed.virtcca_platform_sw_components {
            obj.insert("platform_sw_components".into(), v.clone());
        }
        if let Some(sz) = ima_log_size {
            obj.insert("ima_log_size".into(), sz.into());
        }
        if let Some(sz) = event_log_size {
            obj.insert("event_log_size".into(), sz.into());
        }
    }
    claims.to_string()
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
