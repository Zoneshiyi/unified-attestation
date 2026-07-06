//! iTrustee 验证组件
//!
//! iTrustee 真验签依赖 native libteeverifier.so，wasm 内不做重签名验签。
//! 本组件校验 nonce 绑定，从 report JSON 中提取 TA 度量值，并透传 host 端注入的验证结果。
//!
//! Evidence schema（attester 封装后）：
//! ```text
//! {
//!   "report": "<JSON 字符串，来自 iTrustee SDK RemoteAttest 返回值>",
//!   "nonce": "<base64url nonce>",
//!   "ima_log": [<可选，IMA 日志字节数组>]
//! }
//! ```
//!
//! host 端验证通过后会注入以下字段到 evidence JSON 根层：
//! - `itrustee_uuid`：TA UUID
//! - `itrustee_ta_img`：TA 镜像度量值（hex）
//! - `itrustee_ta_mem`：TA 内存度量值（hex）
//! - `itrustee_hash_alg`：哈希算法
//! - `itrustee_version`：TA 版本号
//!
//! claims：
//! - `tee_type`：固定 "itrustee"
//! - `verification`：passed / failed（基于 nonce 绑定）
//! - `nonce_bound`：bool
//! - `uuid` / `ta_img` / `ta_mem` / `hash_alg` / `version` / `ima_log_size`：从 evidence 提取

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct ItrusteeEvidence {
    report: String,
    nonce: String,
    #[serde(default)]
    ima_log: Option<Vec<u8>>,
    // host 端注入字段（可选）
    #[serde(default)]
    itrustee_uuid: Option<String>,
    #[serde(default)]
    itrustee_ta_img: Option<String>,
    #[serde(default)]
    itrustee_ta_mem: Option<String>,
    #[serde(default)]
    itrustee_hash_alg: Option<String>,
    #[serde(default)]
    itrustee_version: Option<String>,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    let parsed: ItrusteeEvidence = match serde_json::from_slice(&evidence) {
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

    // 优先用 host 端注入值，否则从 report JSON 中提取
    let (uuid, ta_img, ta_mem, hash_alg, version) = if parsed.itrustee_uuid.is_some() {
        (
            parsed.itrustee_uuid.unwrap_or_default(),
            parsed.itrustee_ta_img,
            parsed.itrustee_ta_mem,
            parsed.itrustee_hash_alg,
            parsed.itrustee_version,
        )
    } else {
        let report: serde_json::Value =
            serde_json::from_str(&parsed.report).unwrap_or(serde_json::Value::Null);
        let payload = report.get("payload");
        (
            payload
                .and_then(|p| p.get("uuid"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            payload
                .and_then(|p| p.get("ta_img"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("ta_mem"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("hash_alg"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        )
    };

    let ima_log_size = parsed.ima_log.as_ref().map(|v| v.len());

    let mut claims = json!({
        "tee_type": "itrustee",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "uuid": uuid,
    });
    if let Some(obj) = claims.as_object_mut() {
        if let Some(ref v) = ta_img {
            obj.insert("ta_img".into(), v.clone().into());
        }
        if let Some(ref v) = ta_mem {
            obj.insert("ta_mem".into(), v.clone().into());
        }
        if let Some(ref v) = hash_alg {
            obj.insert("hash_alg".into(), v.clone().into());
        }
        if let Some(ref v) = version {
            obj.insert("version".into(), v.clone().into());
        }
        if let Some(sz) = ima_log_size {
            obj.insert("ima_log_size".into(), sz.into());
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
