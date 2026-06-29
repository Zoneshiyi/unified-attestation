//! TDX 验证组件（参考 trustmee-artifact tdx-verifier-component）。
//!
//! 在 wasm 内做 ECDSA + PCK 链 + Intel root CA + CRL + TCB + QE Identity
//! 完整 DCAP 验签。collateral 由 attester 端从 PCS/PCCS 拉取，随 evidence 一并提交。
//!
//! Evidence schema（JSON）：
//! ```text
//! {
//!   "quote_b64":      "<base64(TDX quote)>",
//!   "collateral_b64": "<base64(serde_json::to_vec(QuoteCollateralV3))>",
//!   "now_secs":       1700000000
//! }
//! ```
//!
//! 校验顺序：
//! 1. dcap-qvl 完整链验签（结果含 tcb_status / advisory_ids）
//! 2. quote.report_data[0..32] == expected_report_data（challenge nonce 绑定）
//! 3. quote.mr_config_id == expected_init_data_hash（如 host 透传）
//! 4. quote 字段（mr_td / mr_seam / rtmr0..3 / mr_config_id）回填 claims，
//!    供 verifier policy 比对

use base64::Engine;
use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::Quote;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct Evidence {
    quote_b64: String,
    collateral_b64: String,
    now_secs: u64,
}

fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn err(msg: impl Into<String>) -> String {
    json!({"tee_type": "tdx", "verification": "failed", "error": msg.into()}).to_string()
}

fn evaluate_impl(
    evidence: Vec<u8>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> String {
    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid evidence json: {e}")),
    };
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

    // 1. 完整 DCAP 链验签
    let verified = match dcap_qvl::verify::rustcrypto::verify(
        &quote_bin,
        &collateral,
        parsed.now_secs,
    ) {
        Ok(v) => v,
        Err(e) => return err(format!("dcap verify: {e:?}")),
    };

    // 2. 解 quote 拿 TD 字段（dcap-qvl 已经做完链验，这里只是抽字段）
    let quote = match Quote::parse(&quote_bin) {
        Ok(v) => v,
        Err(e) => return err(format!("parse quote: {e:?}")),
    };
    let td = match quote.report.as_td10() {
        Some(v) => v,
        None => return err("not a TDX quote"),
    };

    // 3. challenge nonce 绑定：report_data 前 32 字节
    if let Some(expected) = expected_report_data {
        let cmp_len = expected.len().min(td.report_data.len());
        if &td.report_data[..cmp_len] != expected.as_slice()
            || td.report_data[cmp_len..].iter().any(|b| *b != 0)
        {
            return err("report_data does not match expected (challenge nonce)");
        }
    }

    // 4. init_data_hash 绑定 mr_config_id（如 host 透传）
    if let Some(expected) = expected_init_data_hash {
        let cmp_len = expected.len().min(td.mr_config_id.len());
        if &td.mr_config_id[..cmp_len] != expected.as_slice() {
            return err("mr_config_id does not match expected_init_data_hash");
        }
    }

    json!({
        "tee_type": "tdx",
        "verification": "passed",
        "tcb_status": verified.status,
        "advisory_ids": verified.advisory_ids,
        "mr_td": hex::encode(td.mr_td),
        "mr_seam": hex::encode(td.mr_seam),
        "mr_signer_seam": hex::encode(td.mr_signer_seam),
        "mr_config_id": hex::encode(td.mr_config_id),
        "report_data": hex::encode(td.report_data),
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
