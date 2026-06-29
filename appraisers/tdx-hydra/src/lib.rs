//! tdx + hydra 组合 appraiser
//!
//! 在 wasm 内同时校验 TDX 硬件证明与 hydra Groth16 证明，两者共用同一 nonce：
//! 任一层失败即拒收。
//!
//! Evidence schema（JSON，TDX 字段 + hydra 字段并集）：
//! ```text
//! {
//!   "quote_b64":         "<base64(TDX quote)>",
//!   "collateral_b64":    "<base64(serde_json::to_vec(QuoteCollateralV3))>",
//!   "now_secs":          1700000000,
//!   "vk_b64":            "<base64(VerifyingKey)>",
//!   "proof_b64":         "<base64(Groth16 Proof)>",
//!   "public_inputs_b64": "<base64(N × 32 字节 Fr 序列)>"
//! }
//! ```
//!
//! 校验顺序：
//! 1. dcap-qvl 完整链验签（TDX quote + collateral）
//! 2. quote.report_data[..32] == expected_report_data（challenge nonce 绑定）
//! 3. quote.mr_config_id == expected_init_data_hash（如 host 透传）
//! 4. hydra public_inputs 末位 == nonce_to_scalar(expected_report_data)
//! 5. Groth16 verify 通过
//!
//! 输出 claims：
//! - `tee_type`：固定 "tdx-hydra"
//! - `verification`：passed / failed
//! - TDX measurement / TCB 字段（同 tdx appraiser）
//! - `roots_hex`：whitelist root 列表（供 verifier policy 比对）

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

fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn err(msg: impl Into<String>) -> String {
    json!({"tee_type": "tdx-hydra", "verification": "failed", "error": msg.into()}).to_string()
}

fn evaluate_impl(
    evidence: Vec<u8>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> String {
    let report_data = match expected_report_data.as_deref() {
        Some(b) => b,
        None => return err("expected_report_data is required"),
    };

    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid evidence json: {e}")),
    };

    // 1. TDX 链验签
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

    // 2. TDX nonce 绑定（report_data 前 32 字节 == nonce，余位必须全 0）
    let cmp_len = report_data.len().min(td.report_data.len());
    if &td.report_data[..cmp_len] != report_data
        || td.report_data[cmp_len..].iter().any(|b| *b != 0)
    {
        return err("report_data does not match expected (challenge nonce)");
    }

    // 3. init_data_hash 绑定 mr_config_id
    if let Some(expected) = expected_init_data_hash {
        let cmp_len = expected.len().min(td.mr_config_id.len());
        if &td.mr_config_id[..cmp_len] != expected.as_slice() {
            return err("mr_config_id does not match expected_init_data_hash");
        }
    }

    // 4. hydra public inputs 解码 + nonce 绑定
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
    // public input 形态：[pk, root[0..N], output, time, period, challenge]
    // 5 = 非 root 槽数（pk / output / time / period / challenge），N >= 1
    if pi_count < 6 {
        return err("public_inputs too short for hydra schema");
    }
    let root_count = pi_count - 5;
    let roots_hex: Vec<String> = public_inputs[1..1 + root_count]
        .iter()
        .map(|fr| hex::encode(fr_to_bytes(fr)))
        .collect();

    let expected_challenge = nonce_to_scalar(report_data);
    if public_inputs.last() != Some(&expected_challenge) {
        return err("zk nonce mismatch in public_inputs");
    }

    // 5. Groth16 verify
    let ok = match verify_groth16(&vk_bytes, &proof_bytes, &public_inputs) {
        Ok(v) => v,
        Err(e) => return err(e),
    };

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
