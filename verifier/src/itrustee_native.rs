//! iTrustee host 端 evidence 字段提取。
//!
//! 完整验签依赖 libteeverifier.so FFI，当前构建环境不包含该库。
//! 本模块解析 report JSON 提取 TA 度量值，供 wasm appraiser 透传。
//! 部署环境中如有 libteeverifier.so，可在此接入 FFI 验签（参考 hydra/evidence-verify）。

use anyhow::{Context, Result};
use serde_json::Value;

/// 从 iTrustee evidence 中提取的 TA 度量值。
#[derive(Debug, Default)]
pub struct ItrusteeVerificationResult {
    pub uuid: Option<String>,
    pub ta_img: Option<String>,
    pub ta_mem: Option<String>,
    pub hash_alg: Option<String>,
    pub version: Option<String>,
}

/// 解析 evidence JSON，从 report 字段中提取 payload 信息。
///
/// evidence 格式（attester 封装后）：
/// ```json
/// { "report": "<JSON string>", "nonce": "...", "ima_log": null }
/// ```
///
/// report JSON 格式（iTrustee SDK 返回值）：
/// ```json
/// { "payload": { "uuid": "...", "ta_img": "...", "ta_mem": "...", ... } }
/// ```
pub fn extract_claims(evidence: &[u8]) -> Result<ItrusteeVerificationResult> {
    let ev: Value =
        serde_json::from_slice(evidence).context("parse itrustee evidence JSON")?;
    let report_str = ev
        .get("report")
        .and_then(|v| v.as_str())
        .context("evidence.report missing or not a string")?;
    let report: Value =
        serde_json::from_str(report_str).context("parse itrustee report JSON")?;
    let payload = report.get("payload");

    Ok(ItrusteeVerificationResult {
        uuid: payload.and_then(|p| p.get("uuid")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        ta_img: payload.and_then(|p| p.get("ta_img")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        ta_mem: payload.and_then(|p| p.get("ta_mem")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        hash_alg: payload.and_then(|p| p.get("hash_alg")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        version: payload.and_then(|p| p.get("version")).and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}
