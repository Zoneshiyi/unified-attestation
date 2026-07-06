//! VirtCCA host 端 evidence 验证（预留）。
//!
//! 完整验签依赖 OpenSSL + cose + ciborium（CBOR/COSE 解码 + HW 证书链验证）。
//! 参考实现见 hydra/evidence-verify/src/virtcca/mod.rs。
//! 部署环境中如有 libvccaattestation.so + OpenSSL，可在此接入：
//!   1. CBOR Tag 399 解码 → CvmToken + PlatformToken
//!   2. 设备证书链验证（Huawei Root CA → Sub CA → dev_cert）
//!   3. CvmToken COSE-Sign1 验签 + challenge 绑定
//!   4. 参考值比对（RIM）
//!
//! 当前不做重签名验签，wasm appraiser 负责 nonce 绑定 + 字段透传。

use anyhow::Result;
use serde_json::Value;

/// 从 VirtCCA evidence 中提取的元数据。
#[derive(Debug, Default)]
pub struct VirtccaVerificationResult {
    pub token_size: usize,
    pub cert_size: usize,
    pub ima_log_size: Option<usize>,
    pub event_log_size: Option<usize>,
}

/// 解析 evidence JSON，提取二进制字段大小。
pub fn extract_claims(evidence: &[u8]) -> Result<VirtccaVerificationResult> {
    let ev: Value = serde_json::from_slice(evidence)?;
    Ok(VirtccaVerificationResult {
        token_size: ev.get("evidence").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        cert_size: ev.get("dev_cert").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        ima_log_size: ev.get("ima_log").and_then(|v| v.as_array()).map(|a| a.len()),
        event_log_size: ev.get("event_log").and_then(|v| v.as_array()).map(|a| a.len()),
    })
}
