//! EAR 输出。
//!
//! 输出 JWT 形式的 EAR：自定义 claims + ES256 签名。

use crate::config::EarConfig;
use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub struct SigningContext {
    encoding_key: EncodingKey,
}

impl SigningContext {
    pub fn new(cfg: &EarConfig) -> Result<Self> {
        let pem = std::fs::read(&cfg.signing_key_path)
            .with_context(|| format!("read signing key {}", cfg.signing_key_path.display()))?;
        let encoding_key =
            EncodingKey::from_ec_pem(&pem).context("parse signing key as EC PEM (ES256)")?;
        Ok(Self { encoding_key })
    }

    pub fn sign(&self, claims: EarClaims) -> Result<String> {
        let header = Header::new(Algorithm::ES256);
        encode(&header, &claims, &self.encoding_key).context("encode JWT")
    }
}

/// EAR 顶层 claims（简化版）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarClaims {
    pub iss: String,
    pub iat: i64,
    pub eat_nonce: String,
    pub tee_type: String,
    pub component_id: String,
    /// wasm 组件返回的 claims map（已剔除 error 字段）。
    pub submods: Value,
    /// 简化的可信向量。当前只表达 verification = passed/failed。
    pub trust_vector: TrustVector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVector {
    pub instance_identity: i32,
    pub configuration: i32,
    pub executables: i32,
}

impl TrustVector {
    /// 全部维度置为 affirming（=2，AR4SI 中"主张可信"）。
    /// RP 通过 `executables >= 2` 接受 EAR；任一维度低于 2 则视为不可信。
    /// 当前 demo 一旦走完 wasm appraiser + policy 就直接给 affirming，
    /// 真实部署中应根据 wasm 组件返回的 trust_vector 字段细化。
    pub fn affirming() -> Self {
        Self {
            instance_identity: 2,
            configuration: 2,
            executables: 2,
        }
    }
}
