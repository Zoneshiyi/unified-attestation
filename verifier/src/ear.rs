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

/// EAR 顶层 claims。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarClaims {
    pub iss: String,
    pub iat: i64,
    /// 可选过期时间
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub eat_nonce: String,
    pub tee_type: String,
    pub component_id: String,
    /// wasm 组件返回的 claims map（已剔除 error 字段）
    pub submods: Value,
    /// 可信向量：实例身份 / 配置 / 可执行文件
    pub trust_vector: TrustVector,
    /// 发行者元数据
    pub verifier_id: VerifierId,
    /// EAT profile 标识
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eat_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierId {
    pub developer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVector {
    pub instance_identity: i32,
    pub configuration: i32,
    pub executables: i32,
}

impl TrustVector {
    pub fn new(instance_identity: i32, configuration: i32, executables: i32) -> Self {
        Self { instance_identity, configuration, executables }
    }

    /// 全部维度置为 affirming（=2）。
    pub fn affirming() -> Self {
        Self { instance_identity: 2, configuration: 2, executables: 2 }
    }
}
