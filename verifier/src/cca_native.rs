//! Host 端 CCA token 验签（参考 trustee deps/verifier/src/cca/local.rs）。
//!
//! 与 trustmee-artifact 一致：CCA 验签留在 host，wasm appraiser 仅做字段解析与 nonce 比对。
//! 使用 ccatoken crate 跑：CBOR 解码 + COSE-Sign1 验签 + IAK / RAK 链 + RV 比对。

use anyhow::{Context, Result, anyhow, bail};
use ccatoken::store::{MemoRefValueStore, MemoTrustAnchorStore};
use ccatoken::token::Evidence;
use ear::TrustTier;
use std::io::Cursor;
use tracing::warn;

use crate::config::CcaPolicy;

pub struct CcaVerifier {
    tas: MemoTrustAnchorStore,
    rvs: MemoRefValueStore,
}

impl CcaVerifier {
    pub fn load(policy: &CcaPolicy) -> Result<Option<Self>> {
        let (Some(ta), Some(rv)) = (policy.ta_store.as_ref(), policy.rv_store.as_ref()) else {
            return Ok(None);
        };
        let jta = std::fs::read_to_string(ta)
            .with_context(|| format!("read CCA TA store {}", ta.display()))?;
        let jrv = std::fs::read_to_string(rv)
            .with_context(|| format!("read CCA RV store {}", rv.display()))?;

        let mut tas = MemoTrustAnchorStore::default();
        tas.load_json(&jta)
            .map_err(|e| anyhow!("load CCA TA store: {e}"))?;
        let mut rvs = MemoRefValueStore::default();
        rvs.load_json(&jrv)
            .map_err(|e| anyhow!("load CCA RV store: {e}"))?;
        Ok(Some(Self { tas, rvs }))
    }

    /// 验 CCA token：签名链 + RAK attestation + RV 比对 + nonce 绑定。
    /// 返回原始 Evidence，调用方继续抽取 claims。
    pub fn verify(&self, token: &[u8], expected_report_data: &[u8]) -> Result<Evidence> {
        let cursor = Cursor::new(token.to_vec());
        let mut e = Evidence::decode(cursor).map_err(|err| anyhow!("decode CCA token: {err}"))?;

        e.verify(&self.tas)
            .map_err(|err| anyhow!("verify CCA evidence: {err}"))?;
        e.appraise(&self.rvs)
            .map_err(|err| anyhow!("appraise CCA evidence: {err}"))?;

        let (_platform_tvec, realm_tvec) = e.get_trust_vectors();
        if realm_tvec.instance_identity.tier() != TrustTier::Affirming {
            bail!("CCA RAK signature or RAK attestation could not be verified");
        }
        if expected_report_data != e.realm_claims.challenge {
            bail!("CCA realm token challenge does not match expected_report_data");
        }
        Ok(e)
    }
}

/// 没有信任锚配置的 fallback：跳过验签，仅记录日志。
/// 仅 demo / 联调可接受；生产必须配置 ta-store / rv-store。
pub fn warn_no_store(policy: &CcaPolicy) {
    if policy.ta_store.is_none() || policy.rv_store.is_none() {
        warn!(
            "CCA policy.ta_store / policy.rv_store not configured; \
             host-side CCA token verification skipped. DO NOT USE IN PRODUCTION."
        );
    }
}
