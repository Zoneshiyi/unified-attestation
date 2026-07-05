//! Host 端 CCA token 验签（参考 trustee deps/verifier/src/cca/local.rs）。
//!
//! 与 trustmee-artifact 一致：CCA 验签留在 host，wasm appraiser 仅做字段解析与 nonce 比对。
//! 使用 ccatoken crate 跑：CBOR 解码 + COSE-Sign1 验签 + IAK / RAK 链 + RV 比对。

use anyhow::{Context, Result, anyhow, bail};
use ccatoken::store::{MemoRefValueStore, MemoTrustAnchorStore};
use ccatoken::token::Evidence;
use ear::TrustTier;
use serde_json::Value;
use std::io::Cursor;
use tracing::warn;

use crate::config::CcaPolicy;

/// CCA 验证结果（含从 token 中提取的度量值）。
pub struct CcaVerificationResult {
    /// Realm Initial Measurement（hex）
    pub realm_initial_measurement: Option<String>,
    /// Realm Personalization Value（hex）
    pub realm_personalization_value: Option<String>,
    /// CCA Platform Instance ID（hex）
    pub cca_platform_instance_id: Option<String>,
    /// CCA Platform Implementation ID（hex）
    pub cca_platform_implementation_id: Option<String>,
    /// Platform lifecycle state ("secured" etc.)
    pub cca_platform_lifecycle: Option<String>,
    /// Platform software components
    pub cca_platform_sw_components: Option<Vec<Value>>,
}

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
    /// 返回结构化验证结果，含 realm claims 与 platform claims 中的关键度量值。
    pub fn verify(&self, token: &[u8], expected_report_data: &[u8]) -> Result<CcaVerificationResult> {
        let cursor = Cursor::new(token.to_vec());
        let mut e = Evidence::decode(cursor).map_err(|err| anyhow!("decode CCA token: {err}"))?;

        e.verify(&self.tas)
            .map_err(|err| anyhow!("verify CCA evidence: {err}"))?;
        e.appraise(&self.rvs)
            .map_err(|err| anyhow!("appraise CCA evidence: {err}"))?;

        let (_platform_tvec, realm_tvec) = e.get_trust_vectors();
        let passed = realm_tvec.instance_identity.tier() == TrustTier::Affirming;

        if !passed {
            bail!("CCA RAK signature or RAK attestation could not be verified");
        }
        if expected_report_data != e.realm_claims.challenge {
            bail!("CCA realm token challenge does not match expected_report_data");
        }

        let rim_hex = (!e.realm_claims.rim.is_empty())
            .then(|| hex::encode(&e.realm_claims.rim));
        let pv_hex = (!e.realm_claims.perso.is_empty())
            .then(|| hex::encode(&e.realm_claims.perso));

        let (plat_instance_id, plat_impl_id, plat_lifecycle, plat_sw_components) = {
            let pt = &e.platform_claims;
            let iid = Some(hex::encode(&pt.inst_id[..]));
            let impid = Some(hex::encode(&pt.impl_id[..]));
            let lc = match pt.lifecycle {
                0x6000 | 0x6001 => Some("secured".to_string()),
                0x3000 | 0x3001 => Some("recoverable".to_string()),
                0x0000..=0x00ff => Some("not_secured".to_string()),
                _ => Some(format!("0x{:04x}", pt.lifecycle)),
            };
            let sw: Option<Vec<Value>> = if pt.sw_components.is_empty() {
                None
            } else {
                Some(
                    pt.sw_components
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "measurement": hex::encode(&c.mval),
                                "signer_id": hex::encode(&c.signer_id),
                                "measurement_type": c.mtyp,
                                "version": c.version,
                            })
                        })
                        .collect(),
                )
            };
            (iid, impid, lc, sw)
        };

        Ok(CcaVerificationResult {
            realm_initial_measurement: rim_hex,
            realm_personalization_value: pv_hex,
            cca_platform_instance_id: plat_instance_id,
            cca_platform_implementation_id: plat_impl_id,
            cca_platform_lifecycle: plat_lifecycle,
            cca_platform_sw_components: plat_sw_components,
        })
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
