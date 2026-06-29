//! tonic gRPC 实现：VerifierService.Verify。

use crate::cca_native::CcaVerifier;
use crate::config::{CcaPolicy, HydraZkPolicy, TdxPolicy};
use crate::csv_native::CsvVerifier;
use crate::ear::{EarClaims, SigningContext, TrustVector};
use crate::wasm_host::WasmHost;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use protos::verifier_service_server::VerifierService;
use protos::verify_request::Wasm;
use protos::{TeeType, VerifyRequest, VerifyResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct AppState {
    pub host: Arc<WasmHost>,
    pub signing: SigningContext,
    pub hydra_policy: HydraZkPolicy,
    pub cca_policy: CcaPolicy,
    pub tdx_policy: TdxPolicy,
    pub cca_verifier: Option<CcaVerifier>,
    pub csv_verifier: Option<CsvVerifier>,
}

#[tonic::async_trait]
impl VerifierService for AppState {
    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = req.into_inner();
        let tee = TeeType::try_from(req.tee_type)
            .map_err(|_| Status::invalid_argument("invalid tee_type"))?;
        if matches!(tee, TeeType::Unspecified) {
            return Err(Status::invalid_argument("tee_type unspecified"));
        }
        if req.nonce.is_empty() {
            return Err(Status::invalid_argument("nonce required"));
        }

        // 1. 解析 / 加载 wasm 组件
        let component_id = match req.wasm {
            Some(Wasm::WasmComponent(bytes)) => self
                .host
                .register(&bytes)
                .await
                .map_err(|e| Status::invalid_argument(format!("component rejected: {e}")))?,
            Some(Wasm::WasmComponentId(id)) => id,
            None => return Err(Status::invalid_argument("wasm required")),
        };

        // 2. host 端 CCA / CSV 真验签
        if matches!(tee, TeeType::Cca | TeeType::CcaHydra) {
            if let Some(verifier) = &self.cca_verifier {
                let cca_token = extract_b64_field(&req.evidence, "cca_token_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract cca token: {e}")))?;
                // CCA realm challenge 字段固定 64 字节，不足右补 0；attester 端送 32B nonce 后必须补齐
                let mut padded = req.nonce.clone();
                padded.resize(64, 0);
                verifier.verify(&cca_token, &padded).map_err(|e| {
                    warn!(error = %e, "cca host verify failed");
                    Status::invalid_argument(format!("cca verify failed: {e}"))
                })?;
                info!("cca host verify passed");
            }
        }
        if matches!(tee, TeeType::Csv | TeeType::CsvHydra) {
            if let Some(verifier) = &self.csv_verifier {
                let csv_evidence = extract_b64_field(&req.evidence, "csv_evidence_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract csv evidence: {e}")))?;
                verifier
                    .verify(&csv_evidence, &req.nonce)
                    .map_err(|e| Status::invalid_argument(format!("csv verify failed: {e}")))?;
            }
        }

        // 3. TDX：host 端按 fmspc 拉 collateral 注入 evidence。wasm appraiser 拿到的
        //    evidence 与原方案一致（quote_b64 + collateral_b64 + now_secs），无需改动。
        let evidence_for_wasm = if matches!(tee, TeeType::Tdx | TeeType::TdxHydra) {
            inject_tdx_collateral(&req.evidence, &self.tdx_policy.pccs_url)
                .await
                .map_err(|e| {
                    warn!(error = %e, "fetch tdx collateral failed");
                    Status::internal(format!("fetch collateral: {e}"))
                })?
        } else {
            req.evidence.clone()
        };

        // 4. wasm appraiser
        // expected_init 只取 trusted_mr_config_id_hex 列表里的"第一项"作为 init_data_hash 透传：
        // wasm appraiser 对 init_data_hash 是 1:1 强等比对，多值候选无意义；
        // 列表余项最终在下面 enforce_tdx_policy 的 mr_config_id 白名单里做 OR 匹配
        let expected_init = matches!(tee, TeeType::Tdx | TeeType::TdxHydra)
            .then(|| self.tdx_policy.trusted_mr_config_id_hex.first())
            .flatten()
            .and_then(|s| hex::decode(s).ok());
        let outcome = self
            .host
            .evaluate(
                &component_id,
                &evidence_for_wasm,
                Some(&req.nonce),
                expected_init.as_deref(),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "wasm evaluate failed");
                Status::invalid_argument(format!("evidence rejected: {e}"))
            })?;

        // 5. policy
        let tee_kind_str = tee_type_str(tee);
        let claim_tee = outcome
            .claims
            .get("tee_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if claim_tee != tee_kind_str {
            return Err(Status::invalid_argument(format!(
                "tee_type mismatch: request={tee_kind_str}, claim={claim_tee}"
            )));
        }

        match tee {
            // host 端已完成 CSV 链验签，appraiser 不需要再 policy。
            TeeType::Unspecified | TeeType::Mock | TeeType::Csv => {}
            TeeType::Cca => {
                enforce_cca_policy(&self.cca_policy, &outcome.claims).map_err(|e| {
                    warn!(error = %e, "cca policy mismatch");
                    Status::invalid_argument(e)
                })?;
            }
            TeeType::CcaHydra => {
                enforce_cca_policy(&self.cca_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("cca-hydra: {e}")))?;
                enforce_hydra_policy(&self.hydra_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("cca-hydra: {e}")))?;
            }
            TeeType::CsvHydra => {
                enforce_hydra_policy(&self.hydra_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("csv-hydra: {e}")))?;
            }
            TeeType::Tdx => {
                enforce_tdx_policy(&self.tdx_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("tdx: {e}")))?;
            }
            TeeType::TdxHydra => {
                enforce_tdx_policy(&self.tdx_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("tdx-hydra: {e}")))?;
                enforce_hydra_policy(&self.hydra_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("tdx-hydra: {e}")))?;
            }
        }

        // 6. 签 EAR。eat_nonce 用 RP nonce 的 base64url no-pad 文本表示，便于 RP 文本比对。
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&req.nonce);
        let claims = EarClaims {
            iss: "unified-attestation-verifier".to_string(),
            iat: now_secs(),
            eat_nonce: nonce_b64,
            tee_type: tee_kind_str.to_string(),
            component_id: outcome.component_id.clone(),
            submods: outcome.claims,
            trust_vector: TrustVector::affirming(),
        };
        let ear = self
            .signing
            .sign(claims)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(VerifyResponse {
            ear,
            wasm_component_id: outcome.component_id,
        }))
    }
}

fn tee_type_str(t: TeeType) -> &'static str {
    match t {
        TeeType::Unspecified => "unspecified",
        TeeType::Mock => "mock",
        TeeType::Cca => "cca",
        TeeType::CcaHydra => "cca-hydra",
        TeeType::Csv => "csv",
        TeeType::CsvHydra => "csv-hydra",
        TeeType::Tdx => "tdx",
        TeeType::TdxHydra => "tdx-hydra",
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn extract_b64_field(evidence: &[u8], key: &str) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(evidence).map_err(|e| format!("evidence json: {e}"))?;
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("evidence.{key} missing"))?;
    B64.decode(s).map_err(|e| format!("{key} base64: {e}"))
}

/// host 端按 fmspc 从 PCS/PCCS 拉 collateral，写回 evidence JSON。
/// wasm appraiser 不感知拉取过程，拿到的 evidence 形态与"attester 拉"方案一致。
async fn inject_tdx_collateral(evidence: &[u8], pccs_url: &str) -> Result<Vec<u8>, String> {
    let mut v: serde_json::Value =
        serde_json::from_slice(evidence).map_err(|e| format!("evidence json: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "evidence root must be object".to_string())?;

    let quote_b64 = obj
        .get("quote_b64")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "evidence.quote_b64 missing".to_string())?;
    let quote_bytes = B64
        .decode(quote_b64)
        .map_err(|e| format!("quote_b64 base64: {e}"))?;

    let collateral = dcap_qvl::collateral::get_collateral(pccs_url, &quote_bytes)
        .await
        .map_err(|e| format!("get_collateral: {e}"))?;
    let collateral_bin =
        serde_json::to_vec(&collateral).map_err(|e| format!("serialize collateral: {e}"))?;

    obj.insert(
        "collateral_b64".to_string(),
        serde_json::Value::String(B64.encode(&collateral_bin)),
    );
    obj.insert(
        "now_secs".to_string(),
        serde_json::Value::Number(serde_json::Number::from(now_secs())),
    );
    serde_json::to_vec(&v).map_err(|e| format!("serialize evidence: {e}"))
}

fn enforce_cca_policy(policy: &CcaPolicy, claims: &serde_json::Value) -> Result<(), String> {
    if policy.trusted_subjects.is_empty() {
        warn!("cca policy.trusted_subjects is empty; skipping realm binding");
        return Ok(());
    }
    let subject = claims
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "claims.subject missing".to_string())?;
    if !policy.trusted_subjects.iter().any(|s| s == subject) {
        return Err(format!("subject '{}' not in trusted list", subject));
    }
    Ok(())
}

fn enforce_hydra_policy(policy: &HydraZkPolicy, claims: &serde_json::Value) -> Result<(), String> {
    if policy.trusted_roots_hex.is_empty() {
        warn!("hydra policy.trusted_roots_hex is empty; skipping whitelist binding");
        return Ok(());
    }
    let claimed: Vec<&str> = claims
        .get("roots_hex")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "claims.roots_hex missing".to_string())?
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect();

    if claimed.len() != policy.trusted_roots_hex.len() {
        return Err(format!(
            "roots_hex length mismatch: evidence={}, policy={}",
            claimed.len(),
            policy.trusted_roots_hex.len()
        ));
    }
    for (i, (a, b)) in claimed
        .iter()
        .zip(policy.trusted_roots_hex.iter())
        .enumerate()
    {
        if !a.eq_ignore_ascii_case(b) {
            return Err(format!("roots_hex[{i}] mismatch"));
        }
    }
    Ok(())
}

fn enforce_tdx_policy(policy: &TdxPolicy, claims: &serde_json::Value) -> Result<(), String> {
    fn match_hex(claim: Option<&str>, list: &[String], field: &str) -> Result<(), String> {
        if list.is_empty() {
            return Ok(());
        }
        let v = claim.ok_or_else(|| format!("claims.{field} missing"))?;
        if !list.iter().any(|s| s.eq_ignore_ascii_case(v)) {
            return Err(format!("{field} '{v}' not in trusted list"));
        }
        Ok(())
    }

    match_hex(
        claims.get("mr_td").and_then(|v| v.as_str()),
        &policy.trusted_mr_td_hex,
        "mr_td",
    )?;
    match_hex(
        claims.get("mr_seam").and_then(|v| v.as_str()),
        &policy.trusted_mr_seam_hex,
        "mr_seam",
    )?;
    match_hex(
        claims.get("mr_config_id").and_then(|v| v.as_str()),
        &policy.trusted_mr_config_id_hex,
        "mr_config_id",
    )?;
    if !policy.accept_tcb_status.is_empty() {
        let s = claims
            .get("tcb_status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.tcb_status missing".to_string())?;
        if !policy.accept_tcb_status.iter().any(|x| x == s) {
            return Err(format!("tcb_status '{s}' not accepted"));
        }
    }
    Ok(())
}
