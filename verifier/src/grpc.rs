//! tonic gRPC 实现：VerifierService.Verify。

use crate::cca_native::CcaVerifier;
use crate::config::{CcaPolicy, HydraZkPolicy, TdxPolicy};
use crate::csv_native::CsvVerifier;
use crate::ear::{EarClaims, SigningContext, TrustVector, VerifierId};
use crate::wasm_host::WasmHost;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(feature = "blockchain")]
use sha2::Digest;
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
    /// 可选：链上 VC 存储配置（需 `blockchain` feature）
    #[cfg(feature = "blockchain")]
    pub chain_config: Option<hydra::device_vc::ChainConfig>,
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

        // 2. host 端 CCA / CSV / iTrustee / VirtCCA 证据处理 + 度量值注入 evidence JSON
        //    CCA / CSV：完整链验签 + 度量值注入
        //    iTrustee / VirtCCA：解析 evidence 提取字段注入（真验签需 .so / OpenSSL，部署时接入）
        //    TDX：host 端按 fmspc 拉取 collateral 注入 evidence
        let cca_platform_lifecycle: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        let evidence_for_wasm = if matches!(tee, TeeType::Cca | TeeType::CcaHydra) {
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            if let Some(verifier) = &self.cca_verifier {
                let cca_token = extract_b64_field(&req.evidence, "cca_token_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract cca token: {e}")))?;
                let mut padded = req.nonce.clone();
                padded.resize(64, 0);
                let result = verifier.verify(&cca_token, &padded).map_err(|e| {
                    warn!(error = %e, "cca host verify failed");
                    Status::invalid_argument(format!("cca verify failed: {e}"))
                })?;
                info!("cca host verify passed");
                let obj = ev.as_object_mut()
                    .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                inject_cca_claims(obj, &result);
                *cca_platform_lifecycle.lock().unwrap() = result.cca_platform_lifecycle.clone();
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Csv | TeeType::CsvHydra) {
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            if let Some(verifier) = &self.csv_verifier {
                let csv_evidence = extract_b64_field(&req.evidence, "csv_evidence_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract csv evidence: {e}")))?;
                let result = verifier
                    .verify(&csv_evidence, &req.nonce)
                    .map_err(|e| Status::invalid_argument(format!("csv verify failed: {e}")))?;
                let obj = ev.as_object_mut()
                    .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                inject_csv_claims(obj, &result);
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Itrustee) {
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            match crate::itrustee_native::extract_claims(&req.evidence) {
                Ok(result) => {
                    let obj = ev.as_object_mut()
                        .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                    inject_itrustee_claims(obj, &result);
                }
                Err(e) => warn!(error = %e, "itrustee claim extraction failed, proceeding with raw evidence"),
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Virtcca) {
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            match crate::virtcca_native::extract_claims(&req.evidence) {
                Ok(result) => {
                    let obj = ev.as_object_mut()
                        .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                    inject_virtcca_claims(obj, &result);
                }
                Err(e) => warn!(error = %e, "virtcca claim extraction failed, proceeding with raw evidence"),
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Tdx | TeeType::TdxHydra) {
            inject_tdx_collateral(&req.evidence, &self.tdx_policy.pccs_url)
                .await
                .map_err(|e| {
                    warn!(error = %e, "fetch tdx collateral failed");
                    Status::internal(format!("fetch collateral: {e}"))
                })?
        } else {
            req.evidence.clone()
        };

        let cca_lifecycle = cca_platform_lifecycle.lock().unwrap().clone();

        // 3. wasm appraiser
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

        // 4. policy
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
            // Mock / CSV / Itrustee / Virtcca：policy 匹配在 host 端已完成（或 wasm appraiser 自行处理），
            // 此处不额外校验。Itrustee / Virtcca 的 native 验证依赖 .so 库，部署时按需接入。
            TeeType::Unspecified | TeeType::Mock | TeeType::Csv | TeeType::Itrustee | TeeType::Virtcca => {}
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

        // 5. 签 EAR。eat_nonce 用 RP nonce 的 base64url no-pad 文本表示，便于 RP 文本比对。
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&req.nonce);
        let nonce_bound = outcome.claims.get("nonce_bound").and_then(|v| v.as_bool()).unwrap_or(false);
        let tcb_status = outcome.claims.get("tcb_status").and_then(|v| v.as_str());
        let trust_vector = trust_vector_for(tee, nonce_bound, &cca_lifecycle, tcb_status);
        let claims = EarClaims {
            iss: "unified-attestation-verifier".to_string(),
            iat: now_secs(),
            exp: Some(now_secs() + 3600),
            eat_nonce: nonce_b64,
            tee_type: tee_kind_str.to_string(),
            component_id: outcome.component_id.clone(),
            submods: outcome.claims.clone(),
            trust_vector,
            verifier_id: VerifierId {
                developer: "unified-attestation".to_string(),
                build: None,
            },
            eat_profile: Some("tag:github.com,2024:unified-attestation".to_string()),
        };
        let ear = self
            .signing
            .sign(claims)
            .map_err(|e| Status::internal(e.to_string()))?;

        // 6. 可选：验证通过后将 device VC 发布到链上
        #[cfg(feature = "blockchain")]
        if let Some(ref chain_cfg) = self.chain_config {
            use hydra::device_vc;
            let now = chrono_iso_now();
            let evidence_hash = {
                let mut h = sha2::Sha256::new();
                Digest::update(&mut h, &req.evidence);
                hex::encode(Digest::finalize(h))
            };
            let record = device_vc::build_background_check_record(
                &extract_pubkey_from_claims(&outcome.claims)
                    .unwrap_or_else(|| "unknown".to_string()),
                &evidence_hash,
                device_vc::DEFAULT_NETWORK,
                &now,
                true,
            );
            match device_vc::publish_device_vc_to_chain(&record, chain_cfg) {
                Ok(tx_hash) => info!(%tx_hash, "device VC published to chain"),
                Err(e) => warn!(error = %e, "chain publish failed"),
            }
        }

        Ok(Response::new(VerifyResponse {
            ear,
            wasm_component_id: outcome.component_id,
        }))
    }
}

/// `now()` 的 ISO 8601 字符串表示。
#[cfg(feature = "blockchain")]
fn chrono_iso_now() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // 简化：距 epoch 的天数 → 近似日期
    let days = secs / 86400;
    // 从 1970-01-01 开始计算
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mut m = 1i64;
    for (i, days_in_m) in months.iter().enumerate() {
        let dim = if i == 1 && is_leap {
            *days_in_m + 1
        } else {
            *days_in_m
        };
        if remaining < dim {
            m = i as i64 + 1;
            break;
        }
        remaining -= dim;
    }
    format!("{y:04}-{m:02}-{:02}T00:00:00Z", remaining + 1)
}

/// 从 wasm 返回的 claims 中提取设备公钥（如有）。
#[cfg(feature = "blockchain")]
fn extract_pubkey_from_claims(claims: &serde_json::Value) -> Option<String> {
    claims
        .get("device_pubkey")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
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
        TeeType::Itrustee => "itrustee",
        TeeType::Virtcca => "virtcca",
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
    // RIM 比对
    if !policy.trusted_rim_hex.is_empty() {
        let rim = claims
            .get("cca_realm_initial_measurement")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.cca_realm_initial_measurement missing".to_string())?;
        if !policy.trusted_rim_hex.iter().any(|s| s.eq_ignore_ascii_case(rim)) {
            return Err(format!("rim '{}' not in trusted list", rim));
        }
    }
    // subject 比对（用于 cca-hydra 的设备实例白名单）
    if !policy.trusted_subjects.is_empty() {
        let subject = claims
            .get("subject")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.subject missing".to_string())?;
        if !policy.trusted_subjects.iter().any(|s| s == subject) {
            return Err(format!("subject '{}' not in trusted list", subject));
        }
    }
    if policy.trusted_subjects.is_empty() && policy.trusted_rim_hex.is_empty() {
        warn!("cca policy.trusted_subjects and trusted_rim_hex both empty; skipping CCA binding");
    }
    Ok(())
}

/// 将 CCA 验证结果注入 evidence JSON，供 wasm appraiser 透传。
fn inject_cca_claims(obj: &mut serde_json::Map<String, serde_json::Value>, result: &crate::cca_native::CcaVerificationResult) {
    if let Some(ref v) = result.realm_initial_measurement {
        obj.insert("cca_realm_initial_measurement".into(), v.clone().into());
    }
    if let Some(ref v) = result.realm_personalization_value {
        obj.insert("cca_realm_personalization_value".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_instance_id {
        obj.insert("cca_platform_instance_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_implementation_id {
        obj.insert("cca_platform_implementation_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_lifecycle {
        obj.insert("cca_platform_lifecycle".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_sw_components {
        obj.insert("cca_platform_sw_components".into(), serde_json::to_value(v).unwrap_or_default());
    }
}

/// 将 CSV 验证结果注入 evidence JSON，供 wasm appraiser 透传。
fn inject_csv_claims(obj: &mut serde_json::Map<String, serde_json::Value>, result: &crate::csv_native::CsvVerificationResult) {
    if let Some(ref v) = result.chip_id {
        obj.insert("chip_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.measurement {
        obj.insert("measurement".into(), v.clone().into());
    }
    if let Some(ref v) = result.vm_version {
        obj.insert("vm_version".into(), v.clone().into());
    }
    if let Some(v) = result.policy_nodbg {
        obj.insert("policy_nodbg".into(), v.into());
    }
    if let Some(v) = result.policy_noks {
        obj.insert("policy_noks".into(), v.into());
    }
}

/// 根据验证结果为不同 TEE 类型生成动态 Trust Vector。
fn trust_vector_for(
    tee: TeeType,
    nonce_bound: bool,
    cca_lifecycle: &Option<String>,
    tcb_status: Option<&str>,
) -> TrustVector {
    match tee {
        TeeType::Tdx | TeeType::TdxHydra => {
            let executables = match tcb_status {
                Some("UpToDate") => 2,
                Some("SWHardeningNeeded") | Some("ConfigurationAndSWHardeningNeeded") => 1,
                Some("OutOfDate") | Some("Revoked") => 0,
                _ => 1,
            };
            TrustVector::new(2, 2, executables)
        }
        TeeType::Cca | TeeType::CcaHydra => {
            let instance_identity = if nonce_bound { 2 } else { 0 };
            let configuration = match cca_lifecycle.as_deref() {
                Some("secured") | Some("secured_no_debug") => 2,
                Some("not_secured") | Some("recoverable") => 1,
                _ => 0,
            };
            TrustVector::new(instance_identity, configuration, 2)
        }
        TeeType::Csv | TeeType::CsvHydra => {
            let instance_identity = if nonce_bound { 2 } else { 0 };
            TrustVector::new(instance_identity, 2, 2)
        }
        _ => TrustVector::affirming(),
    }
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

/// 将 iTrustee 验证结果注入 evidence JSON，供 wasm appraiser 透传。
fn inject_itrustee_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::itrustee_native::ItrusteeVerificationResult,
) {
    if let Some(ref v) = result.uuid {
        obj.insert("itrustee_uuid".into(), v.clone().into());
    }
    if let Some(ref v) = result.ta_img {
        obj.insert("itrustee_ta_img".into(), v.clone().into());
    }
    if let Some(ref v) = result.ta_mem {
        obj.insert("itrustee_ta_mem".into(), v.clone().into());
    }
    if let Some(ref v) = result.hash_alg {
        obj.insert("itrustee_hash_alg".into(), v.clone().into());
    }
    if let Some(ref v) = result.version {
        obj.insert("itrustee_version".into(), v.clone().into());
    }
}

/// 将 VirtCCA 验证结果注入 evidence JSON，供 wasm appraiser 透传。
fn inject_virtcca_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::virtcca_native::VirtccaVerificationResult,
) {
    obj.insert("virtcca_token_size".into(), result.token_size.into());
    obj.insert("virtcca_cert_size".into(), result.cert_size.into());
    if let Some(sz) = result.ima_log_size {
        obj.insert("virtcca_ima_log_size".into(), sz.into());
    }
    if let Some(sz) = result.event_log_size {
        obj.insert("virtcca_event_log_size".into(), sz.into());
    }
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
