//! evidence 构造。
//!
//! - mock：固定 payload + nonce 透传
//! - cca / csv / tdx：通过 guest-components attestation-agent 取 evidence
//! - itrustee / virtcca：通过 AA 取 evidence，与 CCA/CSV 模式一致
//! - *-hydra：TEE evidence + Groth16 证明叠加，共用同一 nonce

use crate::config::{WhitelistConfig, ZkConfig};
use anyhow::{Context, Result};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hydra::{Fr, circuit::AttestationCircuit, nonce, poseidon, prove, shrubs_tree};
use protos::TeeType;
use serde_json::json;
use std::io::Read;

pub async fn build_evidence(
    tee_type: TeeType,
    nonce_bytes: &[u8],
    zk: Option<&ZkConfig>,
    aa_endpoint: &str,
) -> Result<Vec<u8>> {
    let nonce_b64 = B64URL.encode(nonce_bytes);
    let nonce_b64 = nonce_b64.as_str();
    match tee_type {
        TeeType::Mock => Ok(serde_json::to_vec(&json!({
            "payload": {
                "device_id": "mock-device-001",
                "challenge_b64": nonce_b64,
                "note": "stage-1 mock evidence",
            },
            "issued_at": now_secs(),
        }))?),
        TeeType::Cca => {
            let cca_part = build_cca_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&cca_part)?)
        }
        TeeType::Csv => {
            let csv_part = build_csv_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&csv_part)?)
        }
        TeeType::CsvHydra => {
            let csv_part = build_csv_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = csv_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::CcaHydra => {
            // 同一份 nonce 同时进 CCA token（runtime_data）和 hydra public input 末位，
            // appraiser 两侧都对照 expected_report_data 校验，少绑一层就漏出重放窗口。
            let cca_part = build_cca_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = cca_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::Tdx => {
            let tdx_part = build_tdx_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&tdx_part)?)
        }
        TeeType::TdxHydra => {
            let tdx_part = build_tdx_part(nonce_b64, aa_endpoint)?;
            let zk_part = build_hydra_part(
                zk.context("[zk] section missing in attester config")?,
                nonce_b64,
            )?;
            let mut combined = serde_json::Map::new();
            if let serde_json::Value::Object(m) = tdx_part {
                combined.extend(m);
            }
            if let serde_json::Value::Object(m) = zk_part {
                combined.extend(m);
            }
            Ok(serde_json::to_vec(&serde_json::Value::Object(combined))?)
        }
        TeeType::Itrustee => {
            let part = build_itrustee_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&part)?)
        }
        TeeType::Virtcca => {
            let part = build_virtcca_part(nonce_b64, aa_endpoint)?;
            Ok(serde_json::to_vec(&part)?)
        }
        TeeType::Unspecified => anyhow::bail!("tee_type unspecified"),
    }
}

fn build_hydra_part(zk: &ZkConfig, nonce_b64: &str) -> Result<serde_json::Value> {
    let pk_bytes = std::fs::read(&zk.proving_key_path)
        .with_context(|| format!("read pk {}", zk.proving_key_path.display()))?;
    let vk_bytes = std::fs::read(&zk.verifying_key_path)
        .with_context(|| format!("read vk {}", zk.verifying_key_path.display()))?;

    // challenge nonce → Fr：blake2s_256 + from_le_bytes_mod_order，
    // 与 hydra::nonce::nonce_to_scalar 共用同一函数；attester 与 wasm appraiser 必须走同一编码
    let nonce_bytes = B64URL.decode(nonce_b64).context("decode challenge nonce")?;
    let challenge_scalar = nonce::nonce_to_scalar(&nonce_bytes);

    // time + period 是电路里 output = H(H(H(pk,ar),time),period) 的固定输入。
    // 86_400 = 一天的秒数，配合 time 可在电路侧表达"一天内有效"语义；
    // 当前 wasm appraiser 不强校验 time/period 取值，仅用于 output 比对
    let time = Fr::from(now_secs() as u64);
    let period = Fr::from(86_400u64);

    let wl = &zk.whitelist;
    let (circuit, root_list_for_pi) = build_whitelist_circuit(wl, time, period, challenge_scalar)?;

    let pk_field = circuit.pk;
    let output = circuit.output;

    // ponytail: 时间戳异或固定常量做种子，仅 demo 可重放调试用；生产应换 OsRng
    let mut rng = StdRng::seed_from_u64(now_secs() as u64 ^ 0xa5a5_a5a5);
    let proof_bytes = prove::prove(&pk_bytes, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("prove failed: {e}"))?;

    // public input 顺序必须与 circuit::generate_constraints 中 new_input 调用顺序逐字段对齐：
    // [pk, root[0..root_count], output, time, period, challenge]
    // appraiser 端按相同顺序解码，"末位 challenge" 这个约定也是 hydra appraiser
    // 用 public_inputs.last() 比对 nonce、用 pi_count - 5 反推 root_count 的依据
    let mut pi_bytes = Vec::new();
    pk_field
        .serialize_compressed(&mut pi_bytes)
        .map_err(|e| anyhow::anyhow!("serialize pk: {e}"))?;
    for r in &root_list_for_pi {
        r.serialize_compressed(&mut pi_bytes)
            .map_err(|e| anyhow::anyhow!("serialize root: {e}"))?;
    }
    for fr in [output, time, period, challenge_scalar] {
        fr.serialize_compressed(&mut pi_bytes)
            .map_err(|e| anyhow::anyhow!("serialize public input: {e}"))?;
    }

    let evidence = json!({
        "vk_b64": B64.encode(&vk_bytes),
        "proof_b64": B64.encode(&proof_bytes),
        "public_inputs_b64": B64.encode(&pi_bytes),
    });

    Ok(evidence)
}

/// 完整 shrubs whitelist 模式：基于配置中的 device 列表构 shrubs 树，定位 self_index 的 path。
fn build_whitelist_circuit(
    wl: &WhitelistConfig,
    time: Fr,
    period: Fr,
    challenge_scalar: Fr,
) -> Result<(AttestationCircuit, Vec<Fr>)> {
    if wl.devices.is_empty() {
        anyhow::bail!("zk.whitelist.devices must not be empty");
    }
    if wl.self_index >= wl.devices.len() {
        anyhow::bail!(
            "zk.whitelist.self_index out of range: {} >= {}",
            wl.self_index,
            wl.devices.len()
        );
    }

    let leaves: Vec<Fr> = wl
        .devices
        .iter()
        .map(|d| {
            let pk = Fr::from(d.pk);
            let sk = Fr::from(d.sk);
            let ar = Fr::from(d.ar);
            // leaf hash 顺序与 circuit.rs 中 step 1-2 的 m=H(ar,sk)、leaf=H(m,pk) 严格一致；
            // 这里若改顺序，shrubs root 与电路里推出的 leaf 就对不上
            poseidon::hash_pair(poseidon::hash_pair(ar, sk), pk)
        })
        .collect();

    let mut root_list = Vec::new();
    shrubs_tree::create_batch_devices(&mut root_list, &leaves);

    let (path_values, tag_values) =
        shrubs_tree::find_shrubs_path(&root_list, &leaves, 0, wl.self_index).ok_or_else(|| {
            anyhow::anyhow!(
                "self_index {} has no shrubs path (likely sits on a shrubs root \
                 boundary; pick a different index)",
                wl.self_index
            )
        })?;

    let dev = &wl.devices[wl.self_index];
    let pk = Fr::from(dev.pk);
    let sk = Fr::from(dev.sk);
    let ar = Fr::from(dev.ar);
    let r1 = poseidon::hash_pair(pk, ar);
    let r2 = poseidon::hash_pair(r1, time);
    let output = poseidon::hash_pair(r2, period);

    let circuit = AttestationCircuit {
        pk,
        sk,
        ar,
        time,
        period,
        output,
        root: root_list.clone(),
        path: path_values,
        tag: tag_values,
        challenge: challenge_scalar,
    };
    Ok((circuit, root_list))
}

/// 调 guest-components api-server-rest 取 evidence。nonce 作为 runtime_data 传给 AA，
/// 各 TEE 由 AA 内部按规则写入 report_data / challenge 字段。
fn fetch_aa_evidence(nonce_b64: &str, aa_endpoint: &str) -> Result<Vec<u8>> {
    let nonce_raw = B64URL.decode(nonce_b64).context("decode challenge nonce")?;
    let runtime_data_b64 = B64.encode(&nonce_raw);
    let url = format!("{}/aa/evidence?runtime_data={}", aa_endpoint, runtime_data_b64);
    let response = ureq::get(&url).call().with_context(|| format!("GET {}", url))?;
    let mut buf = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut buf)
        .context("read AA evidence body")?;
    Ok(buf)
}

fn build_cca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let cca_token = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "cca_token_b64": B64.encode(&cca_token),
        "nonce": nonce_b64,
    }))
}

fn build_csv_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let csv_evidence = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "csv_evidence_b64": B64.encode(&csv_evidence),
        "nonce": nonce_b64,
    }))
}

/// 通过 AA 取 TDX quote。collateral 由 verifier host 按 fmspc 拉取，attester 不参与。
fn build_tdx_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let quote_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "quote_b64": B64.encode(&quote_bytes),
    }))
}

/// 通过 AA 取 iTrustee evidence（report JSON + 可选 IMA log），添加 nonce 字段。
fn build_itrustee_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse itrustee AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

/// 通过 AA 取 VirtCCA evidence（CBOR token + dev_cert + event_log），添加 nonce 字段。
fn build_virtcca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse virtcca AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
