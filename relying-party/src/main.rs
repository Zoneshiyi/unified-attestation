//! relying-party：RP 触发的 background-check（gRPC 客户端）。
//!
//! 流程：
//! 1. 本地生成 32B 随机 nonce
//! 2. AttesterService.GetEvidence → 拿 evidence + wasm
//! 3. VerifierService.Verify → 拿 EAR
//! 4. 用 verifier 公钥本地校验 EAR JWT
//! 5. 校验 EAR 中 eat_nonce 与本地 nonce 是否一致

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use clap::{Parser, Subcommand};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use protos::attester_service_client::AttesterServiceClient;
use protos::verifier_service_client::VerifierServiceClient;
use protos::verify_request::Wasm;
use protos::{GetEvidenceRequest, TeeType, VerifyRequest};
use serde_json::Value;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation relying-party")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// attester gRPC 端点，例 `http://127.0.0.1:9000`。
    #[arg(long)]
    attester: Option<String>,
    /// verifier gRPC 端点，例 `http://127.0.0.1:8080`。
    #[arg(long)]
    verifier: Option<String>,
    /// TEE 类型，需与 attester 配置一致。
    #[arg(long, value_parser = parse_tee_type)]
    tee_type: Option<TeeType>,
    /// verifier 的 ES256 公钥（PEM 格式）。
    #[arg(long)]
    pubkey: Option<PathBuf>,
    /// 可选：把 EAR 写到文件以便调试。
    #[arg(long)]
    ear_out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 从链上查询设备 VC（需 `blockchain` feature + Foundry `cast` CLI）
    #[cfg(feature = "blockchain")]
    #[command(name = "query-vc")]
    QueryVc {
        /// 设备公钥 hex
        device_pubkey: String,
    },
}

fn parse_tee_type(s: &str) -> Result<TeeType, String> {
    match s {
        "mock" => Ok(TeeType::Mock),
        "cca" => Ok(TeeType::Cca),
        "cca-hydra" => Ok(TeeType::CcaHydra),
        "csv" => Ok(TeeType::Csv),
        "tdx" => Ok(TeeType::Tdx),
        "tdx-hydra" => Ok(TeeType::TdxHydra),
        "itrustee" => Ok(TeeType::Itrustee),
        "virtcca" => Ok(TeeType::Virtcca),
        other => Err(format!("invalid tee_type '{other}'")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();

    // query-vc 子命令：查链上 VC，不跑远程证明
    #[cfg(feature = "blockchain")]
    if let Some(Command::QueryVc { device_pubkey }) = cli.command {
        use hydra::device_vc::{ChainConfig, query_device_vc_from_chain};
        let cfg = ChainConfig::from_env().context("chain config")?;
        let vc = query_device_vc_from_chain(&device_pubkey, &cfg)?;
        println!("{}", serde_json::to_string_pretty(&vc)?);
        return Ok(());
    }

    // 标准远程证明流程
    let attester = cli.attester.context("--attester required")?;
    let verifier = cli.verifier.context("--verifier required")?;
    let tee_type = cli.tee_type.context("--tee-type required")?;
    let pubkey = cli.pubkey.context("--pubkey required")?;

    let pem =
        std::fs::read(&pubkey).with_context(|| format!("read pubkey {}", pubkey.display()))?;
    let key = DecodingKey::from_ec_pem(&pem).context("parse pubkey as EC PEM")?;

    // 1. nonce
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = B64URL.encode(nonce);
    info!(nonce = %nonce_b64, "generated nonce");

    // 2. attester
    let mut att = AttesterServiceClient::connect(attester.clone())
        .await
        .with_context(|| format!("connect attester {attester}"))?;
    let evidence = att
        .get_evidence(GetEvidenceRequest {
            tee_type: tee_type as i32,
            nonce: nonce.to_vec(),
        })
        .await
        .context("attester GetEvidence")?
        .into_inner();
    info!(
        evidence_len = evidence.evidence.len(),
        wasm_len = evidence.wasm_component.len(),
        "got evidence"
    );

    // 3. verifier
    let mut ver = VerifierServiceClient::connect(verifier.clone())
        .await
        .with_context(|| format!("connect verifier {verifier}"))?;
    let resp = ver
        .verify(VerifyRequest {
            tee_type: tee_type as i32,
            nonce: nonce.to_vec(),
            evidence: evidence.evidence,
            wasm: Some(Wasm::WasmComponent(evidence.wasm_component)),
        })
        .await
        .context("verifier Verify")?
        .into_inner();

    if let Some(path) = &cli.ear_out {
        std::fs::write(path, &resp.ear).with_context(|| format!("write {}", path.display()))?;
    }

    // 4. EAR 验签
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let data = jsonwebtoken::decode::<Value>(resp.ear.trim(), &key, &validation)
        .context("decode/verify EAR")?;
    info!("EAR signature verified");

    // 5. eat_nonce 必须等于本地 nonce
    let eat_nonce = data
        .claims
        .get("eat_nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing eat_nonce"))?;
    if eat_nonce != nonce_b64 {
        bail!("eat_nonce mismatch: ear={eat_nonce}, expected={nonce_b64}");
    }

    println!("{}", serde_json::to_string_pretty(&data.claims)?);

    let trust_vector = data
        .claims
        .get("trust_vector")
        .ok_or_else(|| anyhow!("missing trust_vector"))?;
    let executables = trust_vector
        .get("executables")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if executables < 2 {
        bail!("EAR not affirming: executables = {executables}");
    }
    println!("\nverdict: ACCEPTED");
    Ok(())
}
