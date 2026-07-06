//! relying-party: RP-triggered background-check (gRPC client).
//!
//! Flow:
//! 1. Generate a 32-byte random nonce locally
//! 2. AttesterService.GetEvidence -> get evidence + wasm
//! 3. VerifierService.Verify -> get EAR
//! 4. Verify the EAR JWT locally using the verifier's public key
//! 5. Check that eat_nonce in the EAR matches the local nonce

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

    /// attester gRPC endpoint, e.g. `http://127.0.0.1:9000`.
    #[arg(long)]
    attester: Option<String>,
    /// verifier gRPC endpoint, e.g. `http://127.0.0.1:8080`.
    #[arg(long)]
    verifier: Option<String>,
    /// TEE type, must match the attester configuration.
    #[arg(long, value_parser = parse_tee_type)]
    tee_type: Option<TeeType>,
    /// Verifier's ES256 public key (PEM format).
    #[arg(long)]
    pubkey: Option<PathBuf>,
    /// Optional: write the EAR to a file for debugging.
    #[arg(long)]
    ear_out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Query the device VC from the chain (requires `blockchain` feature + Foundry `cast` CLI).
    #[cfg(feature = "blockchain")]
    #[command(name = "query-vc")]
    QueryVc {
        /// Device public key hex.
        device_pubkey: String,
    },
}

/// Parse a TEE type string into a TeeType enum variant.
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
    // Initialize logging, defaulting to "info" level if not configured.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();

    // query-vc subcommand: query the on-chain VC, does not run remote attestation.
    #[cfg(feature = "blockchain")]
    if let Some(Command::QueryVc { device_pubkey }) = cli.command {
        use hydra::device_vc::{ChainConfig, query_device_vc_from_chain};
        let cfg = ChainConfig::from_env().context("chain config")?;
        let vc = query_device_vc_from_chain(&device_pubkey, &cfg)?;
        println!("{}", serde_json::to_string_pretty(&vc)?);
        return Ok(());
    }

    // Standard remote attestation flow.
    let attester = cli.attester.context("--attester required")?;
    let verifier = cli.verifier.context("--verifier required")?;
    let tee_type = cli.tee_type.context("--tee-type required")?;
    let pubkey = cli.pubkey.context("--pubkey required")?;

    // Read and parse the verifier's EC public key (PEM).
    let pem =
        std::fs::read(&pubkey).with_context(|| format!("read pubkey {}", pubkey.display()))?;
    let key = DecodingKey::from_ec_pem(&pem).context("parse pubkey as EC PEM")?;

    // ---- Step 1: generate a 32-byte random nonce ----
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = B64URL.encode(nonce);
    info!(nonce = %nonce_b64, "generated nonce");

    // ---- Step 2: call attester GetEvidence ----
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

    // ---- Step 3: call verifier Verify ----
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

    // Optionally write raw EAR to a file.
    if let Some(path) = &cli.ear_out {
        std::fs::write(path, &resp.ear).with_context(|| format!("write {}", path.display()))?;
    }

    // ---- Step 4: verify the EAR JWT signature ----
    let mut validation = Validation::new(Algorithm::ES256);
    // Disable standard JWT claim requirements (exp, etc.) — we only care about eat_nonce.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let data = jsonwebtoken::decode::<Value>(resp.ear.trim(), &key, &validation)
        .context("decode/verify EAR")?;
    info!("EAR signature verified");

    // ---- Step 5: ensure eat_nonce matches the local nonce ----
    let eat_nonce = data
        .claims
        .get("eat_nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing eat_nonce"))?;
    if eat_nonce != nonce_b64 {
        bail!("eat_nonce mismatch: ear={eat_nonce}, expected={nonce_b64}");
    }

    // Print the full EAR claims to stdout.
    println!("{}", serde_json::to_string_pretty(&data.claims)?);

    // Check the trust_vector.executables value to confirm affirmation.
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
