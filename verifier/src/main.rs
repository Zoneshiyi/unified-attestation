//! Verifier entry point.
//!
//! Starts a tonic gRPC server exposing only VerifierService.Verify.
//! The RP generates its own nonce and submits it alongside evidence; the verifier is stateless.
//!
//! Startup sequence:
//! 1. Parse TOML config
//! 2. Initialize wasmtime host (load whitelist + previously registered components)
//! 3. Initialize EAR signing context (ES256 private key)
//! 4. Load host-side verifiers per config (CCA / CSV, optional)
//! 5. Assemble AppState → start gRPC server

mod cca_native;
mod config;
mod csv_native;
mod ear;
mod grpc;
mod itrustee_native;
mod virtcca_native;
mod wasm_host;

use anyhow::{Context, Result};
use clap::Parser;
use protos::verifier_service_server::VerifierServiceServer;
use std::path::PathBuf;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation verifier")]
struct Cli {
    #[arg(short, long, default_value = "config/verifier.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log level controllable via RUST_LOG env var; defaults to info
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let config = config::Config::load(&cli.config)
        .with_context(|| format!("load config from {}", cli.config.display()))?;

    // wasmtime host: manages component registration, whitelist validation, sandbox invocation
    let host = wasm_host::WasmHost::new(&config).await?;
    // EAR JWT signing context: loads ES256 private key
    let signing = ear::SigningContext::new(&config.ear)?;

    // CCA host-side verifier: missing ta_store or rv_store → None (skip verification, demo only)
    let cca_verifier = cca_native::CcaVerifier::load(&config.policy.cca)?;
    cca_native::warn_no_store(&config.policy.cca);
    // CSV host-side verifier: skipped when enabled=false
    let csv_verifier = csv_native::CsvVerifier::load(&config.policy.csv);
    if !config.policy.csv.enabled {
        tracing::warn!(
            "CSV policy disabled (policy.csv.enabled=false); host-side CSV verification skipped. \
             DO NOT USE IN PRODUCTION."
        );
    }

    // Blockchain feature: read chain config from env vars (requires `blockchain` feature)
    #[cfg(feature = "blockchain")]
    let chain_config = {
        use hydra::device_vc::ChainConfig;
        ChainConfig::from_env().ok()
    };

    // Assemble global state shared across all gRPC handlers via Arc
    let state = Arc::new(grpc::AppState {
        host,
        signing,
        hydra_policy: config.policy.hydra,
        cca_policy: config.policy.cca,
        tdx_policy: config.policy.tdx,
        cca_verifier,
        csv_verifier,
        #[cfg(feature = "blockchain")]
        chain_config,
    });

    let addr = config
        .listen
        .parse()
        .with_context(|| format!("parse listen '{}'", config.listen))?;
    info!(%addr, "verifier gRPC listening");
    Server::builder()
        .add_service(VerifierServiceServer::from_arc(state))
        .serve(addr)
        .await?;
    Ok(())
}
