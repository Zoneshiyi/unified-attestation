//! verifier 主入口。
//!
//! 启动 tonic gRPC 服务，仅暴露 VerifierService.Verify。
//! RP 自行生成 nonce 并随 evidence 一起提交。

mod cca_native;
mod config;
mod csv_native;
mod ear;
mod grpc;
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let config = config::Config::load(&cli.config)
        .with_context(|| format!("load config from {}", cli.config.display()))?;

    let host = wasm_host::WasmHost::new(&config).await?;
    let signing = ear::SigningContext::new(&config.ear)?;

    let cca_verifier = cca_native::CcaVerifier::load(&config.policy.cca)?;
    cca_native::warn_no_store(&config.policy.cca);
    let csv_verifier = csv_native::CsvVerifier::load(&config.policy.csv);
    if !config.policy.csv.enabled {
        tracing::warn!(
            "CSV policy disabled (policy.csv.enabled=false); host-side CSV verification skipped. \
             DO NOT USE IN PRODUCTION."
        );
    }

    let state = Arc::new(grpc::AppState {
        host,
        signing,
        hydra_policy: config.policy.hydra,
        cca_policy: config.policy.cca,
        tdx_policy: config.policy.tdx,
        cca_verifier,
        csv_verifier,
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
