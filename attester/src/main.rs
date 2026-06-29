//! attester gRPC 服务。
//!
//! RATS background-check：RP 推 nonce 给 attester，attester 收集 TEE evidence
//! 并把本地 wasm 组件一并返回；RP 再转交 verifier 拿 EAR。
//!
//! 由配置决定本机 tee_type，请求中的 `tee_type` 必须与之一致，避免 RP 误用。

mod config;
mod evidence;

use anyhow::{Context, Result};
use clap::Parser;
use protos::attester_service_server::{AttesterService, AttesterServiceServer};
use protos::{GetEvidenceRequest, GetEvidenceResponse, TeeType};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::{Request, Response, Status, transport::Server};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation attester (gRPC)")]
struct Cli {
    #[arg(short, long, default_value = "config/attester.toml")]
    config: PathBuf,
}

struct Svc {
    cfg: config::Config,
    wasm_bytes: Vec<u8>,
}

#[tonic::async_trait]
impl AttesterService for Svc {
    async fn get_evidence(
        &self,
        req: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let req = req.into_inner();
        let tee = TeeType::try_from(req.tee_type)
            .map_err(|_| Status::invalid_argument("invalid tee_type"))?;
        if tee != self.cfg.tee_type {
            return Err(Status::invalid_argument(format!(
                "tee_type mismatch: request={tee:?}, configured={:?}",
                self.cfg.tee_type
            )));
        }
        if req.nonce.is_empty() {
            return Err(Status::invalid_argument("nonce required"));
        }

        let evidence = evidence::build_evidence(
            self.cfg.tee_type,
            &req.nonce,
            self.cfg.zk.as_ref(),
            &self.cfg.aa_endpoint,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "build evidence failed");
            Status::internal(e.to_string())
        })?;

        Ok(Response::new(GetEvidenceResponse {
            evidence,
            wasm_component: self.wasm_bytes.clone(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)?;

    let wasm_bytes = std::fs::read(&cfg.wasm_component_path)
        .with_context(|| format!("read wasm component {}", cfg.wasm_component_path.display()))?;
    info!(
        wasm_path = %cfg.wasm_component_path.display(),
        size = wasm_bytes.len(),
        "loaded wasm component"
    );

    let listen = cfg.listen.clone();
    let svc = Arc::new(Svc { cfg, wasm_bytes });

    let addr = listen.parse().with_context(|| format!("parse listen addr '{listen}'"))?;
    info!(%addr, "attester gRPC listening");
    Server::builder()
        .add_service(AttesterServiceServer::from_arc(svc))
        .serve(addr)
        .await?;
    Ok(())
}
