//! Attester gRPC service.
//!
//! RATS background-check: the RP pushes a nonce to the attester. The attester collects
//! TEE evidence and returns it along with its local wasm component; the RP then forwards
//! everything to the verifier for EAR issuance.
//!
//! The local tee_type is determined by config. The request's tee_type must match —
//! this prevents the RP from accidentally invoking the wrong evidence path.
//!
//! Startup sequence:
//! 1. Parse TOML config → tee_type + wasm component path + AA endpoint
//! 2. Load the local wasm component bytes
//! 3. Assemble gRPC service → listen on port

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

/// gRPC service state: config + pre-loaded wasm component bytes.
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
        // Guard: request tee_type must match the attester's configured type
        if tee != self.cfg.tee_type {
            return Err(Status::invalid_argument(format!(
                "tee_type mismatch: request={tee:?}, configured={:?}",
                self.cfg.tee_type
            )));
        }
        if req.nonce.is_empty() {
            return Err(Status::invalid_argument("nonce required"));
        }

        // Dispatch to the appropriate evidence builder based on tee_type
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

    // Pre-load the wasm component once at startup — all requests serve the same bytes
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
