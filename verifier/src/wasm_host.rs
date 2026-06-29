//! wasm 组件加载、sha256 白名单校验、调用。

use crate::config::Config;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    path: "../appraisers/wit",
    world: "verifier",
    exports: { default: async },
});

use exports::unified_attestation::verifier::verifier_interface::OptionalData;

pub struct WasmHost {
    engine: Engine,
    allow_unsigned: bool,
    registry_dir: PathBuf,
    /// 受信任的组件 sha256（小写 hex）。allow_unsigned=false 时强制比对。
    trusted_hashes: HashSet<String>,
    registry: RwLock<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    /// component_id -> sha256 hex
    by_id: HashMap<String, String>,
    /// sha256 hex -> component_id
    by_hash: HashMap<String, String>,
    /// component_id -> 已编译组件
    compiled: HashMap<String, Component>,
}

pub struct EvaluateOutcome {
    pub component_id: String,
    pub claims: Value,
}

impl WasmHost {
    pub async fn new(config: &Config) -> Result<Arc<Self>> {
        tokio::fs::create_dir_all(&config.wasm.registry_dir)
            .await
            .with_context(|| format!("create {}", config.wasm.registry_dir.display()))?;

        let mut wasmtime_cfg = wasmtime::Config::new();
        wasmtime_cfg.wasm_component_model(true);
        wasmtime_cfg.async_support(true);
        let engine = Engine::new(&wasmtime_cfg).context("create wasmtime engine")?;

        // 信任锚：allow_unsigned 与 trusted_component_hashes 二选一，避免误配置导致永远拒绝或永远放行
        if !config.wasm.allow_unsigned && config.wasm.trusted_component_hashes.is_empty() {
            anyhow::bail!("wasm: allow_unsigned=false 时必须配置至少一个 trusted_component_hashes");
        }
        if config.wasm.allow_unsigned {
            warn!(
                "wasm component signature verification disabled (allow_unsigned = true). \
                 do not enable in production"
            );
        }

        let trusted_hashes: HashSet<String> = config
            .wasm
            .trusted_component_hashes
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if !trusted_hashes.is_empty() {
            info!(
                trusted_count = trusted_hashes.len(),
                "wasm trusted_component_hashes loaded"
            );
        }

        Ok(Arc::new(Self {
            engine,
            allow_unsigned: config.wasm.allow_unsigned,
            registry_dir: config.wasm.registry_dir.clone(),
            trusted_hashes,
            registry: RwLock::new(RegistryState::default()),
        }))
    }

    /// 注册（或复用）组件，返回 component_id。
    pub async fn register(&self, component_bytes: &[u8]) -> Result<String> {
        let sha = sha256_hex(component_bytes);
        if !self.allow_unsigned && !self.trusted_hashes.contains(&sha) {
            bail!("untrusted wasm component: sha256={sha}");
        }
        {
            let state = self.registry.read().await;
            if let Some(id) = state.by_hash.get(&sha) {
                return Ok(id.clone());
            }
        }

        let component = Component::from_binary(&self.engine, component_bytes)
            .context("compile wasm component")?;
        let id = Uuid::new_v4().to_string();
        let path = self.registry_dir.join(format!("{id}.wasm"));
        tokio::fs::write(&path, component_bytes)
            .await
            .with_context(|| format!("persist {}", path.display()))?;

        let mut state = self.registry.write().await;
        if let Some(existing) = state.by_hash.get(&sha).cloned() {
            // 同步竞争：保留先到达者。
            // 多请求并发上传同一份 wasm 时，先拿到写锁的赢，后到者发现 hash 已注册，
            // 删掉自己写出的 .wasm 文件并复用对方 id；磁盘里始终只保留一份组件。
            drop(state);
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(existing);
        }
        state.by_id.insert(id.clone(), sha.clone());
        state.by_hash.insert(sha, id.clone());
        state.compiled.insert(id.clone(), component);
        info!(component_id = %id, "registered wasm component");
        Ok(id)
    }

    /// 调 evaluate，返回组件解析后的 claims JSON。
    ///
    /// 参数语义：
    /// - `expected_report_data`：challenge nonce 原始字节，wasm 内对照 evidence 中
    ///   绑定字段（CCA realm challenge、TDX report_data 前 32 B、hydra public_input 末位）
    /// - `expected_init_data_hash`：仅 TDX 路径用，对照 mr_config_id；其它 path 传 None
    pub async fn evaluate(
        &self,
        component_id: &str,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
    ) -> Result<EvaluateOutcome> {
        let component = {
            let state = self.registry.read().await;
            state
                .compiled
                .get(component_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown component_id {component_id}"))?
        };

        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).context("add wasi to linker")?;

        let mut store = Store::new(&self.engine, HostState::new());
        let bindings = Verifier::instantiate_async(&mut store, &component, &linker)
            .await
            .context("instantiate component")?;
        let iface = bindings.unified_attestation_verifier_verifier_interface();
        let verifier = iface.verifier();
        let resource = verifier
            .call_constructor(&mut store)
            .await
            .context("call constructor")?;

        let report_data = match expected_report_data {
            Some(v) => OptionalData::Value(v.to_vec()),
            None => OptionalData::NotProvided,
        };
        let init_data = match expected_init_data_hash {
            Some(v) => OptionalData::Value(v.to_vec()),
            None => OptionalData::NotProvided,
        };

        let raw = verifier
            .call_evaluate(&mut store, resource, evidence, &report_data, &init_data)
            .await
            .context("call evaluate")?;

        let claims: Value = serde_json::from_str(&raw)
            .with_context(|| format!("component returned non-json: {raw}"))?;
        if let Some(err) = claims.get("error") {
            bail!("wasm component reported error: {err}");
        }
        // verification 字段不为 "passed" 一律视作拒绝——避免 verify_groth16 返回 false
        // 但组件没显式塞 error 字段时漏放
        let verification = claims
            .get("verification")
            .and_then(|v| v.as_str())
            .unwrap_or("missing");
        if verification != "passed" {
            bail!("verification did not pass: {verification}");
        }
        Ok(EvaluateOutcome {
            component_id: component_id.to_string(),
            claims,
        })
    }
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl HostState {
    fn new() -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
        }
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
