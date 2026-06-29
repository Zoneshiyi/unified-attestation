//! attester 配置。

use anyhow::{Context, Result};
use protos::TeeType;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// attester gRPC 监听地址，例 `127.0.0.1:9000`。
    pub listen: String,
    #[serde(deserialize_with = "deser_tee_type")]
    pub tee_type: TeeType,
    pub wasm_component_path: PathBuf,
    /// 仅 hydra 模式使用：trusted setup 产物路径
    #[serde(default)]
    pub zk: Option<ZkConfig>,
    /// CCA 模式：guest-components api-server-rest 地址，默认 127.0.0.1:8006
    #[serde(default = "default_aa_endpoint")]
    pub aa_endpoint: String,
}

pub fn parse_tee_type(s: &str) -> Result<TeeType> {
    match s {
        "mock" => Ok(TeeType::Mock),
        "cca" => Ok(TeeType::Cca),
        "cca-hydra" => Ok(TeeType::CcaHydra),
        "csv" => Ok(TeeType::Csv),
        "csv-hydra" => Ok(TeeType::CsvHydra),
        "tdx" => Ok(TeeType::Tdx),
        "tdx-hydra" => Ok(TeeType::TdxHydra),
        other => anyhow::bail!("unknown tee_type '{other}'"),
    }
}

fn deser_tee_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TeeType, D::Error> {
    let s = String::deserialize(d)?;
    parse_tee_type(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct ZkConfig {
    pub proving_key_path: PathBuf,
    pub verifying_key_path: PathBuf,
    /// shrubs whitelist：设备列表 + self_index。
    pub whitelist: WhitelistConfig,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistConfig {
    /// 设备列表：每个 device 提供 (pk, sk, ar) 三元组（demo 用十进制小整数表达 Fr）。
    /// 真实部署中应来自安全的设备注册流程，这里仅用于完整链路演示。
    pub devices: Vec<DeviceEntry>,
    /// 当前 attester 在 `devices` 中的下标。circuit 走完整 path 校验时此 leaf 必须落在
    /// shrubs root 列表的可达 Merkle path 上（即不能选 hydra shrubs 中"落单"的位置）。
    pub self_index: usize,
}

#[derive(Debug, Deserialize)]
pub struct DeviceEntry {
    pub pk: u64,
    pub sk: u64,
    pub ar: u64,
}

fn default_aa_endpoint() -> String {
    "http://127.0.0.1:8006".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parse toml {}", path.display()))
    }
}
