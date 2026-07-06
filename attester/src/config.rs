//! Attester configuration (TOML).

use anyhow::{Context, Result};
use protos::TeeType;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// attester gRPC listen address, e.g. `127.0.0.1:9000`
    pub listen: String,
    /// TEE type of this attester instance (custom deserializer: kebab string → proto enum)
    #[serde(deserialize_with = "deser_tee_type")]
    pub tee_type: TeeType,
    /// Path to the local wasm component binary
    pub wasm_component_path: PathBuf,
    /// Hydra trusted setup artifacts (only for hydra-stacking paths)
    #[serde(default)]
    pub zk: Option<ZkConfig>,
    /// guest-components api-server-rest address for evidence collection.
    /// Used by CCA / CSV / TDX / iTrustee / VirtCCA paths.
    #[serde(default = "default_aa_endpoint")]
    pub aa_endpoint: String,
}

/// Parse a kebab-case tee_type string to the proto enum.
pub fn parse_tee_type(s: &str) -> Result<TeeType> {
    match s {
        "mock" => Ok(TeeType::Mock),
        "cca" => Ok(TeeType::Cca),
        "cca-hydra" => Ok(TeeType::CcaHydra),
        "csv" => Ok(TeeType::Csv),
        "csv-hydra" => Ok(TeeType::CsvHydra),
        "tdx" => Ok(TeeType::Tdx),
        "tdx-hydra" => Ok(TeeType::TdxHydra),
        "itrustee" => Ok(TeeType::Itrustee),
        "virtcca" => Ok(TeeType::Virtcca),
        other => anyhow::bail!("unknown tee_type '{other}'"),
    }
}

fn deser_tee_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TeeType, D::Error> {
    let s = String::deserialize(d)?;
    parse_tee_type(&s).map_err(serde::de::Error::custom)
}

/// Hydra zero-knowledge configuration (for hydra-stacking paths only).
#[derive(Debug, Deserialize)]
pub struct ZkConfig {
    pub proving_key_path: PathBuf,
    pub verifying_key_path: PathBuf,
    /// Shrubs whitelist: device list + self_index for this attester.
    pub whitelist: WhitelistConfig,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistConfig {
    /// Device list: each device provides a (pk, sk, ar) triple.
    /// In the demo, small decimal integers represent Fr elements. In production,
    /// these should come from a secure device registration process.
    pub devices: Vec<DeviceEntry>,
    /// Index of this attester in `devices`. The leaf must fall on a reachable
    /// Merkle path of the shrubs root list — positions on root boundaries are invalid.
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
