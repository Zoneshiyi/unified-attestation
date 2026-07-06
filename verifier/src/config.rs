//! Verifier configuration (TOML).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Root verifier config, loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: String,
    #[serde(default)]
    pub wasm: WasmConfig,
    pub ear: EarConfig,
    /// Per-TEE-type policies. Default (all empty) allows any measurement; demo only.
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub hydra: HydraZkPolicy,
    #[serde(default)]
    pub cca: CcaPolicy,
    #[serde(default)]
    pub csv: CsvPolicy,
    #[serde(default)]
    pub tdx: TdxPolicy,
    #[serde(default)]
    pub itrustee: ItrusteePolicy,
    #[serde(default)]
    pub virtcca: VirtccaPolicy,
}

#[derive(Debug, Default, Deserialize)]
pub struct HydraZkPolicy {
    /// Trusted shrubs root list (lowercase hex, 32 bytes / 64 chars per root).
    /// When non-empty, the `roots_hex` returned by the wasm component must match
    /// position-by-position; otherwise the verifier rejects. Empty = no check (demo only).
    #[serde(default)]
    pub trusted_roots_hex: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CcaPolicy {
    /// ccatoken trust anchor store path (contains IAK public keys and other trust anchors).
    /// When absent, host-side verification is skipped (demo only, not for production).
    #[serde(default)]
    pub ta_store: Option<PathBuf>,
    /// ccatoken reference value store path (contains platform/realm expected measurements).
    #[serde(default)]
    pub rv_store: Option<PathBuf>,
    /// Trusted realm subject list. When non-empty, the verifier checks claims
    /// `cca_realm_initial_measurement` against this list (lowercase hex).
    #[serde(default)]
    pub trusted_subjects: Vec<String>,
    /// Trusted Realm Initial Measurement list (hex). When non-empty, wasm-returned
    /// `cca_realm_initial_measurement` must match an entry in this list.
    #[serde(default)]
    pub trusted_rim_hex: Vec<String>,
}

/// Hygon CSV policy: host-side csv-rs verification + nonce binding.
#[derive(Debug, Deserialize)]
pub struct CsvPolicy {
    /// Whether to enable host-side verification. false → skip entirely (demo only).
    #[serde(default)]
    pub enabled: bool,
    /// HSK/CEK offline cache directory, searched as `<dir>/hsk_cek/<chip_id>/hsk_cek.cert`.
    #[serde(default = "default_csv_cert_dir")]
    pub cert_dir: PathBuf,
    /// Whether to fetch from the online KDS (https://cert.hygon.cn/hsk_cek) on cache miss.
    #[serde(default)]
    pub allow_kds_fetch: bool,
    /// Trusted chip_id list (serial_number text, trailing nulls trimmed). Empty = no whitelist.
    #[serde(default)]
    pub trusted_chip_ids: Vec<String>,
}

impl Default for CsvPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_dir: default_csv_cert_dir(),
            allow_kds_fetch: false,
            trusted_chip_ids: Vec::new(),
        }
    }
}

fn default_csv_cert_dir() -> PathBuf {
    PathBuf::from("/opt/hygon/csv")
}

#[derive(Debug, Deserialize)]
pub struct TdxPolicy {
    /// PCCS or Intel PCS URL for host-side collateral fetch by fmspc. Defaults to Intel public.
    #[serde(default = "default_pccs_url")]
    pub pccs_url: String,
    /// Trusted mr_td list (lowercase hex, 48 bytes / 96 chars).
    #[serde(default)]
    pub trusted_mr_td_hex: Vec<String>,
    /// Trusted mr_seam (Intel-signed SEAM module measurement).
    #[serde(default)]
    pub trusted_mr_seam_hex: Vec<String>,
    /// Trusted mr_config_id (init_data_hash), corresponds to expected_init_data_hash.
    /// When non-empty, the wasm appraiser's expected_init_data_hash must also match.
    #[serde(default)]
    pub trusted_mr_config_id_hex: Vec<String>,
    /// Acceptable TCB status values, e.g. ["UpToDate"] / ["UpToDate", "SWHardeningNeeded"].
    /// Empty = no check (demo only).
    #[serde(default)]
    pub accept_tcb_status: Vec<String>,
}

impl Default for TdxPolicy {
    fn default() -> Self {
        Self {
            pccs_url: default_pccs_url(),
            trusted_mr_td_hex: Vec::new(),
            trusted_mr_seam_hex: Vec::new(),
            trusted_mr_config_id_hex: Vec::new(),
            accept_tcb_status: Vec::new(),
        }
    }
}

fn default_pccs_url() -> String {
    "https://api.trustedservices.intel.com".to_string()
}

/// iTrustee policy (reserved; native verification requires libteeverifier.so).
#[derive(Debug, Default, Deserialize)]
pub struct ItrusteePolicy {
    /// Trusted TA UUID list. Empty = skip.
    #[serde(default)]
    pub trusted_uuids: Vec<String>,
    /// Trusted TA measurement list (hex). Empty = skip.
    #[serde(default)]
    pub trusted_ta_img_hex: Vec<String>,
}

/// VirtCCA policy (reserved; native verification requires libvccaattestation.so + OpenSSL).
#[derive(Debug, Default, Deserialize)]
pub struct VirtccaPolicy {
    /// Trusted RIM list (hex). Empty = skip.
    #[serde(default)]
    pub trusted_rim_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WasmConfig {
    /// Debug escape hatch: when true, the verifier accepts any uploaded wasm bytes
    /// (development only). Mutually exclusive with trusted_component_hashes: when false,
    /// at least one hash must be configured.
    #[serde(default)]
    pub allow_unsigned: bool,
    /// Persistent directory for registered component binaries.
    #[serde(default = "default_components_dir")]
    pub registry_dir: PathBuf,
    /// Trusted component sha256 whitelist (lowercase hex). When allow_unsigned is false,
    /// registered components must match an entry in this list.
    #[serde(default)]
    pub trusted_component_hashes: Vec<String>,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            allow_unsigned: false,
            registry_dir: default_components_dir(),
            trusted_component_hashes: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EarConfig {
    /// EAR JWT signing private key path (PEM format). Algorithm is fixed to ES256.
    pub signing_key_path: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parse toml {}", path.display()))
    }
}

fn default_components_dir() -> PathBuf {
    PathBuf::from("data/components")
}
