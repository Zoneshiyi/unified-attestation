//! verifier 配置。

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: String,
    #[serde(default)]
    pub wasm: WasmConfig,
    pub ear: EarConfig,
    /// 各 TEE 类型的 policy。缺省允许任意 root，供 demo 使用。
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
}

#[derive(Debug, Default, Deserialize)]
pub struct HydraZkPolicy {
    /// 可信 shrubs root 列表（小写 hex，每根 32 字节 / 64 字符）。
    /// 非空时，wasm 组件返回的 `roots_hex` 必须按顺序逐一相等，否则 verifier 拒收。
    /// 空表示不校验，仅 demo / 开发期使用。
    #[serde(default)]
    pub trusted_roots_hex: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CcaPolicy {
    /// ccatoken trust anchor store 路径（含 IAK 公钥等信任锚）。
    /// 缺省时跳过 host 端验签，仅作 demo 用，不可用于生产。
    #[serde(default)]
    pub ta_store: Option<PathBuf>,
    /// ccatoken reference value store 路径（含 platform / realm 期望测量值）。
    #[serde(default)]
    pub rv_store: Option<PathBuf>,
    /// 可信 Realm 主体标识列表。非空时，verifier 比对 claims 中 `cca-realm-initial-measurement`
    /// 是否命中此列表（小写 hex），用于业务级白名单。
    #[serde(default)]
    pub trusted_subjects: Vec<String>,
}

/// Hygon CSV policy。host 端 csv-rs 验签 + nonce 绑定。
#[derive(Debug, Deserialize)]
pub struct CsvPolicy {
    /// 是否启用 host 端验签。false 时整体跳过 CSV 验签（仅 demo / 联调）。
    #[serde(default)]
    pub enabled: bool,
    /// HSK/CEK 离线缓存目录，按 `<dir>/hsk_cek/<chip_id>/hsk_cek.cert` 查找。
    #[serde(default = "default_csv_cert_dir")]
    pub cert_dir: PathBuf,
    /// 离线缓存未命中时是否走在线 KDS（https://cert.hygon.cn/hsk_cek）拉取。
    #[serde(default)]
    pub allow_kds_fetch: bool,
    /// 可信 chip_id 列表（serial_number 文本去尾零）。空表示不做 chip 白名单。
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
    /// PCCS 或 Intel PCS URL，host 端按 fmspc 拉 collateral 用。默认走 Intel 公网。
    #[serde(default = "default_pccs_url")]
    pub pccs_url: String,
    /// 可信 mr_td 列表（小写 hex，48 字节 / 96 字符）。
    #[serde(default)]
    pub trusted_mr_td_hex: Vec<String>,
    /// 可信 mr_seam（Intel 签名的 SEAM 模块测量）。
    #[serde(default)]
    pub trusted_mr_seam_hex: Vec<String>,
    /// 可信 mr_config_id（init_data_hash），与 expected_init_data_hash 对应。
    /// 非空时，wasm appraiser 收到的 expected_init_data_hash 也必须命中此列表。
    #[serde(default)]
    pub trusted_mr_config_id_hex: Vec<String>,
    /// 可接受的 TCB status，例如 ["UpToDate"] / ["UpToDate", "SwHardeningNeeded"]。
    /// 空表示不校验，仅 demo 用。
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

#[derive(Debug, Deserialize)]
pub struct WasmConfig {
    /// 调试逃生通道：置 true 时 verifier 接受任意上传的 wasm 字节，仅供开发期使用。
    /// 与 `trusted_component_hashes` 二选一：默认 false，必须配置至少一个 hash。
    #[serde(default)]
    pub allow_unsigned: bool,
    /// 已注册组件持久化目录。
    #[serde(default = "default_components_dir")]
    pub registry_dir: PathBuf,
    /// 受信任的组件 sha256（小写 hex）白名单。`allow_unsigned = false` 时，
    /// 注册组件必须命中此列表，否则 verifier 拒绝加载。
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
    /// EAR JWT 签名私钥（PEM 格式）路径。算法固定 ES256。
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
