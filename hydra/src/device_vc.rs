//! 设备 VC 链上存储与查询。
//!
//! 通过 EVM 兼容链上的 DeviceVCRecord 合约实现设备可验证凭证的去中心化存储。
//! 链交互通过 `cast` CLI（Foundry 工具链）完成，不引入 Rust 区块链 SDK 依赖。

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

// ── 常量 ────────────────────────────────────────────────────────────

/// VC 信任有效期（天）。
pub const TRUST_TTL_DAYS: i64 = 10;

/// 本地 VC 缓存文件名。
pub const DEVICE_VC_CACHE_FILE: &str = "device_vc_cache.json";

/// 链标识符，用于构造 DID `did:chain:<network>:<pubkey_hash>`。
pub const DEFAULT_NETWORK: &str = "evm";

// ── 配置 ────────────────────────────────────────────────────────────

/// EVM 链配置。从环境变量读取。
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub contract_address: String,
    pub private_key: String,
}

impl ChainConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            rpc_url: std::env::var("CHAIN_RPC_URL")
                .context("CHAIN_RPC_URL not set")?,
            contract_address: std::env::var("CHAIN_CONTRACT_ADDRESS")
                .context("CHAIN_CONTRACT_ADDRESS not set")?,
            private_key: std::env::var("CHAIN_PRIVATE_KEY")
                .context("CHAIN_PRIVATE_KEY not set")?,
        })
    }
}

// ── 数据结构 ────────────────────────────────────────────────────────

/// 设备信任状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Trusted,
    Untrusted,
    Expired,
}

/// VC 元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCInfor {
    /// 设备 DID，格式 `did:chain:<network>:0x<sha256(pubkey)>`
    pub device_did: String,
    /// 设备公钥 hex（compressed secp256k1）
    pub device_pubkey: String,
    /// 信任状态
    pub status: DeviceStatus,
    /// evidence 的 sha256 hex
    pub evidence_hash: String,
    /// 有效期截止时间（ISO 8601）
    pub period: String,
}

/// 完整 VC 记录（本地缓存 + 链上交互用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCRecord {
    /// sha256(device_pubkey_bytes) 的 hex
    pub device_pubkey_hash: String,
    /// VC 元数据
    pub vc_info: DeviceVCInfor,
    /// W3C DID Document（JSON）
    pub did_document: Value,
    /// W3C Verifiable Credential（JSON）
    pub verifiable_credential: Value,
    /// 上链返回的交易 hash（32 字节 hex，`0x` 前缀）
    #[serde(default)]
    pub chain_tx_hash: Option<String>,
}

/// 本地 VC 缓存。
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceVCCache {
    pub devices: Vec<DeviceVCRecord>,
}

impl DeviceVCCache {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("serialize cache")?;
        std::fs::write(path, &raw).with_context(|| format!("write {}", path.display()))
    }

    /// 插入或更新设备记录（按 pubkey_hash 去重）。
    pub fn upsert(&mut self, record: DeviceVCRecord) {
        if let Some(existing) = self
            .devices
            .iter_mut()
            .find(|r| r.device_pubkey_hash == record.device_pubkey_hash)
        {
            *existing = record;
        } else {
            self.devices.push(record);
        }
    }

    /// 将超过 period 的 Trusted 记录标记为 Expired，返回被标记的列表。
    pub fn expire_trusted(&mut self, now_iso: &str) -> Vec<DeviceVCRecord> {
        let mut expired = Vec::new();
        for r in &mut self.devices {
            if matches!(r.vc_info.status, DeviceStatus::Trusted) && r.vc_info.period.as_str() <= now_iso {
                r.vc_info.status = DeviceStatus::Expired;
                expired.push(r.clone());
            }
        }
        expired
    }
}

// ── 链交互（通过 cast CLI）──────────────────────────────────────────

/// 将设备 VC 发布到链上 DeviceVCRecord 合约。
///
/// 等价于：`cast send $CONTRACT "storeVC(bytes32,string)" $HASH "$VC_JSON"`
/// 返回交易 hash（`0x` 前缀 hex）。
pub fn publish_device_vc_to_chain(
    record: &DeviceVCRecord,
    config: &ChainConfig,
) -> Result<String> {
    let vc_json = serde_json::to_string(&record.verifiable_credential)
        .context("serialize vc")?;
    let pubkey_hash = format!(
        "0x{}",
        record
            .device_pubkey_hash
            .strip_prefix("0x")
            .unwrap_or(&record.device_pubkey_hash)
    );
    if pubkey_hash.len() != 66 {
        bail!("pubkey_hash must be 32 bytes hex, got {}", pubkey_hash.len());
    }

    let output = Command::new("cast")
        .args([
            "send",
            &config.contract_address,
            "storeVC(bytes32,string)",
            &pubkey_hash,
            &vc_json,
            "--rpc-url",
            &config.rpc_url,
            "--private-key",
            &config.private_key,
            "--json",
        ])
        .output()
        .context("spawn cast send")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("cast send failed: {stderr}");
    }

    let result: Value =
        serde_json::from_slice(&output.stdout).context("parse cast output")?;
    let tx_hash = result["transactionHash"]
        .as_str()
        .context("missing transactionHash in cast output")?;
    Ok(tx_hash.to_string())
}

/// 从链上 DeviceVCRecord 合约查询设备的最新 VC。
///
/// 等价于：`cast call $CONTRACT "getVC(bytes32)" $HASH`
/// 返回 (vcJson, timestamp) 元组。
pub fn query_device_vc_from_chain(
    device_pubkey: &str,
    config: &ChainConfig,
) -> Result<Value> {
    let pubkey_bytes =
        hex::decode(device_pubkey).context("decode device_pubkey hex")?;
    let pubkey_hash = public_key_hash_hex(&pubkey_bytes);
    let hash_arg = format!("0x{pubkey_hash}");

    let output = Command::new("cast")
        .args([
            "call",
            &config.contract_address,
            "getVC(bytes32)(string,uint256)",
            &hash_arg,
            "--rpc-url",
            &config.rpc_url,
        ])
        .output()
        .context("spawn cast call")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("cast call failed: {stderr}");
    }

    // cast call 返回 ABI 编码的 (string, uint256)
    // 用 cast --abi-decode 解出 vc_json
    let raw = String::from_utf8(output.stdout).context("cast output not utf-8")?;
    let raw = raw.trim();

    if raw == "0x" || raw.is_empty() {
        return Ok(Value::Null);
    }

    let decode_output = Command::new("cast")
        .args([
            "abi-decode",
            "getVC(bytes32)(string,uint256)",
            raw,
        ])
        .output()
        .context("spawn cast abi-decode")?;

    if !decode_output.status.success() {
        // 可能返回空值 (0x0...0)
        return Ok(Value::Null);
    }

    let decoded = String::from_utf8(decode_output.stdout).context("decode output not utf-8")?;
    let decoded = decoded.trim();

    // 输出格式: ["<vc_json>", <timestamp>] 或 ["", 0]
    if decoded.starts_with("[\"\"") || decoded == "[]" {
        return Ok(Value::Null);
    }

    // 提取第一个字符串参数（vc_json）
    let v: Value = serde_json::from_str(decoded).context("parse abi-decode output")?;
    let vc_str = v[0].as_str().unwrap_or("");
    if vc_str.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(vc_str).context("parse vc json from chain")
}

// ── VC 构造 ─────────────────────────────────────────────────────────

/// 构造 background-check VC 记录。
pub fn build_background_check_record(
    device_pubkey: &str,
    evidence_hash: &str,
    network: &str,
    now_iso: &str,
    has_evidence: bool,
) -> DeviceVCRecord {
    let pubkey_bytes = hex::decode(device_pubkey).unwrap_or_default();
    let pubkey_hash = public_key_hash_hex(&pubkey_bytes);
    let device_did = format!("did:chain:{network}:0x{pubkey_hash}");

    let period = if has_evidence {
        chrono_iso(now_iso, TRUST_TTL_DAYS)
    } else {
        now_iso.to_string()
    };

    let vc_info = DeviceVCInfor {
        device_did: device_did.clone(),
        device_pubkey: device_pubkey.to_string(),
        status: if has_evidence {
            DeviceStatus::Trusted
        } else {
            DeviceStatus::Untrusted
        },
        evidence_hash: evidence_hash.to_string(),
        period,
    };

    let verifier_did = format!("did:chain:{network}:verifier");
    let vc = build_device_vc(&verifier_did, &vc_info);
    let did_doc = build_device_did_document(network, &pubkey_hash, &device_did);

    DeviceVCRecord {
        device_pubkey_hash: pubkey_hash,
        vc_info,
        did_document: did_doc,
        verifiable_credential: vc,
        chain_tx_hash: None,
    }
}

// ── 辅助函数 ────────────────────────────────────────────────────────

/// sha256(device_pubkey_bytes) → hex
pub fn public_key_hash_hex(public_key_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key_bytes);
    hex::encode(h.finalize())
}

fn build_device_vc(issuer_did: &str, info: &DeviceVCInfor) -> Value {
    serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": ["VerifiableCredential", "DeviceCredential"],
        "issuer": issuer_did,
        "issuanceDate": info.period,
        "credentialSubject": {
            "id": info.device_did,
            "device_pubkey": info.device_pubkey,
            "status": match info.status {
                DeviceStatus::Trusted => "trusted",
                DeviceStatus::Untrusted => "untrusted",
                DeviceStatus::Expired => "expired",
            },
            "evidence_hash": info.evidence_hash,
        }
    })
}

fn build_device_did_document(network: &str, pubkey_hash: &str, device_did: &str) -> Value {
    serde_json::json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": device_did,
        "verificationMethod": [{
            "id": format!("{device_did}#keys-1"),
            "type": "EcdsaSecp256k1VerificationKey2019",
            "controller": device_did,
            "blockchainAccountId": format!("eip155:{network}:0x{pubkey_hash}")
        }],
        "authentication": [format!("{device_did}#keys-1")]
    })
}

/// 日期偏移（天）。ponytail: 不引入 chrono crate，直接做 ISO 日期加减。
fn chrono_iso(now_iso: &str, add_days: i64) -> String {
    // 解析 "2026-01-15T00:00:00Z" 或 "2026-01-15" 格式
    let date_part = now_iso.split('T').next().unwrap_or(now_iso);
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() < 3 {
        return now_iso.to_string();
    }
    let year: i64 = parts[0].parse().unwrap_or(0);
    let month: i64 = parts[1].parse().unwrap_or(0);
    let day: i64 = parts[2].parse().unwrap_or(0);

    let days_in_month = |m: i64, y: i64| -> i64 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                    29
                } else {
                    28
                }
            }
            _ => 30,
        }
    };

    let mut d = day + add_days;
    let mut m = month;
    let mut y = year;
    while d > days_in_month(m, y) {
        d -= days_in_month(m, y);
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}
