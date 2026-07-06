//! On-chain device VC storage and querying.
//!
//! Decentralized storage of device verifiable credentials via the DeviceVCRecord contract
//! on an EVM-compatible chain. Chain interaction uses the `cast` CLI (Foundry toolchain)
//! rather than pulling in a Rust blockchain SDK dependency.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

// ── Constants ────────────────────────────────────────────────────────────

/// VC trust validity period (days).
pub const TRUST_TTL_DAYS: i64 = 10;

/// Local VC cache filename.
pub const DEVICE_VC_CACHE_FILE: &str = "device_vc_cache.json";

/// Chain identifier used to construct DIDs: `did:chain:<network>:<pubkey_hash>`.
pub const DEFAULT_NETWORK: &str = "evm";

// ── Configuration ────────────────────────────────────────────────────────

/// EVM chain configuration, read from environment variables.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub contract_address: String,
    pub private_key: String,
}

impl ChainConfig {
    /// Build config from environment variables. Fails with context if any var is missing.
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

// ── Data structures ──────────────────────────────────────────────────────

/// Device trust status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Trusted,
    Untrusted,
    Expired,
}

/// VC metadata for a single device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCInfor {
    /// Device DID, format: `did:chain:<network>:0x<sha256(pubkey)>`
    pub device_did: String,
    /// Device public key hex (compressed secp256k1)
    pub device_pubkey: String,
    /// Trust status
    pub status: DeviceStatus,
    /// SHA-256 hex digest of the evidence
    pub evidence_hash: String,
    /// Expiry time (ISO 8601)
    pub period: String,
}

/// Full VC record used for local caching and chain interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCRecord {
    /// Hex-encoded sha256(device_pubkey_bytes)
    pub device_pubkey_hash: String,
    /// VC metadata
    pub vc_info: DeviceVCInfor,
    /// W3C DID Document (JSON)
    pub did_document: Value,
    /// W3C Verifiable Credential (JSON)
    pub verifiable_credential: Value,
    /// Transaction hash returned from on-chain publish (32-byte hex, `0x`-prefixed)
    #[serde(default)]
    pub chain_tx_hash: Option<String>,
}

/// Local VC cache persisted to disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceVCCache {
    pub devices: Vec<DeviceVCRecord>,
}

impl DeviceVCCache {
    /// Load the cache from disk, or return an empty default if the file does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    /// Write the cache to disk as pretty-printed JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("serialize cache")?;
        std::fs::write(path, &raw).with_context(|| format!("write {}", path.display()))
    }

    /// Insert or update a device record (deduplicated by pubkey_hash).
    pub fn upsert(&mut self, record: DeviceVCRecord) {
        // Find existing record by pubkey_hash; replace if found, push otherwise
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

    /// Mark all Trusted records whose period has passed as Expired.
    /// Returns the list of records that were expired.
    pub fn expire_trusted(&mut self, now_iso: &str) -> Vec<DeviceVCRecord> {
        let mut expired = Vec::new();
        for r in &mut self.devices {
            // Compare ISO 8601 strings lexicographically: "2026-01-15T00:00:00Z" <= now means expired
            if matches!(r.vc_info.status, DeviceStatus::Trusted) && r.vc_info.period.as_str() <= now_iso {
                r.vc_info.status = DeviceStatus::Expired;
                expired.push(r.clone());
            }
        }
        expired
    }
}

// ── Chain interaction (via cast CLI) ─────────────────────────────────────

/// Publish a device VC to the on-chain DeviceVCRecord contract.
///
/// Equivalent to: `cast send $CONTRACT "storeVC(bytes32,string)" $HASH "$VC_JSON"`
/// Returns the transaction hash (`0x`-prefixed hex).
pub fn publish_device_vc_to_chain(
    record: &DeviceVCRecord,
    config: &ChainConfig,
) -> Result<String> {
    // Serialize the VC JSON for the contract call
    let vc_json = serde_json::to_string(&record.verifiable_credential)
        .context("serialize vc")?;
    // Ensure pubkey_hash is normalized to 0x-prefixed 32-byte hex
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

    // Invoke cast send to call the contract's storeVC function
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

    // Parse the JSON output to extract transactionHash
    let result: Value =
        serde_json::from_slice(&output.stdout).context("parse cast output")?;
    let tx_hash = result["transactionHash"]
        .as_str()
        .context("missing transactionHash in cast output")?;
    Ok(tx_hash.to_string())
}

/// Query the latest VC for a device from the on-chain DeviceVCRecord contract.
///
/// Equivalent to: `cast call $CONTRACT "getVC(bytes32)" $HASH`
/// Returns (vcJson, timestamp) as a parsed JSON value.
pub fn query_device_vc_from_chain(
    device_pubkey: &str,
    config: &ChainConfig,
) -> Result<Value> {
    // Compute the pubkey hash from the raw public key bytes
    let pubkey_bytes =
        hex::decode(device_pubkey).context("decode device_pubkey hex")?;
    let pubkey_hash = public_key_hash_hex(&pubkey_bytes);
    let hash_arg = format!("0x{pubkey_hash}");

    // Call the contract's getVC view function
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

    // cast call returns ABI-encoded (string, uint256); decode with cast abi-decode
    let raw = String::from_utf8(output.stdout).context("cast output not utf-8")?;
    let raw = raw.trim();

    // Empty result (0x or blank) means no VC stored yet
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
        // May return zero-value encoding (0x0...0) when no record exists
        return Ok(Value::Null);
    }

    let decoded = String::from_utf8(decode_output.stdout).context("decode output not utf-8")?;
    let decoded = decoded.trim();

    // Output format: ["<vc_json>", <timestamp>] or ["", 0]
    if decoded.starts_with("[\"\"") || decoded == "[]" {
        return Ok(Value::Null);
    }

    // Extract the first string argument (vc_json) from the decoded array
    let v: Value = serde_json::from_str(decoded).context("parse abi-decode output")?;
    let vc_str = v[0].as_str().unwrap_or("");
    if vc_str.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(vc_str).context("parse vc json from chain")
}

// ── VC construction ──────────────────────────────────────────────────────

/// Build a background-check VC record for a device.
///
/// If `has_evidence` is true, the device is marked Trusted with a future expiry;
/// otherwise it is Untrusted with the current timestamp as period.
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

    // Set expiry: TRUST_TTL_DAYS from now if trusted, otherwise immediate
    let period = if has_evidence {
        chrono_iso(now_iso, TRUST_TTL_DAYS)
    } else {
        now_iso.to_string()
    };

    // Determine initial status from evidence presence
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

    // Build the W3C DID document and VC from the metadata
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

// ── Helpers ──────────────────────────────────────────────────────────────

/// Compute sha256(public_key_bytes) and return as lowercase hex.
pub fn public_key_hash_hex(public_key_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key_bytes);
    hex::encode(h.finalize())
}

/// Build a W3C Verifiable Credential JSON object for a device.
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

/// Build a W3C DID Document JSON object for a device.
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

/// Offset an ISO 8601 date string by a number of days.
///
/// ponytail: manual ISO date arithmetic instead of pulling in the chrono crate.
/// Handles "2026-01-15T00:00:00Z" and "2026-01-15" formats.
fn chrono_iso(now_iso: &str, add_days: i64) -> String {
    // Extract the date part before any 'T' separator
    let date_part = now_iso.split('T').next().unwrap_or(now_iso);
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() < 3 {
        return now_iso.to_string();
    }
    let year: i64 = parts[0].parse().unwrap_or(0);
    let month: i64 = parts[1].parse().unwrap_or(0);
    let day: i64 = parts[2].parse().unwrap_or(0);

    // Closure to compute days in a given month, accounting for leap years
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

    // Add days, carrying overflow into months and years
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
