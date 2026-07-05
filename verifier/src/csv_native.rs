//! Host 端 Hygon CSV evidence 验签（参考 anolis-trustee deps/verifier/src/csv/mod.rs）。
//!
//! csv-rs 用 openssl 跑 P-384 ECDSA + 链式验签，不能跨 wasm32-wasip1，
//! 与 ccatoken 同位置：host 端验签，wasm appraiser 仅做字段透传与 nonce 比对。
//!
//! 链：HRK(self-signed) → HSK → CEK → PEK → TEE attestation report。
//! HRK 内嵌（`verifier/assets/hygon_hrk.cert`），HSK/CEK 由 evidence 自带或现配 chip_id 在线拉取。

use crate::config::CsvPolicy;
use anyhow::{Context, Result, anyhow, bail};
use codicon::Decoder;
use csv_rs::api::guest::{AttestationReport, AttestationReportWrapper};
use csv_rs::certs::{Verifiable, ca, csv};
use serde::Deserialize;
use std::io::Cursor;
use tracing::info;

const HRK: &[u8] = include_bytes!("../assets/hygon_hrk.cert");

#[derive(Deserialize)]
struct HskCek {
    hsk: ca::Certificate,
    cek: csv::Certificate,
}

#[derive(Deserialize)]
struct CertificateChain {
    #[serde(default)]
    hsk_cek: Option<HskCek>,
    pek: csv::Certificate,
}

#[derive(Deserialize)]
struct CsvEvidenceJson {
    attestation_report: AttestationReportWrapper,
    cert_chain: CertificateChain,
    serial_number: Vec<u8>,
}

/// CSV 验证结果（含从 attestation report 中提取的度量值）。
pub struct CsvVerificationResult {
    /// 芯片 ID（serial_number trim 尾部 \0）
    pub chip_id: Option<String>,
    /// 度量值（hex）
    pub measurement: Option<String>,
    /// VM 版本号
    pub vm_version: Option<String>,
    /// 策略：是否禁止调试（0=false, 1=true）
    pub policy_nodbg: Option<u32>,
    /// 策略：是否禁止密钥共享（0=false, 1=true）
    pub policy_noks: Option<u32>,
}

pub struct CsvVerifier {
    policy: CsvPolicy,
}

impl CsvVerifier {
    pub fn load(policy: &CsvPolicy) -> Option<Self> {
        if !policy.enabled {
            return None;
        }
        Some(Self {
            policy: CsvPolicy {
                enabled: policy.enabled,
                cert_dir: policy.cert_dir.clone(),
                allow_kds_fetch: policy.allow_kds_fetch,
                trusted_chip_ids: policy.trusted_chip_ids.clone(),
            },
        })
    }

    /// 完整验：链证书（HRK→HSK→CEK→PEK→report）+ report_data nonce 绑定。
    /// 返回结构化验证结果，含芯片 ID 与度量值。
    pub fn verify(&self, evidence: &[u8], expected_report_data: &[u8]) -> Result<CsvVerificationResult> {
        let parsed: CsvEvidenceJson =
            serde_json::from_slice(evidence).context("decode CSV evidence JSON")?;

        let report = AttestationReport::try_from(&parsed.attestation_report)
            .map_err(|e| anyhow!("parse CSV attestation report: {e}"))?;
        let chip_id = std::str::from_utf8(&parsed.serial_number)
            .context("decode serial_number")?
            .trim_end_matches('\0')
            .to_string();

        let (hsk, cek, pek) = match parsed.cert_chain.hsk_cek {
            Some(h) => (h.hsk, h.cek, parsed.cert_chain.pek),
            None => {
                let cert_data = self
                    .load_hsk_cek(&chip_id)
                    .with_context(|| format!("load HSK/CEK for chip {chip_id}"))?;
                let mut reader = Cursor::new(cert_data);
                let hsk = ca::Certificate::decode(&mut reader, ())
                    .map_err(|e| anyhow!("decode HSK: {e}"))?;
                let cek = csv::Certificate::decode(&mut reader, ())
                    .map_err(|e| anyhow!("decode CEK: {e}"))?;
                (hsk, cek, parsed.cert_chain.pek)
            }
        };

        verify_chain(&report, hsk, cek, pek)?;

        // CSV attestation report 的 report_data 固定 64 字节，nonce(32B) 不足右补 0
        let mut expected = expected_report_data.to_vec();
        expected.resize(64, 0);
        if expected.as_slice() != report.tee_info().report_data() {
            bail!("CSV report_data does not match expected nonce");
        }

        if !self.policy.trusted_chip_ids.is_empty()
            && !self.policy.trusted_chip_ids.iter().any(|x| x == &chip_id)
        {
            bail!("CSV chip_id '{chip_id}' not in trusted list");
        }

        // 提取度量值（注：csv-rs 的度量字段在 tee_info() 上）
        let tee = report.tee_info();
        let measure_bytes = tee.measure();
        let measurement = (!measure_bytes.is_empty()).then(|| hex::encode(&measure_bytes));
        let vm_version = Some(hex::encode(&tee.vm_version()));
        let policy = tee.policy();
        let policy_nodbg = Some(policy.nodbg());
        let policy_noks = Some(policy.noks());

        info!(%chip_id, "CSV host verify passed");
        Ok(CsvVerificationResult {
            chip_id: Some(chip_id),
            measurement,
            vm_version,
            policy_nodbg,
            policy_noks,
        })
    }

    /// 离线优先：<cert_dir>/hsk_cek/<chip_id>/hsk_cek.cert；
    /// 否则 GET https://cert.hygon.cn/hsk_cek?snumber=<chip_id>。
    /// ponytail: 同步 ureq，避免引入 reqwest+tokio runtime 复用问题。
    fn load_hsk_cek(&self, chip_id: &str) -> Result<Vec<u8>> {
        let local = self
            .policy
            .cert_dir
            .join("hsk_cek")
            .join(chip_id)
            .join("hsk_cek.cert");
        if let Ok(b) = std::fs::read(&local) {
            return Ok(b);
        }
        if !self.policy.allow_kds_fetch {
            bail!(
                "HSK/CEK not found at {} and policy.csv.allow_kds_fetch=false",
                local.display()
            );
        }
        let url = format!("https://cert.hygon.cn/hsk_cek?snumber={chip_id}");
        let resp = ureq::get(&url)
            .call()
            .with_context(|| format!("GET {url}"))?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)
            .context("read HSK/CEK body")?;
        Ok(buf)
    }
}

fn verify_chain(
    report: &AttestationReport,
    hsk: ca::Certificate,
    cek: csv::Certificate,
    pek: csv::Certificate,
) -> Result<()> {
    let hrk = ca::Certificate::decode(&mut &HRK[..], ()).map_err(|e| anyhow!("decode HRK: {e}"))?;
    (&hrk, &hrk).verify().map_err(|e| anyhow!("HRK self-sign: {e}"))?;
    (&hrk, &hsk).verify().map_err(|e| anyhow!("HSK signed by HRK: {e}"))?;
    (&hsk, &cek).verify().map_err(|e| anyhow!("CEK signed by HSK: {e}"))?;
    (&cek, &pek).verify().map_err(|e| anyhow!("PEK signed by CEK: {e}"))?;
    (&pek, &report.tee_info())
        .verify()
        .map_err(|e| anyhow!("report signed by PEK: {e}"))?;
    Ok(())
}
