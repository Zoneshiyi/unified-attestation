//! Trusted setup
//!
//! 由独立工具调用，产生 (pk, vk) 字节流；unified-attestation demo 在启动脚本中预生成一次。
//!
//! AttestationCircuit 的电路形状由 root 槽位数与 path 长度决定，setup 时必须确定。

use crate::circuit::AttestationCircuit;
use alloc::{vec, vec::Vec};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

pub struct SetupArtifacts {
    pub pk_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

pub fn run_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
    root_count: usize,
    path_len: usize,
) -> Result<SetupArtifacts, &'static str> {
    let placeholder = AttestationCircuit {
        pk: Fr::from(0u64),
        sk: Fr::from(0u64),
        ar: Fr::from(0u64),
        time: Fr::from(0u64),
        period: Fr::from(0u64),
        output: Fr::from(0u64),
        root: vec![Fr::from(0u64); root_count],
        path: vec![Fr::from(0u64); path_len],
        tag: vec![false; path_len],
        challenge: Fr::from(0u64),
    };
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(placeholder, rng)
        .map_err(|_| "setup failed")?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|_| "pk serialize")?;
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|_| "vk serialize")?;
    Ok(SetupArtifacts { pk_bytes, vk_bytes })
}
