//! Groth16 verify 包装
//!
//! 给 wasm 验证组件用。设计目标：
//! - 输入是字节流（VK / proof / public input），不直接暴露 ark 类型
//! - 错误用 `&'static str` 携带，避免给调用方塞 ark 错误类型

use alloc::vec::Vec;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

pub fn verify_groth16(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[Fr],
) -> Result<bool, &'static str> {
    let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes)
        .map_err(|_| "invalid verifying key")?;
    let proof =
        Proof::<Bls12_381>::deserialize_compressed(proof_bytes).map_err(|_| "invalid proof")?;
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).map_err(|_| "process_vk failed")?;
    Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, public_inputs, &proof)
        .map_err(|_| "verify failed")
}

/// 反序列化 public input 字段元素列表（每元素 32 字节，compressed）
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, &'static str> {
    if !bytes.len().is_multiple_of(32) {
        return Err("public inputs not 32-byte aligned");
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let fr = Fr::deserialize_compressed(chunk).map_err(|_| "invalid field element")?;
        out.push(fr);
    }
    Ok(out)
}

/// 把 Fr 序列化为 32 字节 compressed 字节流。失败时返回长度 0 的 vec——
/// 仅用于 wasm 组件回填 claims 这一类"序列化必然成功"的场景，避免外露 ark 错误类型。
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    let _ = fr.serialize_compressed(&mut buf);
    buf
}
