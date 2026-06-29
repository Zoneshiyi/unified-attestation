//! challenge nonce 与 BLS12-381 Fr 的统一编码
//!
//! `Fr::from_le_bytes_mod_order(blake2s_256(nonce_bytes))`。
//! attester 与 wasm 验证组件必须使用本函数，不允许各自实现。

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use blake2::{Blake2s256, Digest};

pub fn nonce_to_scalar(nonce_bytes: &[u8]) -> Fr {
    let digest = Blake2s256::digest(nonce_bytes);
    Fr::from_le_bytes_mod_order(&digest)
}
