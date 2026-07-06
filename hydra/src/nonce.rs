//! Challenge nonce encoding into a BLS12-381 Fr element
//!
//! `Fr::from_le_bytes_mod_order(blake2s_256(nonce_bytes))`.
//! Both the attester and the wasm verifier MUST use this function — no ad-hoc implementations.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use blake2::{Blake2s256, Digest};

/// Hash the nonce bytes with Blake2s-256, then map the digest into a BLS12-381 scalar
/// via from_le_bytes_mod_order (reads the 32-byte digest as a little-endian integer and
/// reduces modulo the field order).
pub fn nonce_to_scalar(nonce_bytes: &[u8]) -> Fr {
    let digest = Blake2s256::digest(nonce_bytes);
    Fr::from_le_bytes_mod_order(&digest)
}
