//! Groth16 verify wrapper
//!
//! Designed for the wasm verifier component. Goals:
//! - Inputs are byte streams (VK / proof / public inputs), never expose raw ark types
//! - Errors carried as `&'static str` so callers don't pull in ark error types

use alloc::vec::Vec;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

/// Deserialize verifying key and proof from compressed bytes, process the VK,
/// and run Groth16 verification against the given public inputs.
pub fn verify_groth16(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[Fr],
) -> Result<bool, &'static str> {
    // Deserialize verifying key and proof from compressed byte streams
    let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes)
        .map_err(|_| "invalid verifying key")?;
    let proof =
        Proof::<Bls12_381>::deserialize_compressed(proof_bytes).map_err(|_| "invalid proof")?;
    // Process the VK into a prepared form for faster verification
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).map_err(|_| "process_vk failed")?;
    // Run the actual verification
    Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, public_inputs, &proof)
        .map_err(|_| "verify failed")
}

/// Deserialize public input field elements from a flat byte stream.
/// Each element is 32 bytes, compressed canonical representation.
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, &'static str> {
    // Input must be a multiple of 32 bytes (one Fr element each)
    if !bytes.len().is_multiple_of(32) {
        return Err("public inputs not 32-byte aligned");
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    // Deserialize each 32-byte chunk as a compressed Fr element
    for chunk in bytes.chunks(32) {
        let fr = Fr::deserialize_compressed(chunk).map_err(|_| "invalid field element")?;
        out.push(fr);
    }
    Ok(out)
}

/// Serialize an Fr element to 32-byte compressed bytes.
/// Returns an empty vec on failure — used only in wasm claim backfill scenarios where
/// serialization is virtually guaranteed to succeed, avoiding ark error type leakage.
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    let _ = fr.serialize_compressed(&mut buf);
    buf
}
