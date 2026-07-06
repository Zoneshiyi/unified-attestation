//! Prove: generate a Groth16 proof on the attester side
//!
//! The caller assembles an [`AttestationCircuit`] and passes it directly — the circuit
//! has enough fields that an extra wrapper layer adds no value.

use crate::circuit::AttestationCircuit;
use alloc::vec::Vec;
use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// Deserialize the proving key from compressed bytes, generate a Groth16 proof
/// for the given circuit, and return the proof as compressed bytes.
pub fn prove<R: RngCore + CryptoRng>(
    pk_bytes: &[u8],
    circuit: AttestationCircuit,
    rng: &mut R,
) -> Result<Vec<u8>, &'static str> {
    // Deserialize the proving key from compressed format
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes)
        .map_err(|_| "invalid proving key")?;
    // Generate the Groth16 proof
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, rng).map_err(|_| "prove failed")?;
    // Serialize the proof to compressed bytes for transport
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|_| "proof serialization failed")?;
    Ok(bytes)
}
