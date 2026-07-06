//! Trusted setup
//!
//! Invoked by a standalone tool to produce (pk, vk) byte streams; the unified-attestation
//! demo pre-generates these once in its startup script.
//!
//! The circuit shape of AttestationCircuit is determined by the number of root slots and
//! the path length, both of which must be fixed at setup time.
//!
//! Setup flow (Groth16 circuit-specific setup):
//! 1. Build an all-zero placeholder circuit to describe the shape (root_count + path_len slots)
//! 2. Call arkworks Groth16 `circuit_specific_setup` to generate (pk, vk)
//! 3. Serialize both as compressed byte streams → SetupArtifacts

use crate::circuit::AttestationCircuit;
use alloc::{vec, vec::Vec};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// Trusted setup output: serialized proving key (pk) and verifying key (vk).
pub struct SetupArtifacts {
    pub pk_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

/// Execute circuit-specific trusted setup.
///
/// `root_count`: number of shrubs accumulator root slots (matches the root list length
///   in the whitelist)
/// `path_len`: Merkle path length (determined by device count and shrubs tree shape)
pub fn run_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
    root_count: usize,
    path_len: usize,
) -> Result<SetupArtifacts, &'static str> {
    // Build an all-zero placeholder circuit instance solely to describe the circuit shape
    // (i.e. allocate the correct number of slots for roots and path).
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
    // Run Groth16 circuit-specific setup to produce proving and verifying keys
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(placeholder, rng)
        .map_err(|_| "setup failed")?;

    // Serialize both keys to compressed byte format
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|_| "pk serialization failed")?;
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|_| "vk serialization failed")?;
    Ok(SetupArtifacts { pk_bytes, vk_bytes })
}
