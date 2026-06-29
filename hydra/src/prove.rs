//! Prove：attester 端生成 Groth16 proof
//!
//! 让调用方组装好 [`AttestationCircuit`] 直接传进来——电路字段较多，没必要再包一层。

use crate::circuit::AttestationCircuit;
use alloc::vec::Vec;
use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

pub fn prove<R: RngCore + CryptoRng>(
    pk_bytes: &[u8],
    circuit: AttestationCircuit,
    rng: &mut R,
) -> Result<Vec<u8>, &'static str> {
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes)
        .map_err(|_| "invalid proving key")?;
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, rng).map_err(|_| "prove failed")?;
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|_| "proof serialize")?;
    Ok(bytes)
}
