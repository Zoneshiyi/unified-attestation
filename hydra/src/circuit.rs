//! Attestation circuit
//!
//! Ported from hydra `hydra-sys/src/zkcircuit.rs`, adapted for ark 0.5 + Poseidon sponge gadget:
//!
//! - Removed hydra's original `HG: FieldHasherGadget` generic — this crate only uses Poseidon
//!   sponge; a generic with only one implementation adds noise
//! - Hasher is constructed on-the-fly from ark-crypto-primitives 0.5's [`PoseidonSpongeVar`]
//! - Whitelist roots use a public input list, matching hydra's approach
//! - Added `challenge` public input slot: bound to the challenge nonce, unconstrained inside
//!   the circuit; the wasm verifier checks it against `expected_report_data` after verify succeeds
//!
//! Constraint logic (matches hydra):
//! 1. `m = H(ar, sk)`
//! 2. `leaf = H(m, pk)`
//! 3. Walk the Merkle path: `leaf = tag ? H(leaf, sib) : H(sib, leaf)`,
//!    requiring the final leaf to match any entry in the `root[]` list
//! 4. `output == H(H(H(pk, ar), time), period)`
//!
//! Field roles:
//! - public:  pk / root / output / time / period / challenge
//! - witness: sk / ar / path / tag

use crate::poseidon;
use alloc::vec::Vec;
use ark_bls12_381::Fr as BlsScalar;
use ark_crypto_primitives::sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::constraints::PoseidonSpongeVar,
};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct AttestationCircuit {
    pub pk: BlsScalar,
    pub sk: BlsScalar,
    pub ar: BlsScalar,
    pub time: BlsScalar,
    pub period: BlsScalar,
    pub output: BlsScalar,
    pub root: Vec<BlsScalar>,
    pub path: Vec<BlsScalar>,
    pub tag: Vec<bool>,
    pub challenge: BlsScalar,
}

/// Poseidon hash of two field elements as a circuit gadget.
/// Constructs a fresh PoseidonSpongeVar, absorbs both inputs, then squeezes one element.
fn hash_pair_var(
    cs: ConstraintSystemRef<BlsScalar>,
    a: &FpVar<BlsScalar>,
    b: &FpVar<BlsScalar>,
) -> Result<FpVar<BlsScalar>, SynthesisError> {
    let cfg = poseidon::default_config();
    let mut sponge = PoseidonSpongeVar::<BlsScalar>::new(cs, &cfg);
    // Absorb both inputs into the sponge state
    sponge.absorb(&a.to_sponge_field_elements()?)?;
    sponge.absorb(&b.to_sponge_field_elements()?)?;
    // Squeeze one field element as the hash output
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out.into_iter().next().expect("squeeze 1 element"))
}

impl ConstraintSynthesizer<BlsScalar> for AttestationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsScalar>,
    ) -> Result<(), SynthesisError> {
        // Allocate witnesses (private inputs): sk, ar
        let sk = FpVar::new_witness(cs.clone(), || Ok(self.sk))?;
        let ar = FpVar::new_witness(cs.clone(), || Ok(self.ar))?;

        // Allocate public inputs: pk, root list, output, time, period
        let pk = FpVar::new_input(cs.clone(), || Ok(self.pk))?;

        let root: Vec<FpVar<BlsScalar>> = self
            .root
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;

        let output = FpVar::new_input(cs.clone(), || Ok(self.output))?;
        let time = FpVar::new_input(cs.clone(), || Ok(self.time))?;
        let period = FpVar::new_input(cs.clone(), || Ok(self.period))?;

        // Step 1-2: leaf = H(H(ar, sk), pk)
        let m = hash_pair_var(cs.clone(), &ar, &sk)?;
        let mut leaf = hash_pair_var(cs.clone(), &m, &pk)?;

        // Step 3: Merkle path verification
        // path and tag must have matching lengths (validated at prove time)
        if self.path.len() != self.tag.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        // Allocate path siblings as witnesses
        let path: Vec<FpVar<BlsScalar>> = self
            .path
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;
        // tag bits are allocated as Boolean witnesses so the R1CS shape depends only on
        // path_len (not tag values). This keeps setup and prove R1CS shapes strictly identical.
        let tags: Vec<Boolean<BlsScalar>> = self
            .tag
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        // Walk each level of the Merkle path
        for (sib, tag) in path.iter().zip(tags.iter()) {
            // tag=true  => H(leaf, sib)  (current node is left child)
            // tag=false => H(sib, leaf)  (current node is right child)
            // Use conditionally_select to pick operands without branching:
            //   cond ? (leaf, sib) : (sib, leaf)
            let left = FpVar::conditionally_select(tag, &leaf, sib)?;
            let right = FpVar::conditionally_select(tag, sib, &leaf)?;
            leaf = hash_pair_var(cs.clone(), &left, &right)?;
        }

        // Check that the resulting leaf matches at least one of the trusted roots.
        // Accumulate OR across all root entries.
        let mut acc = Boolean::<BlsScalar>::constant(false);
        for r in root.iter() {
            acc = &acc | &leaf.is_eq(r)?;
        }
        acc.enforce_equal(&Boolean::TRUE)?;

        // Step 4: output = H(H(H(pk, ar), time), period)
        // This binds the attestation to the specific (public_key, attestation_result, timestamp, period)
        let r1 = hash_pair_var(cs.clone(), &pk, &ar)?;
        let r2 = hash_pair_var(cs.clone(), &r1, &time)?;
        let r3 = hash_pair_var(cs.clone(), &r2, &period)?;
        output.enforce_equal(&r3)?;

        // Step 5: challenge — occupies a public input slot but is NOT constrained inside the circuit.
        // The wasm verifier compares this against expected_report_data after Groth16 verify passes.
        let _challenge = FpVar::new_input(cs, || Ok(self.challenge))?;

        Ok(())
    }
}
