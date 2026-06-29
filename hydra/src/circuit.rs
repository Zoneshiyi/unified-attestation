//! Attestation circuit
//!
//! 移植自 hydra `hydra-sys/src/zkcircuit.rs`，按 ark 0.5 + Poseidon sponge gadget 调整：
//!
//! - 去掉 hydra 原版的 `HG: FieldHasherGadget` 泛型——本 crate 只用 Poseidon
//!   sponge，泛型化没有第二个实现，只徒增噪音
//! - hasher 从 ark-crypto-primitives 0.5 的 [`PoseidonSpongeVar`] 现场构造
//! - whitelist root 用 public input 列表，跟 hydra 一致
//! - 新增 `challenge` public input 槽：与 challenge nonce 绑定，电路内不约束，
//!   仅由 wasm 验证组件在 verify 后对照 `expected_report_data` 校验一致
//!
//! 约束逻辑（与 hydra 一致）：
//! 1. `m = H(ar, sk)`
//! 2. `leaf = H(m, pk)`
//! 3. 沿 Merkle path 反复 `leaf = tag ? H(leaf, sib) : H(sib, leaf)`，
//!    要求最终 leaf 落在 `root[]` 列表中任一位置
//! 4. `output == H(H(H(pk, ar), time), period)`
//!
//! 字段角色：
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

fn hash_pair_var(
    cs: ConstraintSystemRef<BlsScalar>,
    a: &FpVar<BlsScalar>,
    b: &FpVar<BlsScalar>,
) -> Result<FpVar<BlsScalar>, SynthesisError> {
    let cfg = poseidon::default_config();
    let mut sponge = PoseidonSpongeVar::<BlsScalar>::new(cs, &cfg);
    sponge.absorb(&a.to_sponge_field_elements()?)?;
    sponge.absorb(&b.to_sponge_field_elements()?)?;
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out.into_iter().next().expect("squeeze 1 element"))
}

impl ConstraintSynthesizer<BlsScalar> for AttestationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsScalar>,
    ) -> Result<(), SynthesisError> {
        let sk = FpVar::new_witness(cs.clone(), || Ok(self.sk))?;
        let ar = FpVar::new_witness(cs.clone(), || Ok(self.ar))?;
        let pk = FpVar::new_input(cs.clone(), || Ok(self.pk))?;

        let root: Vec<FpVar<BlsScalar>> = self
            .root
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;

        let output = FpVar::new_input(cs.clone(), || Ok(self.output))?;
        let time = FpVar::new_input(cs.clone(), || Ok(self.time))?;
        let period = FpVar::new_input(cs.clone(), || Ok(self.period))?;

        // step 1-2: leaf = H(H(ar, sk), pk)
        let m = hash_pair_var(cs.clone(), &ar, &sk)?;
        let mut leaf = hash_pair_var(cs.clone(), &m, &pk)?;

        // step 3: Merkle path 校验
        if self.path.len() != self.tag.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let path: Vec<FpVar<BlsScalar>> = self
            .path
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;
        // tag 作为 Boolean witness：电路形态只与 path_len 有关，
        // tag 取值在 prove 时填进来。这样 setup 与 prove 的 R1CS 形态严格一致。
        let tags: Vec<Boolean<BlsScalar>> = self
            .tag
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        for (sib, tag) in path.iter().zip(tags.iter()) {
            // tag=true => H(leaf, sib)；tag=false => H(sib, leaf)
            // `conditionally_select(cond, true_value, false_value)`
            let left = FpVar::conditionally_select(tag, &leaf, sib)?;
            let right = FpVar::conditionally_select(tag, sib, &leaf)?;
            leaf = hash_pair_var(cs.clone(), &left, &right)?;
        }

        let mut acc = Boolean::<BlsScalar>::constant(false);
        for r in root.iter() {
            acc = &acc | &leaf.is_eq(r)?;
        }
        acc.enforce_equal(&Boolean::TRUE)?;

        // step 4: output = H(H(H(pk, ar), time), period)
        let r1 = hash_pair_var(cs.clone(), &pk, &ar)?;
        let r2 = hash_pair_var(cs.clone(), &r1, &time)?;
        let r3 = hash_pair_var(cs.clone(), &r2, &period)?;
        output.enforce_equal(&r3)?;

        // step 5: challenge —— 占用 public input 槽位，电路内不约束
        // 由 wasm 验证组件在 verify 通过后对比 expected_report_data 强校验
        let _challenge = FpVar::new_input(cs, || Ok(self.challenge))?;

        Ok(())
    }
}
