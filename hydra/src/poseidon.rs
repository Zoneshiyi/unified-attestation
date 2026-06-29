//! Poseidon 配置 + native sponge 哈希
//!
//! 直接复用 `ark_crypto_primitives::sponge::poseidon::PoseidonSponge`，
//! 仅暴露一组 BLS12-381 Fr 上的标准参数与 hash 便捷函数，避免外部传 `PoseidonConfig`。
//!
//! 参数对齐 ark-crypto-primitives 0.5 的 `PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0)`
//! （rate=2，optimized for constraints）：alpha=17、full_rounds=8、partial_rounds=31、capacity=1。
//! ark / mds 由 `find_poseidon_ark_and_mds` 通过 Grain LFSR 现场推导，
//! 与上游 `bls12_381_fr_poseidon_default_parameters_test` 测试用例输出一致。
//!
//! ark-bls12-381 0.5 自身没为 `Fr` 实现 `PoseidonDefaultConfig` trait，
//! 所以这里走通用的 `find_poseidon_ark_and_mds` 入口，不依赖未存在的 trait 实现。

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds},
};
use ark_ff::PrimeField;

const RATE: usize = 2;
const CAPACITY: usize = 1;
const ALPHA: u64 = 17;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const SKIP_MATRICES: u64 = 0;

/// BLS12-381 Fr 上的标准 Poseidon 参数。
///
/// Grain LFSR 在毫秒级，对当前 attest/verify 频率不构成瓶颈，先不做缓存。
pub fn default_config() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        SKIP_MATRICES,
    );
    PoseidonConfig {
        full_rounds: FULL_ROUNDS,
        partial_rounds: PARTIAL_ROUNDS,
        alpha: ALPHA,
        ark,
        mds,
        rate: RATE,
        capacity: CAPACITY,
    }
}

pub fn hash(inputs: &[Fr]) -> Fr {
    let cfg = default_config();
    let mut sponge: PoseidonSponge<Fr> = PoseidonSponge::new(&cfg);
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// 两元素 hash，shrubs tree 用得最多的接口。
pub fn hash_pair(a: Fr, b: Fr) -> Fr {
    hash(&[a, b])
}
