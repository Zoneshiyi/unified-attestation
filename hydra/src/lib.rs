//! hydra：unified-attestation 的最小 zk 子集
//!
//! 包含 Groth16 over BLS12-381 的 setup / prove / verify 三件套，
//! 一份 attestation circuit，以及 shrubs tree 与 Poseidon 的薄包装。
//!
//! - 关闭 default features 时仍可编 wasm32-wasip1，仅暴露 verify 路径
//! - 与 hydra 主项目算法独立，VK / Proof 序列化格式不互通

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod circuit;
pub mod nonce;
pub mod poseidon;
pub mod shrubs_tree;
pub mod verify;

#[cfg(feature = "std")]
pub mod prove;
#[cfg(feature = "std")]
pub mod setup;

pub use ark_bls12_381::{Bls12_381, Fr};
