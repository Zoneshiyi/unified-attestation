//! hydra: minimal zk subset for unified-attestation
//!
//! Contains Groth16 over BLS12-381 setup / prove / verify, an attestation circuit,
//! and thin wrappers for shrubs tree and Poseidon hash.
//!
//! - With default features disabled, compiles to wasm32-wasip1, exposing only the verify path
//! - Algorithmically independent from the main hydra project; VK / Proof serialization
//!   formats are not interoperable

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
#[cfg(feature = "blockchain")]
pub mod device_vc;

pub use ark_bls12_381::{Bls12_381, Fr};
