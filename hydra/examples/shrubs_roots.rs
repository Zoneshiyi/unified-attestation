//! Compute the trusted root list (lowercase hex) for the shrubs whitelist,
//! and report whether each self_index lands on a shrubs root boundary
//! (boundary positions cannot walk a Merkle path for verification).
//!
//! Usage: cargo run -p hydra --example shrubs_roots
//!
//! The device list must exactly match [zk.whitelist.devices] in attester-cca-zk.toml.

use ark_serialize::CanonicalSerialize;
use hydra::{Fr, poseidon, shrubs_tree};

/// Convert bytes to lowercase hex string.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() {
    // Must exactly match the device list in config/attester-cca-zk.toml
    let devices: [(u64, u64, u64); 4] = [
        (100, 200, 300),
        (101, 201, 301),
        (102, 202, 302),
        (103, 203, 303),
    ];

    // Compute leaf = H(H(ar, sk), pk) for each device
    let leaves: Vec<Fr> = devices
        .iter()
        .map(|(pk, sk, ar)| {
            poseidon::hash_pair(
                poseidon::hash_pair(Fr::from(*ar), Fr::from(*sk)),
                Fr::from(*pk),
            )
        })
        .collect();

    // Build the shrubs accumulator roots from the leaf set
    let mut roots = Vec::new();
    shrubs_tree::create_batch_devices(&mut roots, &leaves);

    println!("# devices = {}", devices.len());
    println!("# root_list_len = {}", roots.len());
    println!();
    println!("trusted_roots_hex = [");
    for r in &roots {
        let mut buf = Vec::with_capacity(32);
        r.serialize_compressed(&mut buf).unwrap();
        println!("  \"{}\",", hex_lower(&buf));
    }
    println!("]");

    // Annotate which self_index values have a usable Merkle path vs. sit on a boundary
    println!();
    for i in 0..devices.len() {
        let path = shrubs_tree::find_shrubs_path(&roots, &leaves, 0, i);
        let label = if path.is_some() {
            "ok"
        } else {
            "boundary (no path)"
        };
        println!("# self_index={i}: {label}");
    }
}
