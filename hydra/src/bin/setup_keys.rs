//! One-shot trusted setup tool: produces (pk, vk) byte streams under config/hydra-shrubs/.
//!
//! Usage:
//!   cargo run -p hydra --bin setup_keys -- <root_count> <path_len> [<out_dir>]
//!
//! root_count and path_len must match the circuit shape the attester will actually run.
//! root_count depends on the device list size; path_len depends on the self_index position
//! within the shrubs tree:
//!   - 4 devices, self_index=0 → root_count=3, path_len=1
//!   - 4 devices, self_index=2 → boundary (no path), choose a different self_index
//! Mismatched shapes cause "Unsatisfiable / R1CS dimension mismatch" at prove time.
//!
//! Note: a fixed seed produces deterministic output — demo only, not for production.

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    // Parse CLI arguments: root_count, path_len, and optional output directory
    let mut args = std::env::args().skip(1);
    let root_count: usize = args
        .next()
        .expect("usage: setup_keys <root_count> <path_len> [out_dir]")
        .parse()
        .expect("root_count must be usize");
    let path_len: usize = args
        .next()
        .expect("usage: setup_keys <root_count> <path_len> [out_dir]")
        .parse()
        .expect("path_len must be usize");
    let out_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/hydra-shrubs"));
    std::fs::create_dir_all(&out_dir)?;

    // Fixed seed for deterministic, reproducible setup (demo purposes only)
    let mut rng = StdRng::seed_from_u64(0xc0ffee_u64);
    let artifacts = hydra::setup::run_setup(&mut rng, root_count, path_len).expect("setup");

    // Write proving key and verifying key to disk
    let pk_path = out_dir.join("attestation_pk.bin");
    let vk_path = out_dir.join("attestation_vk.bin");
    std::fs::write(&pk_path, &artifacts.pk_bytes)?;
    std::fs::write(&vk_path, &artifacts.vk_bytes)?;

    println!("shape: root_count={root_count}, path_len={path_len}");
    println!(
        "wrote {} ({} bytes)",
        pk_path.display(),
        artifacts.pk_bytes.len()
    );
    println!(
        "wrote {} ({} bytes)",
        vk_path.display(),
        artifacts.vk_bytes.len()
    );
    Ok(())
}
