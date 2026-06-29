//! 一次性 trusted setup 工具：产 (pk, vk) 字节流到 config/hydra-shrubs/。
//!
//! 用法：
//!   cargo run -p hydra --bin setup_keys -- <root_count> <path_len> [<out_dir>]
//!
//! root_count 与 path_len 必须与 attester 实际跑的电路形状一致——shrubs root 数量取决于
//! 设备列表大小，path_len 取决于 self_index 在 shrubs 里的层数：
//!   - 4 设备 self_index=0 → root_count=3, path_len=1
//!   - 4 设备 self_index=2 → boundary（无 path），换 self_index 重选
//! 形状对不上 prove 时会跑出 "Unsatisfiable / R1CS dimension mismatch"。
//!
//! 注意：固定种子产确定性输出，仅 demo 用，不可用于生产。

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
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

    let mut rng = StdRng::seed_from_u64(0xc0ffee_u64);
    let artifacts = hydra::setup::run_setup(&mut rng, root_count, path_len).expect("setup");

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
