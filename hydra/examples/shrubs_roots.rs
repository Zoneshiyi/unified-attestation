//! 算 shrubs whitelist 的 trusted root 列表（小写 hex），
//! 同时打印 self_index 是否落在 shrubs root 边界（落在边界则没法走 path 校验分支）。
//!
//! 用法：cargo run -p hydra --example shrubs_roots
//!
//! 设备列表与 attester-cca-zk.toml 中的 [zk.whitelist.devices] 严格保持一致。

use ark_serialize::CanonicalSerialize;
use hydra::{Fr, poseidon, shrubs_tree};

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() {
    // 与 config/attester-cca-zk.toml 中的设备列表严格保持一致
    let devices: [(u64, u64, u64); 4] = [
        (100, 200, 300),
        (101, 201, 301),
        (102, 202, 302),
        (103, 203, 303),
    ];
    let leaves: Vec<Fr> = devices
        .iter()
        .map(|(pk, sk, ar)| {
            poseidon::hash_pair(
                poseidon::hash_pair(Fr::from(*ar), Fr::from(*sk)),
                Fr::from(*pk),
            )
        })
        .collect();

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

    // 顺手提示哪些 self_index 没法走 path（留给配置者参考）
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
