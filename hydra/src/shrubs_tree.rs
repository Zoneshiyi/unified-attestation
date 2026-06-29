//! Shrubs tree —— whitelist 累积器
//!
//! 移植自 hydra `hydra-sys/src/shurbstree.rs`，按 ark 0.5 + sponge Poseidon 调整：
//!
//! - 把 rayon 并行 chunk 换成串行 `chunks_exact`，保 wasm32-wasip1 兼容
//! - 去掉 `println!` 调试输出
//! - hasher 改为本 crate 的 [`poseidon::hash_pair`]，不再外传 ark crypto-primitives 类型

use crate::poseidon;
use alloc::vec::Vec;
use ark_bls12_381::Fr as BlsScalar;

fn hash_chunks_pair(vect: &[BlsScalar]) -> Vec<BlsScalar> {
    vect.chunks_exact(2)
        .map(|c| poseidon::hash_pair(c[0], c[1]))
        .collect()
}

/// 批量构建：把 `leaves` 反复两两 hash，每层都把"最右侧落单元素"作为 shrubs root 推到 `root`。
///
/// 与标准 Merkle 树的差异：标准树要求叶子数补齐到 2^n，shrubs 不补齐，
/// 而是把每层无法配对的最右元素直接当作一个独立 root，等可信白名单里的多棵小树。
///
/// 例（4 个 leaf [L0 L1 L2 L3]）：
///   层 0: 最右成对元素 L2 → root[0] = L2；下一层 [H(L0,L1), H(L2,L3)]
///   层 1: 最右成对元素 H(L0,L1) → root[1] = H(L0,L1)
///   最终 root = [L2, H(L0,L1)]，每个 leaf 都能落进其中一棵
///
/// 副作用：偶数 leaf 的层会把"次右"元素当 root（`last_i = len - 2`），
/// 因为最右那个已经会被下一层 chunks_exact 配对吸收。
pub fn create_batch_devices(root: &mut Vec<BlsScalar>, leaves: &[BlsScalar]) {
    let len = leaves.len();
    if len == 0 {
        return;
    }
    let temp = hash_chunks_pair(leaves);
    let last_i = if len.is_multiple_of(2) {
        len - 2
    } else {
        len - 1
    };
    root.push(leaves[last_i]);
    if !temp.is_empty() {
        create_batch_devices(root, &temp);
    }
}

/// 在 shrubs 中给定 `value` 处的叶节点定位 Merkle path。
/// 返回 `(path_siblings, direction_bits)`，bit=true 表示当前节点是右子。
///
/// 返回 `None` 的两种情况：
/// 1. 当前层只剩 1 个 leaf 且与 root[0] 相等（boundary case）：
///    leaf 自身就是某个 shrubs root，无 path 可走，电路里也就走不通"沿 path 升至某个 root"分支。
///    示例：3 个 leaf 时 root[0] = L2，self_index=2 触发此情况。
///    应对：attester 配置 self_index 时避开这些位置，或调整设备列表使其不落在 boundary。
/// 2. 索引越界 / `value` 落入空层。
pub fn find_shrubs_path(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    j: usize,
    value: usize,
) -> Option<(Vec<BlsScalar>, Vec<bool>)> {
    if leaves.len() >= 2 && root[0] == leaves[value] {
        return None;
    }
    if leaves.is_empty() || value >= leaves.len() {
        return None;
    }

    let mut path = Vec::<BlsScalar>::new();
    let mut index = Vec::<bool>::new();

    let sibling_index = if value.is_multiple_of(2) {
        index.push(true);
        value.checked_add(1)?
    } else {
        index.push(false);
        value.checked_sub(1)?
    };
    path.push(*leaves.get(sibling_index)?);

    let temp = hash_chunks_pair(leaves);
    if temp.len() >= 2 {
        let val = value / 2;
        let next_j = j + 1;
        if val >= temp.len() || next_j >= root.len() {
            return None;
        }
        if temp[val] == root[next_j] {
            return Some((path, index));
        }
        let (mut sub_path, mut sub_index) = find_shrubs_path(root, &temp, next_j, val)?;
        path.append(&mut sub_path);
        index.append(&mut sub_index);
    }
    Some((path, index))
}
