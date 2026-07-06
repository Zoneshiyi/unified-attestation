//! Shrubs tree — whitelist accumulator
//!
//! Ported from hydra `hydra-sys/src/shurbstree.rs`, adapted for ark 0.5 + sponge Poseidon:
//!
//! - Replaced rayon parallel chunks with serial `chunks_exact` to preserve wasm32-wasip1
//!   compatibility
//! - Removed `println!` debug output
//! - Hasher now uses this crate's [`poseidon::hash_pair`]; no ark crypto-primitives types
//!   leak to callers

use crate::poseidon;
use alloc::vec::Vec;
use ark_bls12_381::Fr as BlsScalar;

/// Pairwise-hash a slice of scalars in chunks of 2.
/// Returns a vector of hashes, one per pair. Any trailing odd element is discarded by
/// `chunks_exact`.
fn hash_chunks_pair(vect: &[BlsScalar]) -> Vec<BlsScalar> {
    vect.chunks_exact(2)
        .map(|c| poseidon::hash_pair(c[0], c[1]))
        .collect()
}

/// Batch construction: repeatedly pairwise-hash `leaves`, pushing the "rightmost unpaired
/// element" from each level as a shrubs root into `root`.
///
/// Difference from a standard Merkle tree: standard trees pad the leaf count to a power of
/// two; shrubs does not pad. Instead, at each level the rightmost element that cannot be
/// paired is recorded directly as an independent root — like a set of small trusted trees.
///
/// Example (4 leaves [L0 L1 L2 L3]):
///   Level 0: rightmost paired element L2 → root[0] = L2; next = [H(L0,L1), H(L2,L3)]
///   Level 1: rightmost paired element H(L0,L1) → root[1] = H(L0,L1)
///   Final root = [L2, H(L0,L1)]; every leaf lands in one of these trees.
///
/// Side effect: for even-length leaf layers, the "second-from-right" element is taken as
/// root (`last_i = len - 2`), because the rightmost element will be absorbed by the next
/// level's `chunks_exact` pairing.
pub fn create_batch_devices(root: &mut Vec<BlsScalar>, leaves: &[BlsScalar]) {
    let len = leaves.len();
    if len == 0 {
        return;
    }
    // Hash all leaf pairs into the next level
    let temp = hash_chunks_pair(leaves);
    // Pick the unpaired rightmost element as a root:
    //   - odd len  → last element (index len-1) is unpaired
    //   - even len → second-to-last (index len-2); the last element pairs into next level
    let last_i = if len.is_multiple_of(2) {
        len - 2
    } else {
        len - 1
    };
    root.push(leaves[last_i]);
    // Recurse on the next (hashed) level if non-empty
    if !temp.is_empty() {
        create_batch_devices(root, &temp);
    }
}

/// Locate the Merkle path for a leaf at index `value` within the shrubs tree.
/// Returns `(path_siblings, direction_bits)`, where `bit=true` means the current node is
/// the right child.
///
/// Returns `None` in two cases:
/// 1. The current level has only 1 leaf and it equals root[0] (boundary case):
///    the leaf itself is a shrubs root, so there is no path to walk, and the circuit
///    cannot follow the "ascend to a root via path" branch.
///    Example: with 3 leaves, root[0] = L2; self_index=2 triggers this.
///    Mitigation: the attester config should avoid these positions, or adjust the device
///    list so the target index does not land on a boundary.
/// 2. Index out of bounds, or `value` falls into an empty level.
pub fn find_shrubs_path(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    j: usize,
    value: usize,
) -> Option<(Vec<BlsScalar>, Vec<bool>)> {
    // Boundary case: the leaf at `value` is itself a root — no path exists
    if leaves.len() >= 2 && root[0] == leaves[value] {
        return None;
    }
    // Guard against out-of-bounds
    if leaves.is_empty() || value >= leaves.len() {
        return None;
    }

    let mut path = Vec::<BlsScalar>::new();
    let mut index = Vec::<bool>::new();

    // Determine sibling index and direction bit:
    //   value is even → it is the left child, sibling is value+1, direction = true
    //   value is odd  → it is the right child, sibling is value-1, direction = false
    let sibling_index = if value.is_multiple_of(2) {
        index.push(true);
        value.checked_add(1)?
    } else {
        index.push(false);
        value.checked_sub(1)?
    };
    // Push the sibling scalar (returns None if index out of bounds)
    path.push(*leaves.get(sibling_index)?);

    // Hash to the next level and recurse
    let temp = hash_chunks_pair(leaves);
    if temp.len() >= 2 {
        let val = value / 2;
        let next_j = j + 1;
        // Guard: value must map into the next level's range
        if val >= temp.len() || next_j >= root.len() {
            return None;
        }
        // If the current node's hash already matches a root, path is complete
        if temp[val] == root[next_j] {
            return Some((path, index));
        }
        // Otherwise recurse deeper into the next level
        let (mut sub_path, mut sub_index) = find_shrubs_path(root, &temp, next_j, val)?;
        path.append(&mut sub_path);
        index.append(&mut sub_index);
    }
    Some((path, index))
}
