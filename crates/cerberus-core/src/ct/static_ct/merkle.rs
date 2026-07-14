use sha2::{Digest, Sha256};

use crate::error::{CerberusError, Result};

pub const RFC6962_HASH_LEN: usize = 32;

pub type MerkleHash = [u8; RFC6962_HASH_LEN];

pub fn empty_hash() -> MerkleHash {
    Sha256::digest([]).into()
}

pub fn leaf_hash(timestamped_entry: &[u8]) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update([0x00, 0x00, 0x00]);
    hasher.update(timestamped_entry);
    hasher.finalize().into()
}

pub fn node_hash(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn hash_from_hex(input: &str) -> Result<MerkleHash> {
    let bytes = hex::decode(input).map_err(|error| {
        CerberusError::CtSource(format!("Merkle hash is not valid lowercase hex: {error}"))
    })?;

    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CerberusError::CtSource(format!(
            "Merkle hash must be {RFC6962_HASH_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

pub fn combine_perfect_subtree_roots(mut roots: Vec<MerkleHash>) -> Result<MerkleHash> {
    if roots.is_empty() {
        return Err(CerberusError::CtSource(
            "cannot combine an empty set of Merkle roots".to_string(),
        ));
    }

    while roots.len() > 1 {
        if roots.len() % 2 != 0 {
            return Err(CerberusError::CtSource(format!(
                "cannot combine {} roots into a perfect subtree",
                roots.len()
            )));
        }

        roots = roots
            .chunks_exact(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }

    Ok(roots[0])
}

pub fn combine_compact_range_roots(roots: &[MerkleHash]) -> MerkleHash {
    let Some((last, rest)) = roots.split_last() else {
        return empty_hash();
    };

    rest.iter()
        .rev()
        .fold(*last, |acc, root| node_hash(root, &acc))
}

pub fn highest_power_of_two_less_than_or_equal(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        1u64 << (63 - value.leading_zeros())
    }
}

pub fn power_subtree_level_and_count(size: u64) -> Result<(u8, usize, u64)> {
    if size == 0 || !size.is_power_of_two() {
        return Err(CerberusError::CtSource(format!(
            "subtree size must be a non-zero power of two, got {size}"
        )));
    }

    let level = (size.trailing_zeros() / 8).min(5) as u8;
    let block_size = 256u64.pow(level as u32);
    let count = size / block_size;

    if count == 0 || count > 256 {
        return Err(CerberusError::CtSource(format!(
            "subtree size {size} cannot be represented from one Static CT tile level"
        )));
    }

    Ok((level, count as usize, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_compact_roots_right_associatively() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let c = leaf_hash(b"c");

        let expected = node_hash(&node_hash(&a, &b), &c);
        let compact = combine_compact_range_roots(&[node_hash(&a, &b), c]);

        assert_eq!(compact, expected);
    }

    #[test]
    fn chooses_tile_level_for_power_subtree() {
        assert_eq!(power_subtree_level_and_count(1).unwrap(), (0, 1, 1));
        assert_eq!(power_subtree_level_and_count(128).unwrap(), (0, 128, 1));
        assert_eq!(power_subtree_level_and_count(256).unwrap(), (1, 1, 256));
        assert_eq!(power_subtree_level_and_count(32768).unwrap(), (1, 128, 256));
    }
}
