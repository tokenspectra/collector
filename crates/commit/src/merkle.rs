//! The Merkle tree over a chunk's packet hashes (spec §6).

use alloc::vec::Vec;

/// The Merkle root over a chunk's packet hashes, in packet order (spec §6).
///
/// A leaf is `blake3(0x00 ‖ packet hash)` and a node `blake3(0x01 ‖ left ‖
/// right)`, so a leaf can never pass for a node. An odd node at the end of
/// a level moves up unchanged. `None` for an empty chunk.
pub fn merkle_root(packet_hashes: &[blake3::Hash]) -> Option<blake3::Hash> {
    let mut level: Vec<blake3::Hash> = packet_hashes
        .iter()
        .map(|h| {
            let mut x = blake3::Hasher::new();
            x.update(&[0]);
            x.update(h.as_bytes());
            x.finalize()
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => {
                    let mut x = blake3::Hasher::new();
                    x.update(&[1]);
                    x.update(l.as_bytes());
                    x.update(r.as_bytes());
                    x.finalize()
                }
                [one] => *one,
                _ => unreachable!(),
            })
            .collect();
    }
    level.pop()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn merkle_root_shapes() {
        let h: Vec<blake3::Hash> = (0u8..3).map(|i| blake3::hash(&[i])).collect();
        assert_eq!(merkle_root(&[]), None);
        let leaf = |x: &blake3::Hash| {
            let mut v = vec![0];
            v.extend_from_slice(x.as_bytes());
            blake3::hash(&v)
        };
        let node = |l: blake3::Hash, r: blake3::Hash| {
            let mut v = vec![1];
            v.extend_from_slice(l.as_bytes());
            v.extend_from_slice(r.as_bytes());
            blake3::hash(&v)
        };
        assert_eq!(merkle_root(&h[..1]), Some(leaf(&h[0])));
        assert_eq!(
            merkle_root(&h),
            Some(node(node(leaf(&h[0]), leaf(&h[1])), leaf(&h[2])))
        );
    }
}
