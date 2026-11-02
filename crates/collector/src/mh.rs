//! Hash names (spec §6 "Multihash"): every stored hash is a multihash,
//! written as multibase base16 lowercase. A BLAKE3 hash is `f1e20` followed
//! by the 64 hex digits `b3sum` prints.

use multihash::Multihash;

/// Multicodec code of BLAKE3.
pub const BLAKE3: u64 = 0x1e;

/// Text form of a BLAKE3 hash: `f1e20` + 64 lowercase hex digits.
pub fn name(hash: &blake3::Hash) -> String {
    let mh = Multihash::<32>::wrap(BLAKE3, hash.as_bytes()).expect("32-byte digest fits");
    let mut s = String::with_capacity(1 + 2 * mh.encoded_len());
    s.push('f');
    for b in mh.to_bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The BLAKE3 hash of `data`, as a name.
pub fn of(data: &[u8]) -> String {
    name(&blake3::hash(data))
}

/// Parses a name. Strict: only `f1e20` + 64 lowercase hex digits is
/// accepted; anything else is rejected, not guessed at.
pub fn parse(s: &str) -> Option<blake3::Hash> {
    let hex = s.strip_prefix('f')?;
    if hex.len() != 2 * 34
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let mh = Multihash::<32>::from_bytes(&bytes).ok()?;
    if mh.code() != BLAKE3 || mh.size() != 32 {
        return None;
    }
    let digest: [u8; 32] = mh.digest().try_into().ok()?;
    Some(blake3::Hash::from_bytes(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_multihash_hex_ending_in_b3sum() {
        let n = of(b"");
        // b3sum of the empty input.
        assert_eq!(
            n,
            "f1e20af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(parse(&n), Some(blake3::hash(b"")));
    }

    #[test]
    fn parse_is_strict() {
        let n = of(b"x");
        assert!(parse(&n).is_some());
        for bad in [
            n.to_uppercase(),
            n.replacen('f', "F", 1),
            n[1..].to_string(),
            format!("{n}0"),
            n[..n.len() - 2].to_string(),
            n.replacen("f1e20", "f1220", 1),
            n.replacen("f1e20", "f1e1f", 1),
            format!("b3:{}", &n[5..]),
            n.replacen('a', "g", 1),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }
}
