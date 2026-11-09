//! The key window manifests are signed with (spec §11 "Signed chain").
//!
//! The Collector signs each manifest with an Ed25519 key held behind
//! [`KeyProvider`]: the provider signs and gives out its public key, never
//! the private one. The target (TS-39) is a key generated and sealed inside
//! the attested boundary (sealed appliance or TEE/CVM), so the Operator can
//! cut evidence but not change it. That provider does not exist yet.
//!
//! [`SoftwareKey`] is the only provider today: a key the Collector generates
//! and keeps in a file only its owner can read. Anyone who can read that
//! file can sign as the Collector.
//!
//! The same seam holds the Fleet's keys ([`crate::fleet`]): a second
//! Ed25519 key for mTLS, and an [`HpkeKey`], which opens what the Fleet
//! encrypts to the Collector and never gives out its private half either.
//! [`SoftwareHpkeKey`] is the only provider of that, on the same terms.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, Serializable};

/// Signs window manifests. A provider never exports its private key.
pub trait KeyProvider: Send + Sync {
    /// The Ed25519 public key manifests are verified with.
    fn public_key(&self) -> [u8; 32];
    /// Signs `msg` with Ed25519 (RFC 8032): the same message always gets
    /// the same signature, so signed manifests stay deterministic.
    fn sign(&self, msg: &[u8]) -> io::Result<[u8; 64]>;
}

/// A key in a file: 64 hex digits, the Ed25519 seed. No `Debug`, so it
/// can't end up in a log.
pub struct SoftwareKey {
    key: SigningKey,
}

impl SoftwareKey {
    /// Reads the key at `path`, or generates one there if there is none
    /// ([`seed_file`]).
    pub fn open_or_create(path: &Path) -> io::Result<Self> {
        seed_file(path).map(Self::from_seed)
    }

    /// A key from a fixed seed. For tests: every run signing with it writes
    /// the same bytes.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SoftwareKey {
            key: SigningKey::from_bytes(&seed),
        }
    }
}

impl KeyProvider for SoftwareKey {
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> io::Result<[u8; 64]> {
        Ok(self.key.sign(msg).to_bytes())
    }
}

/// Opens what is encrypted to this key: HPKE base mode (RFC 9180),
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. A provider
/// never exports its private key.
///
/// Base mode doesn't say who encrypted: anyone with the public key can.
/// Callers check the sender another way.
pub trait HpkeKey: Send + Sync {
    /// The X25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// The plaintext of `ct`, sealed to [`HpkeKey::public_key`] under `enc`.
    fn open(&self, info: &[u8], aad: &[u8], enc: &[u8], ct: &[u8]) -> io::Result<Vec<u8>>;
}

/// An HPKE key in a file, like [`SoftwareKey`]: the file holds the seed the
/// key pair is derived from. No `Debug`, so it can't end up in a log.
pub struct SoftwareHpkeKey {
    private: <X25519HkdfSha256 as Kem>::PrivateKey,
    public: [u8; 32],
}

impl SoftwareHpkeKey {
    /// Reads the key at `path`, or generates one there ([`seed_file`]).
    pub fn open_or_create(path: &Path) -> io::Result<Self> {
        seed_file(path).map(|seed| Self::from_seed(&seed))
    }

    /// A key from a fixed seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (private, public) = X25519HkdfSha256::derive_keypair(seed);
        let public = public.to_bytes().as_slice().try_into().expect("32 bytes");
        SoftwareHpkeKey { private, public }
    }
}

impl HpkeKey for SoftwareHpkeKey {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn open(&self, info: &[u8], aad: &[u8], enc: &[u8], ct: &[u8]) -> io::Result<Vec<u8>> {
        let bad = |e: hpke::HpkeError| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc).map_err(bad)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.private,
            &enc,
            info,
            ct,
            aad,
        )
        .map_err(bad)
    }
}

/// Reads the 32-byte seed at `path`, or generates one there if there is
/// none. A new file is readable by its owner only, and is synced with its
/// directory entry before it is used. On Unix, a key file that its group
/// or others can read is refused.
fn seed_file(path: &Path) -> io::Result<[u8; 32]> {
    match read_seed(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        other => return other,
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| io::Error::other(e.to_string()))?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = match opts.open(path) {
        Ok(f) => f,
        // Another process made one first: use it.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return read_seed(path),
        Err(e) => return Err(e),
    };
    file.write_all(format!("{}\n", hex(&seed)).as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(seed)
}

fn read_seed(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("key file is readable by others (mode {:o})", mode & 0o777),
            ));
        }
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    parse_hex::<32>(text.trim_end_matches('\n'))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a key (64 hex digits)"))
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses exactly `2 * N` lowercase hex digits. Strict, as [`crate::mh`]:
/// anything else is rejected, not guessed at.
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_is_kept_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        let a = SoftwareKey::open_or_create(&path).unwrap();
        let b = SoftwareKey::open_or_create(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sign(b"m").unwrap(), b.sign(b"m").unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Another directory, another key.
        let other = tempfile::tempdir().unwrap();
        let c = SoftwareKey::open_or_create(&other.path().join("signing.key")).unwrap();
        assert_ne!(a.public_key(), c.public_key());
    }

    #[test]
    fn an_hpke_key_opens_what_was_sealed_to_it() {
        use hpke::OpModeS;
        let key = SoftwareHpkeKey::from_seed(&[7; 32]);
        let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&key.public_key()).unwrap();
        let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            b"info",
            b"secret",
            b"aad",
        )
        .unwrap();
        let enc = enc.to_bytes();
        assert_eq!(key.open(b"info", b"aad", &enc, &ct).unwrap(), b"secret");
        assert!(key.open(b"info", b"other", &enc, &ct).is_err());
        assert!(key.open(b"other", b"aad", &enc, &ct).is_err());
        assert!(SoftwareHpkeKey::from_seed(&[8; 32])
            .open(b"info", b"aad", &enc, &ct)
            .is_err());
    }

    #[test]
    fn a_bad_key_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        std::fs::write(&path, "not hex\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let e = SoftwareKey::open_or_create(&path).err().unwrap();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            std::fs::write(&path, format!("{}\n", hex(&[1; 32]))).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let e = SoftwareKey::open_or_create(&path).err().unwrap();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}
