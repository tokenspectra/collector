//! Window manifests and the append-only log they go to (spec §11).
//!
//! When the store seals a window ([`crate::store`]), it writes one
//! [`WindowManifest`]: the Collector, the window, its Links, its L0 chunks,
//! its pack, the key and row count of each index table, and totals. The
//! manifest names objects already written; it never holds rows itself.
//!
//! Manifests are appended to [`LOG`] in the output directory, one JSON line
//! per window, and synced to disk before the run moves on. The log is the
//! source of truth for the control plane: the shipper ([`crate::ship`])
//! reads it and POSTs each line to the ingest. It is only ever appended to,
//! across runs too. A re-run over the same capture leaves the windows the
//! log already holds alone, so the ingest never sees one window twice with
//! other bytes.
//!
//! **Signed chain.** Each line carries a [`Chain`] (its place in the log,
//! the BLAKE3 hash of the line before it, the public key) and is signed by
//! the Collector's [`KeyProvider`]. A dropped, reordered, edited or
//! re-signed line then fails [`ChainVerifier`]. The first line a run
//! appends to an existing log says so (`restart`), so a restart, and the
//! windows it missed, show instead of passing as a gap in the traffic.
//!
//! A line is the manifest's JSON object with `chain` as its last field and
//! `,"sig":"<128 hex digits>"` spliced in before the closing brace. The
//! signature is over [`SIG_CONTEXT`] followed by the line without that
//! splice, so a verifier checks the bytes as logged and never
//! re-serializes.
//!
//! Every field comes from the capture or the key, and Ed25519 signatures
//! are deterministic, so the lines are byte-identical across runs with the
//! same key (spec §12).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub use bundle::manifest::*;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tracing::debug;

use crate::mh;
use crate::sign::{hex, parse_hex, KeyProvider};

/// The append-only manifest log.
pub struct Log {
    file: File,
    key: Box<dyn KeyProvider>,
    key_hex: String,
    /// The next line's chain, but for the key.
    seq: u64,
    prev: Option<String>,
    restart: bool,
    /// Every window in the log: its dedup key, and the hash of its manifest
    /// without chain and signature.
    logged: HashMap<String, blake3::Hash>,
}

impl Log {
    /// Opens [`LOG`] in `dir` for appending, creating it if needed, with
    /// `key` to sign new lines. A partial last line, left by a crash
    /// mid-write, is cut off first: it was never complete, so it was never
    /// shipped. The chain goes on from the last complete line.
    ///
    /// A new log's directory entry is synced before the first append, so a
    /// synced line can't be lost with the file that holds it.
    pub fn open(dir: &Path, key: Box<dyn KeyProvider>) -> io::Result<Self> {
        let path = dir.join(LOG);
        let mut file = match OpenOptions::new()
            .create_new(true)
            .read(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => {
                sync_dir(dir)?;
                f
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                OpenOptions::new().read(true).append(true).open(&path)?
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        let mut text = Vec::new();
        if len > 0 {
            let complete = complete_len(&mut file, len)?;
            if complete < len {
                file.set_len(complete)?;
            }
            file.seek(SeekFrom::Start(0))?;
            (&mut file).take(complete).read_to_end(&mut text)?;
        }
        let mut logged = HashMap::new();
        let mut last = None;
        for (i, line) in text.split(|&b| b == b'\n').filter(|l| !l.is_empty()).enumerate() {
            let (dedup, body) = unchained(line).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: line {} is not a manifest", path.display(), i + 1),
                )
            })?;
            logged.insert(dedup, body);
            last = Some(line);
        }
        let (seq, prev, restart) = match last {
            None => (0, None, false),
            // A last line without a chain was logged before manifests were
            // signed: the chain starts after it.
            Some(line) => {
                let seq = serde_json::from_slice::<Head>(line).map_or(0, |h| h.chain.seq + 1);
                (seq, Some(mh::of(line)), true)
            }
        };
        let key_hex = hex(&key.public_key());
        Ok(Log {
            file,
            key,
            key_hex,
            seq,
            prev,
            restart,
            logged,
        })
    }

    /// Chains, signs and appends one manifest as a line and syncs it to
    /// disk. A window the log already holds is left alone; one it holds
    /// with other contents is an error, as a conflicting store put is.
    pub fn append(&mut self, m: &WindowManifest) -> io::Result<()> {
        let dedup = m.dedup_key();
        let body = blake3::hash(&serde_json::to_vec(&serde_json::to_value(m)?)?);
        match self.logged.get(&dedup) {
            Some(h) if *h == body => {
                debug!(window = %dedup, "window already in the manifest log");
                return Ok(());
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("window {dedup} is already in {LOG} with other contents"),
                ))
            }
            None => {}
        }
        let chain = Chain {
            seq: self.seq,
            prev: self.prev.clone(),
            restart: self.restart,
            key: self.key_hex.clone(),
        };
        let mut line = serde_json::to_vec(&Unsigned {
            manifest: m,
            chain: &chain,
        })?;
        let sig = self.key.sign(&signed_message(&line))?;
        line.pop(); // the closing brace
        line.extend_from_slice(SIG_FIELD);
        line.extend_from_slice(hex(&sig).as_bytes());
        line.extend_from_slice(b"\"}");
        let hash = mh::of(&line);
        line.push(b'\n');
        // One write per line: a crash leaves at most a partial last line,
        // which the shipper never sends.
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.seq += 1;
        self.prev = Some(hash);
        self.restart = false;
        self.logged.insert(dedup, body);
        Ok(())
    }
}

/// The fields of a line the chain needs.
#[derive(Deserialize)]
struct Head {
    collector: String,
    window_start_ns: u64,
    chain: Chain,
}

/// A logged line's dedup key, and the hash of its manifest without chain
/// and signature, comparable with [`Log::append`]'s.
fn unchained(line: &[u8]) -> Option<(String, blake3::Hash)> {
    let mut v: serde_json::Value = serde_json::from_slice(line).ok()?;
    let obj = v.as_object_mut()?;
    obj.remove("sig");
    obj.remove("chain");
    let dedup = format!(
        "{}/{}",
        obj.get("collector")?.as_str()?,
        obj.get("window_start_ns")?.as_u64()?
    );
    Some((dedup, blake3::hash(&serde_json::to_vec(&v).ok()?)))
}

/// Why a log fails [`ChainVerifier`]. Lines count from 1.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("not an Ed25519 public key")]
    BadKey,
    #[error("line {line}: {reason}")]
    Malformed { line: u64, reason: &'static str },
    #[error("line {line}: signed by another key")]
    WrongKey { line: u64 },
    #[error("line {line}: signature does not match")]
    BadSignature { line: u64 },
    #[error("line {line}: seq {got}, expected {want}: a line was dropped or moved")]
    Sequence { line: u64, want: u64, got: u64 },
    #[error("line {line}: does not chain to the line before it")]
    Broken { line: u64 },
}

/// A line that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub seq: u64,
    pub restart: bool,
    pub collector: String,
    pub window_start_ns: u64,
}

/// Checks a manifest log line by line, from its first line, against the
/// one public key the Collector is trusted to sign with. Each line must be
/// signed by that key, number itself one past the line before, and carry
/// that line's hash.
///
/// That a key is trusted at all (it was sealed in an attested image) is the
/// Verifier's call (TS-41), not this one's.
pub struct ChainVerifier {
    key: VerifyingKey,
    key_hex: String,
    lines: u64,
    prev: Option<String>,
}

impl ChainVerifier {
    pub fn new(public_key: [u8; 32]) -> Result<Self, ChainError> {
        Ok(ChainVerifier {
            key: VerifyingKey::from_bytes(&public_key).map_err(|_| ChainError::BadKey)?,
            key_hex: hex(&public_key),
            lines: 0,
            prev: None,
        })
    }

    /// Verifies the next line, without its newline. After an error the
    /// verifier is left as it was before the line.
    pub fn push(&mut self, line: &[u8]) -> Result<Verified, ChainError> {
        let n = self.lines + 1;
        let unsigned_err = ChainError::Malformed {
            line: n,
            reason: "not signed",
        };
        let at = line
            .len()
            .checked_sub(SIG_FIELD.len() + 128 + 2)
            .ok_or_else(|| unsigned_err.clone())?;
        let (head, tail) = line.split_at(at);
        let sig = tail
            .strip_prefix(SIG_FIELD)
            .and_then(|t| t.strip_suffix(b"\"}"))
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(parse_hex::<64>)
            .ok_or(unsigned_err)?;
        let unsigned = [head, &b"}"[..]].concat();
        let h: Head = serde_json::from_slice(&unsigned).map_err(|_| ChainError::Malformed {
            line: n,
            reason: "not a chained manifest",
        })?;
        if h.chain.key != self.key_hex {
            return Err(ChainError::WrongKey { line: n });
        }
        self.key
            .verify_strict(&signed_message(&unsigned), &Signature::from_bytes(&sig))
            .map_err(|_| ChainError::BadSignature { line: n })?;
        if h.chain.seq != n - 1 {
            return Err(ChainError::Sequence {
                line: n,
                want: n - 1,
                got: h.chain.seq,
            });
        }
        if h.chain.prev != self.prev {
            return Err(ChainError::Broken { line: n });
        }
        self.lines = n;
        self.prev = Some(mh::of(line));
        Ok(Verified {
            seq: h.chain.seq,
            restart: h.chain.restart,
            collector: h.collector,
            window_start_ns: h.window_start_ns,
        })
    }
}

/// Verifies a whole log (the bytes of [`LOG`]) against `public_key`. A
/// partial last line, still being written or left by a crash, is not part
/// of the log yet and is skipped.
pub fn verify_log(log: &[u8], public_key: [u8; 32]) -> Result<Vec<Verified>, ChainError> {
    let mut v = ChainVerifier::new(public_key)?;
    let complete = log.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    log[..complete]
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| v.push(l))
        .collect()
}

/// Syncs `dir`'s entries. Only Unix can open a directory to sync it.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Length of `file` up to and including its last newline.
fn complete_len(file: &mut File, len: u64) -> io::Result<u64> {
    let mut end = len;
    let mut buf = [0u8; 4096];
    while end > 0 {
        let start = end.saturating_sub(buf.len() as u64);
        let n = (end - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SoftwareKey;

    const SEED: [u8; 32] = [1; 32];

    const PINNED: &str = concat!(
        "{\"site\":\"local\",\"collector\":\"c1\",\"window_start_ns\":0,\"window_ns\":10,\"links\":[\"lo\"],\"chunks\":[{\"link\":\"lo\",\"window_start_ns\":0,\"key\":\"raw/c\",\"chunk_hash\":\"f1e206b1d440ada61d0f4e4416c73bcbab3694f96875a3e5df3253075163ffe93cd4d\",\"merkle_root\":\"f1e2092a2b787a06d7272df43eaf87acc3b9c1d315d79d599d61c285983483e431998\",\"packets\":1,\"truncated_packets\":2,\"kept_bytes\":3,\"truncated_bytes\":4,\"pcapng_len\":5,\"stored_len\":6,\"parts\":1}],\"pack\":\"pack/p\",\"index\":[{\"table\":\"packets\",\"key\":\"index/p\",\"rows\":1}],\"totals\":{\"packets\":1,\"bytes\":2,\"kept_bytes\":3,\"truncated_bytes\":4,\"flows\":5,\"exchanges\":6,\"workunits\":7,\"events\":8,\"blobs\":9},\"chain\":{\"seq\":0,\"prev\":null,\"restart\":false,\"key\":\"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\"},\"sig\":\"4946a2dc63dee3f4ad7e7400acced7f72d42f51d7cb79ec2c26bc5ead2c61662b1052c7680c4f3606eca3510cc23fa74438fb13d6fbed263bdc198f99a6ebd00\"}\n",
        "{\"site\":\"local\",\"collector\":\"c1\",\"window_start_ns\":10,\"window_ns\":10,\"links\":[\"lo\"],\"chunks\":[],\"pack\":null,\"index\":[],\"totals\":{\"packets\":0,\"bytes\":0,\"kept_bytes\":0,\"truncated_bytes\":0,\"flows\":0,\"exchanges\":0,\"workunits\":0,\"events\":0,\"blobs\":0},\"chain\":{\"seq\":1,\"prev\":\"f1e20a634eed8799c7f9db6e64262d58d858642847cd693ea1a13dd807aa773f7c482\",\"restart\":false,\"key\":\"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\"},\"sig\":\"c5fe494ca6850218a300f6c15865494e3483d5b4b1565201e7b6b9e40d34a170199f7403da0ab51c0a7b889a5ac984a8106b20375cab2da50064493cab59b40c\"}\n",
    );

    fn manifest(w: u64) -> WindowManifest {
        WindowManifest {
            site: "local".into(),
            collector: "c1".into(),
            window_start_ns: w,
            window_ns: 10,
            links: vec![LinkId::new("lo")],
            chunks: Vec::new(),
            pack: None,
            index: Vec::new(),
            totals: Totals::default(),
        }
    }

    fn key(seed: [u8; 32]) -> Box<dyn KeyProvider> {
        Box::new(SoftwareKey::from_seed(seed))
    }

    fn public(seed: [u8; 32]) -> [u8; 32] {
        SoftwareKey::from_seed(seed).public_key()
    }

    /// A log of windows 0, 10, …, signed with `seed`, as its lines.
    fn log_of(seed: [u8; 32], windows: u64) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path(), key(seed)).unwrap();
        for w in 0..windows {
            log.append(&manifest(10 * w)).unwrap();
        }
        let text = std::fs::read_to_string(dir.path().join(LOG)).unwrap();
        text.lines().map(str::to_owned).collect()
    }

    fn verify(lines: &[String]) -> Result<Vec<Verified>, ChainError> {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        verify_log(text.as_bytes(), public(SEED))
    }

    #[test]
    fn appends_across_opens_and_drops_a_partial_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path(), key(SEED)).unwrap();
        log.append(&manifest(0)).unwrap();
        drop(log);
        // A crash mid-write.
        let path = dir.path().join(LOG);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"site\":\"lo").unwrap();
        drop(f);

        let mut log = Log::open(dir.path(), key(SEED)).unwrap();
        log.append(&manifest(10)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"site\":\"local\",\"collector\":\"c1\",\"window_start_ns\":0,"));
        assert!(lines[1].contains("\"window_start_ns\":10"));
        assert_eq!(manifest(10).dedup_key(), "c1/10");

        // The second run chains on from the first, and says it restarted.
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["chain"]["seq"], 0);
        assert_eq!(first["chain"]["prev"], serde_json::Value::Null);
        assert_eq!(first["chain"]["restart"], false);
        assert_eq!(second["chain"]["seq"], 1);
        assert_eq!(second["chain"]["prev"], mh::of(lines[0].as_bytes()));
        assert_eq!(second["chain"]["restart"], true);
        assert_eq!(second["chain"]["key"], hex(&public(SEED)));
        let v = verify_log(text.as_bytes(), public(SEED)).unwrap();
        assert_eq!(
            v.iter()
                .map(|v| (v.seq, v.restart, v.window_start_ns))
                .collect::<Vec<_>>(),
            [(0, false, 0), (1, true, 10)]
        );
    }

    #[test]
    fn a_valid_chain_verifies_and_is_deterministic() {
        let lines = log_of(SEED, 4);
        assert_eq!(verify(&lines).unwrap().len(), 4);
        assert_eq!(log_of(SEED, 4), lines);
        // A partial last line is not part of the log yet.
        let mut text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        text.push_str(&lines[0][..20]);
        assert_eq!(verify_log(text.as_bytes(), public(SEED)).unwrap().len(), 4);
    }

    #[test]
    fn a_dropped_window_fails() {
        let mut lines = log_of(SEED, 4);
        lines.remove(1);
        assert_eq!(
            verify(&lines),
            Err(ChainError::Sequence {
                line: 2,
                want: 1,
                got: 2
            })
        );
        // Dropping the first line too.
        let lines = log_of(SEED, 4)[1..].to_vec();
        assert!(matches!(
            verify(&lines),
            Err(ChainError::Sequence { line: 1, .. })
        ));
    }

    #[test]
    fn swapped_windows_fail() {
        let mut lines = log_of(SEED, 4);
        lines.swap(1, 2);
        assert!(matches!(
            verify(&lines),
            Err(ChainError::Sequence { line: 2, .. })
        ));
    }

    #[test]
    fn an_edited_window_fails() {
        let mut lines = log_of(SEED, 4);
        lines[2] = lines[2].replace("\"packets\":0", "\"packets\":7");
        assert_eq!(verify(&lines), Err(ChainError::BadSignature { line: 3 }));
        // Editing the chain itself, to splice out a window, fails the same.
        let mut lines = log_of(SEED, 4);
        let prev = mh::of(lines[0].as_bytes());
        let hop = lines[2]
            .replace(&mh::of(lines[1].as_bytes()), &prev)
            .replace("\"seq\":2", "\"seq\":1");
        lines.splice(1..3, [hop]);
        assert_eq!(verify(&lines), Err(ChainError::BadSignature { line: 2 }));
    }

    #[test]
    fn a_window_signed_with_another_key_fails() {
        // A whole log signed and chained by another key.
        let other = log_of([2; 32], 4);
        assert_eq!(verify(&other), Err(ChainError::WrongKey { line: 1 }));
        // One line re-signed by another key, chained correctly.
        let ours = log_of(SEED, 4);
        let mut lines = ours.clone();
        lines[3] = {
            let dir = tempfile::tempdir().unwrap();
            let mut log = Log::open(dir.path(), key([2; 32])).unwrap();
            log.seq = 3;
            log.prev = Some(mh::of(ours[2].as_bytes()));
            log.append(&manifest(30)).unwrap();
            std::fs::read_to_string(dir.path().join(LOG))
                .unwrap()
                .trim_end()
                .to_owned()
        };
        assert_eq!(verify(&lines), Err(ChainError::WrongKey { line: 4 }));
        // Claiming the trusted key doesn't help.
        lines[3] = lines[3].replace(&hex(&public([2; 32])), &hex(&public(SEED)));
        assert_eq!(verify(&lines), Err(ChainError::BadSignature { line: 4 }));
        // Neither does an unsigned line.
        let unsigned = ours[1][..ours[1].find(",\"sig\"").unwrap()].to_owned() + "}";
        let lines = vec![ours[0].clone(), unsigned];
        assert!(matches!(
            verify(&lines),
            Err(ChainError::Malformed { line: 2, .. })
        ));
    }

    #[test]
    fn a_window_already_logged_is_not_logged_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path(), key(SEED)).unwrap();
        log.append(&manifest(0)).unwrap();
        log.append(&manifest(10)).unwrap();
        drop(log);
        let before = std::fs::read(dir.path().join(LOG)).unwrap();

        // A re-run over the same capture.
        let mut log = Log::open(dir.path(), key(SEED)).unwrap();
        log.append(&manifest(0)).unwrap();
        log.append(&manifest(10)).unwrap();
        assert_eq!(std::fs::read(dir.path().join(LOG)).unwrap(), before);
        // The same window with other contents.
        let mut other = manifest(10);
        other.totals.packets = 1;
        let e = log.append(&other).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // A new window chains on, as a restart.
        log.append(&manifest(20)).unwrap();
        let text = std::fs::read(dir.path().join(LOG)).unwrap();
        let v = verify_log(&text, public(SEED)).unwrap();
        assert_eq!(
            v.iter().map(|v| v.restart).collect::<Vec<_>>(),
            [false, false, true]
        );
    }

    /// The bytes of a line are the format: every field of the manifest, in
    /// order, under a fixed key.
    #[test]
    fn a_signed_line_keeps_its_bytes() {
        let m = WindowManifest {
            chunks: vec![ChunkRecord {
                link: LinkId::new("lo"),
                window_start_ns: 0,
                key: "raw/c".into(),
                chunk_hash: mh::of(b"chunk"),
                merkle_root: mh::of(b"root"),
                packets: 1,
                truncated_packets: 2,
                kept_bytes: 3,
                truncated_bytes: 4,
                pcapng_len: 5,
                stored_len: 6,
                parts: 1,
            }],
            pack: Some("pack/p".into()),
            index: vec![IndexFile {
                table: "packets".into(),
                key: "index/p".into(),
                rows: 1,
            }],
            totals: Totals {
                packets: 1,
                bytes: 2,
                kept_bytes: 3,
                truncated_bytes: 4,
                flows: 5,
                exchanges: 6,
                workunits: 7,
                events: 8,
                blobs: 9,
            },
            ..manifest(0)
        };
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path(), key(SEED)).unwrap();
        log.append(&m).unwrap();
        log.append(&manifest(10)).unwrap();
        let text = std::fs::read_to_string(dir.path().join(LOG)).unwrap();
        assert_eq!(text, PINNED);
    }
}
