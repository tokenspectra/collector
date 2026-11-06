//! The window manifest (spec §11): what a sealed window names, and the
//! bytes of a line of the manifest log. The log itself is the Collector's.
//!
//! A line is the manifest's JSON object with `chain` as its last field and
//! `,"sig":"<128 hex digits>"` spliced in before the closing brace. The
//! signature is over [`SIG_CONTEXT`], which carries the format version,
//! followed by the line without that splice.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// The log of window manifests, inside the output directory.
pub const LOG: &str = "manifests.jsonl";

/// A Link, named after the capture interface (`if_name` in the pcapng
/// Interface Description Block, or `if<N>` when the block has no name).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(pub Arc<str>);

impl LinkId {
    pub fn new(name: &str) -> Self {
        LinkId(Arc::from(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for LinkId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// One L0 chunk as written (the `chunks` table, spec §6 "chunk index").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChunkRecord {
    pub link: LinkId,
    pub window_start_ns: u64,
    pub key: String,
    /// BLAKE3 of the uncompressed pcapng, as stored.
    pub chunk_hash: String,
    /// Merkle root over the packets' hashes (spec §6, `commit::merkle_root`).
    pub merkle_root: String,
    pub packets: u64,
    pub truncated_packets: u64,
    /// Captured bytes stored, and captured bytes cut by the Capture Rate.
    pub kept_bytes: u64,
    pub truncated_bytes: u64,
    pub pcapng_len: u64,
    /// Size of the compressed chunk, all parts together.
    pub stored_len: u64,
    /// Objects it is stored in: 1 is the object at `key`; more are
    /// `{key}-part0` to `{key}-part{parts - 1}`, whose bytes joined in order
    /// are the compressed chunk.
    pub parts: u64,
}

/// One index table of a window: where it is and how many rows it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IndexFile {
    pub table: String,
    pub key: String,
    pub rows: u64,
}

/// What a window holds, summed over its rows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub packets: u64,
    /// Wire bytes of those packets (`orig_len`).
    pub bytes: u64,
    /// Captured bytes written to chunks, and captured bytes the Capture Rate
    /// cut.
    pub kept_bytes: u64,
    pub truncated_bytes: u64,
    /// Flow rows: one per Flow per Slice.
    pub flows: u64,
    pub exchanges: u64,
    pub workunits: u64,
    pub events: u64,
    /// Pack items: bodies and Request Workunit records.
    pub blobs: u64,
}

/// One sealed window, as sent to the control plane (spec §11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowManifest {
    pub site: String,
    pub collector: String,
    pub window_start_ns: u64,
    pub window_ns: u64,
    pub links: Vec<LinkId>,
    pub chunks: Vec<ChunkRecord>,
    /// The window's pack, if it has items.
    pub pack: Option<String>,
    pub index: Vec<IndexFile>,
    pub totals: Totals,
    /// What the Fleet has to say about the window; absent in a run with no
    /// Fleet. These fields aren't what was captured: a re-run under
    /// another config repeats the window, it doesn't conflict with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<Observed>,
}

/// Who wrote the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// The multihash of the signed config this window was cut under.
    pub config: String,
}

/// How the window was cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureInfo {
    /// The seed epoch of the window's capture secret; never the secret.
    pub epoch: Option<u64>,
}

/// Live-only health, as the run saw it when it sealed the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observed {
    /// The control channel was down: the run went on with its last config
    /// and current seed epoch.
    pub channel_cut: bool,
}

impl WindowManifest {
    /// What the ingest deduplicates on: Collector and window.
    pub fn dedup_key(&self) -> String {
        format!("{}/{}", self.collector, self.window_start_ns)
    }
}

/// What every signature covers first, so a signed line can't pass for
/// anything else the key signs.
pub const SIG_CONTEXT: &[u8] = b"tokenspectra/window-manifest/v1\n";

/// What the signature is spliced in as, before the line's closing brace.
pub const SIG_FIELD: &[u8] = b",\"sig\":\"";

/// A line's place in the log's chain (the `chain` field).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// Position in the log, from 0. It keeps counting across restarts.
    pub seq: u64,
    /// The BLAKE3 hash of the line before, as logged (signature included,
    /// newline not), as a multihash name; `null` only on the first line.
    pub prev: Option<String>,
    /// The first line a run appended to an existing log. No run saw the
    /// windows between `prev`'s and this one.
    pub restart: bool,
    /// The Ed25519 public key that signed the line, 64 hex digits.
    pub key: String,
}

/// A manifest with its chain: the bytes the signature covers.
#[derive(Serialize)]
pub struct Unsigned<'a> {
    #[serde(flatten)]
    pub manifest: &'a WindowManifest,
    pub chain: &'a Chain,
}

pub fn signed_message(unsigned: &[u8]) -> Vec<u8> {
    [SIG_CONTEXT, unsigned].concat()
}
