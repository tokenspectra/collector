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
//! across runs too: a re-run over the same capture appends the same lines
//! again, and the ingest deduplicates them by Collector and window.
//!
//! Every field comes from the capture, so the lines are byte-identical
//! across runs (spec §12).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use serde::Serialize;

use crate::source::LinkId;
use crate::store::ChunkRecord;

/// The log of window manifests, inside the output directory.
pub const LOG: &str = "manifests.jsonl";

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
}

impl WindowManifest {
    /// What the ingest deduplicates on: Collector and window.
    pub fn dedup_key(&self) -> String {
        format!("{}/{}", self.collector, self.window_start_ns)
    }
}

/// The append-only manifest log.
pub struct Log {
    file: File,
}

impl Log {
    /// Opens [`LOG`] in `dir` for appending, creating it if needed. A
    /// partial last line, left by a crash mid-write, is cut off first: it
    /// was never complete, so it was never shipped.
    ///
    /// A new log's directory entry is synced before the first append, so a
    /// synced line can't be lost with the file that holds it.
    pub fn open(dir: &Path) -> io::Result<Self> {
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
        if len > 0 {
            let complete = complete_len(&mut file, len)?;
            if complete < len {
                file.set_len(complete)?;
            }
        }
        Ok(Log { file })
    }

    /// Appends one manifest as a line and syncs it to disk.
    pub fn append(&mut self, m: &WindowManifest) -> io::Result<()> {
        let mut line = serde_json::to_vec(m)?;
        line.push(b'\n');
        // One write per line: a crash leaves at most a partial last line,
        // which the shipper never sends.
        self.file.write_all(&line)?;
        self.file.sync_data()
    }
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

    #[test]
    fn appends_across_opens_and_drops_a_partial_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path()).unwrap();
        log.append(&manifest(0)).unwrap();
        drop(log);
        // A crash mid-write.
        let path = dir.path().join(LOG);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"site\":\"lo").unwrap();
        drop(f);

        let mut log = Log::open(dir.path()).unwrap();
        log.append(&manifest(10)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"window_start_ns\":0"));
        assert!(lines[1].contains("\"window_start_ns\":10"));
        assert_eq!(manifest(10).dedup_key(), "c1/10");
    }
}
