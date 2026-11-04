//! The object store (spec §6–8): L0 chunks, packs and Parquet index tables,
//! written once each through the `object_store` crate.
//!
//! [`StoreSink`] sits in the sink chain and forwards every record
//! unchanged. It holds each window's packets, rows and pack items until the
//! window is sealed, then writes, in this order:
//!
//! - one zstd-compressed pcapng chunk per Link, cut by the Capture Rate
//!   (`capture`), named by the BLAKE3 hash of the uncompressed pcapng;
//! - one pack of the window's bodies and Request Workunit records;
//! - one Parquet file per index table;
//!
//! and then hands the window's manifest ([`crate::manifest`]), which names
//! them, to the sink behind it.
//!
//! A window is sealed once it has closed and every TCP packet in it has its
//! bytes bucketed (a Flow row can wait a window for its response head), or
//! when `hold_windows` more windows have closed, whichever comes first.
//! Packets still unknown then are kept in full. Every decision depends on
//! the capture only, so the store's contents are deterministic.
//!
//! The CLI's local store ([`local`]) syncs each object, and the directories
//! it creates, before the put returns. A window's manifest is committed
//! only after every object it names is on disk, so a machine crash cannot
//! keep a manifest and lose what it points at. [`open`] also takes an
//! `s3://` URL: Amazon S3 or an S3-compatible store.
//!
//! Every put is `PutMode::Create` (`If-None-Match: *` on S3). An object that
//! already exists with the same bytes (a re-run over the same capture) is
//! left alone; with other bytes, the run fails. A chunk bigger than
//! [`StoreConfig::part_bytes`] is split into `-partN` objects, each put
//! once, since a multipart upload cannot be write-once (spec §8).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::prefix::PrefixStore;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload};
use serde::Serialize;
use serde_json::Value;
use tracing::info;

use crate::assembler::{EventRecord, PacketRecord, SegmentRecord};
use crate::capture::{CaptureConfig, Class};
use crate::chunk::{self, Packet};
use crate::decode::{BodyKey, ExchangeRecord, FlowRecord, RecordSink, Span, WindowClose, WorkunitRecord};
use crate::flow::{Dir, FlowId};
use crate::manifest::{IndexFile, Totals, WindowManifest};
use crate::source::{CapturedPacket, LinkId};
use crate::stats::{add, Registry};
use crate::window::PacketRef;
use crate::{index, mh, pack};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("object store: {0}")]
    Store(#[from] object_store::Error),
    #[error("parquet: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0} already exists with different bytes; objects are written once")]
    Conflict(String),
    #[error("--store {0:?}: expected a directory or s3://bucket[/prefix]")]
    Url(String),
    #[error("{0}")]
    Endpoint(String),
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// The `{site}` and `{collector}` parts of every key.
    pub site: String,
    pub collector: String,
    pub window_ns: u64,
    pub capture: CaptureConfig,
    /// Closed windows a window waits for its Flow rows before it is sealed
    /// anyway.
    pub hold_windows: u64,
    pub zstd_level: i32,
    /// Stored bytes in one chunk object; a bigger chunk is split into
    /// `-partN` objects of this size, the last one shorter. S3 takes at
    /// most 5 GiB in one put.
    pub part_bytes: u64,
}

impl StoreConfig {
    pub fn new(window_ns: u64) -> Self {
        StoreConfig {
            site: "local".into(),
            collector: "local".into(),
            window_ns,
            capture: CaptureConfig::default(),
            hold_windows: 2,
            zstd_level: 3,
            part_bytes: 1 << 30,
        }
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
    /// Merkle root over the packets' hashes (spec §6, [`chunk::merkle_root`]).
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobKind {
    /// An HTTP body, as hashed (spec §6 L2).
    Body,
    /// A Request Workunit record, the `workunits` row's JSON (spec §6 L3).
    Workunit,
}

/// One pack item (the `blobs` table): hash → pack location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlobRecord {
    pub hash: String,
    pub kind: BlobKind,
    pub workunit_id: Option<String>,
    pub window_start_ns: u64,
    pub pack: String,
    /// The item's zstd frame is `[offset, offset + len)` of the pack.
    pub offset: u64,
    pub len: u64,
    pub raw_len: u64,
}

/// A packet waiting for its chunk.
struct Held {
    link_type: u32,
    ts_ns: u64,
    orig_len: u32,
    data: Vec<u8>,
    rec: Option<PacketRecord>,
    /// An anomaly points at this packet: keep it whole.
    flagged: bool,
}

struct Item {
    hash: String,
    kind: BlobKind,
    workunit_id: Option<String>,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Window {
    closed: bool,
    chunks: BTreeMap<LinkId, Vec<Held>>,
    rows: BTreeMap<&'static str, Vec<Value>>,
    items: Vec<Item>,
    item_hashes: HashSet<String>,
    /// Anomalies at (index, Flow) whose packet record has not arrived yet:
    /// the assembler reports them before the packet itself.
    pending_flags: HashSet<(u32, FlowId)>,
}

/// The settled spans of one Flow direction, by start offset.
#[derive(Default)]
struct DirSpans {
    spans: BTreeMap<u64, Span>,
    /// One past the last settled byte.
    cursor: u64,
}

/// What a store run wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSummary {
    pub chunks: u64,
    pub packs: u64,
    pub index_files: u64,
}

/// Wraps a [`RecordSink`]: writes the object store and forwards every
/// record, plus a `chunks` and a `blobs` record per object written.
pub struct StoreSink<'a> {
    inner: &'a mut dyn RecordSink,
    store: Arc<dyn ObjectStore>,
    cfg: StoreConfig,
    reg: Option<Arc<Registry>>,
    windows: BTreeMap<u64, Window>,
    sealed_through: Option<u64>,
    spans: HashMap<(FlowId, Dir), DirSpans>,
    /// TCP Flows whose last row is out: no more spans will come.
    done: HashSet<FlowId>,
    bodies: HashMap<BodyKey, Vec<u8>>,
    summary: StoreSummary,
    error: Option<StoreError>,
}

impl<'a> StoreSink<'a> {
    pub fn new(
        inner: &'a mut dyn RecordSink,
        store: Arc<dyn ObjectStore>,
        cfg: StoreConfig,
        reg: Option<Arc<Registry>>,
    ) -> Self {
        StoreSink {
            inner,
            store,
            cfg,
            reg,
            windows: BTreeMap::new(),
            sealed_through: None,
            spans: HashMap::new(),
            done: HashSet::new(),
            bodies: HashMap::new(),
            summary: StoreSummary::default(),
            error: None,
        }
    }

    /// Seals every window still held and reports the first error, if any.
    pub fn finish(mut self) -> Result<StoreSummary, StoreError> {
        while let Some(&w) = self.windows.keys().next() {
            self.seal(w);
        }
        match self.error.take() {
            Some(e) => Err(e),
            None => Ok(self.summary),
        }
    }

    /// The window a row or item goes in: its own while it is held, else the
    /// newest window still held (spec §8).
    fn slot(&mut self, window: Option<u64>) -> &mut Window {
        let w = match window {
            Some(w) if self.windows.contains_key(&w) => w,
            _ => match self.windows.keys().next_back() {
                Some(&w) => w,
                None => self.sealed_through.map_or(0, |s| s + self.cfg.window_ns),
            },
        };
        self.windows.entry(w).or_default()
    }

    /// The newest window held: where bodies and records go.
    fn current(&self) -> Option<u64> {
        self.windows.keys().next_back().copied()
    }

    fn row<T: Serialize>(&mut self, table: &'static str, window: Option<u64>, rec: &T) {
        match serde_json::to_value(rec) {
            Ok(v) => self.slot(window).rows.entry(table).or_default().push(v),
            Err(e) => {
                self.error.get_or_insert(e.into());
            }
        }
    }

    fn item(&mut self, item: Item) {
        let w = self.current();
        let win = self.slot(w);
        if win.item_hashes.insert(item.hash.clone()) {
            win.items.push(item);
        }
    }

    /// The stream range a TCP packet's payload covers.
    fn range(rec: &PacketRecord) -> Option<(FlowId, Dir, u64, u64)> {
        let (flow, dir, off, len) = (rec.flow.clone()?, rec.dir?, rec.stream_off?, rec.payload_len?);
        let end = off + i64::from(len);
        (end > 0).then(|| (flow, dir, off.max(0) as u64, end as u64))
    }

    fn resolved(&self, rec: &PacketRecord) -> bool {
        match Self::range(rec) {
            None => true,
            Some((flow, dir, _, end)) => {
                self.done.contains(&flow) || self.spans.get(&(flow, dir)).is_some_and(|s| s.cursor >= end)
            }
        }
    }

    fn ready(&self, w: &Window) -> bool {
        w.closed
            && w.chunks
                .values()
                .flatten()
                .all(|h| h.rec.as_ref().is_none_or(|r| self.resolved(r)))
    }

    /// Seals windows in order while they are ready, or overdue as of the
    /// close of `closing`.
    fn seal_ready(&mut self, closing: u64) {
        while let Some((&w, win)) = self.windows.iter().next() {
            let overdue = w + self.cfg.hold_windows * self.cfg.window_ns <= closing;
            if !(win.closed && (overdue || self.ready(win))) {
                break;
            }
            self.seal(w);
        }
    }

    fn class(&self, h: &Held) -> Class {
        let Some(rec) = &h.rec else { return Class::Full };
        if h.flagged || rec.flow.is_none() {
            return Class::Full;
        }
        if rec.stream_off.is_none() {
            // UDP or another IP protocol: opaque, the alarm.
            return if rec.payload_len.unwrap_or(0) > 0 {
                Class::Alarm
            } else {
                Class::Full
            };
        }
        let Some((flow, dir, start, end)) = Self::range(rec) else {
            return Class::Full;
        };
        let Some(ds) = self.spans.get(&(flow, dir)) else {
            return Class::Full;
        };
        let first = ds.spans.range(..=start).next_back().map_or(start, |(&s, _)| s);
        let labels = ds
            .spans
            .range(first..end)
            .map(|(_, s)| s)
            .filter(|s| s.start + s.len > start)
            .map(|s| (s.bucket, s.workunit.as_deref()));
        self.cfg.capture.classify(labels, self.cfg.window_ns)
    }

    fn seal(&mut self, w: u64) {
        let Some(mut win) = self.windows.remove(&w) else {
            return;
        };
        self.sealed_through = Some(w);
        if self.error.is_none() {
            if let Err(e) = self.write_window(w, &mut win) {
                self.error = Some(e);
            }
        }
        self.prune();
    }

    fn write_window(&mut self, w: u64, win: &mut Window) -> Result<(), StoreError> {
        let date = date_path(w);
        let (site, collector) = (safe(&self.cfg.site), safe(&self.cfg.collector));
        let mut chunks = Vec::with_capacity(win.chunks.len());
        for (link, held) in std::mem::take(&mut win.chunks) {
            let rec = self.write_chunk(w, &date, &link, &held)?;
            win.rows
                .entry("chunks")
                .or_default()
                .push(serde_json::to_value(&rec)?);
            self.inner.chunk(&rec);
            chunks.push(rec);
        }
        let mut pack = None;
        if !win.items.is_empty() {
            let key = format!("packs/{site}/{collector}/{date}/{w}.pack");
            pack = Some(key.clone());
            let (bytes, entries) = pack::build(win.items.iter().map(|i| &i.bytes[..]), self.cfg.zstd_level)?;
            self.put(&key, bytes, Kind::Pack)?;
            self.summary.packs += 1;
            for (item, e) in win.items.iter().zip(entries) {
                let rec = BlobRecord {
                    hash: item.hash.clone(),
                    kind: item.kind,
                    workunit_id: item.workunit_id.clone(),
                    window_start_ns: w,
                    pack: key.clone(),
                    offset: e.offset,
                    len: e.len,
                    raw_len: e.raw_len,
                };
                win.rows
                    .entry("blobs")
                    .or_default()
                    .push(serde_json::to_value(&rec)?);
                self.inner.blob(&rec);
            }
        }
        let mut index_files = Vec::with_capacity(index::TABLES.len());
        for table in index::TABLES {
            let rows = win.rows.get(table).map_or(&[][..], Vec::as_slice);
            let key = format!("index/{site}/{collector}/{date}/{w}/{table}.parquet");
            self.put(&key, index::parquet(table, rows)?, Kind::Index)?;
            self.summary.index_files += 1;
            index_files.push(IndexFile {
                table: table.to_string(),
                key,
                rows: rows.len() as u64,
            });
        }
        let manifest = self.build_manifest(w, win, chunks, pack, index_files);
        self.inner.manifest(&manifest);
        Ok(())
    }

    /// The window's manifest, from what was just written (spec §11).
    fn build_manifest(
        &self,
        w: u64,
        win: &Window,
        chunks: Vec<ChunkRecord>,
        pack: Option<String>,
        index: Vec<IndexFile>,
    ) -> WindowManifest {
        let rows = |table: &str| win.rows.get(table).map_or(&[][..], Vec::as_slice);
        let count = |table: &str| rows(table).len() as u64;
        let totals = Totals {
            packets: count("packets"),
            bytes: rows("packets")
                .iter()
                .filter_map(|p| p["orig_len"].as_u64())
                .sum(),
            kept_bytes: chunks.iter().map(|c| c.kept_bytes).sum(),
            truncated_bytes: chunks.iter().map(|c| c.truncated_bytes).sum(),
            flows: count("flows"),
            exchanges: count("http"),
            workunits: count("workunits"),
            events: count("events"),
            blobs: count("blobs"),
        };
        WindowManifest {
            site: self.cfg.site.clone(),
            collector: self.cfg.collector.clone(),
            window_start_ns: w,
            window_ns: self.cfg.window_ns,
            links: chunks.iter().map(|c| c.link.clone()).collect(),
            chunks,
            pack,
            index,
            totals,
        }
    }

    fn write_chunk(
        &mut self,
        w: u64,
        date: &str,
        link: &LinkId,
        held: &[Held],
    ) -> Result<ChunkRecord, StoreError> {
        let cap = &self.cfg.capture;
        let mut alarm_used: HashMap<&FlowId, u64> = HashMap::new();
        let mut stored: Vec<&[u8]> = Vec::with_capacity(held.len());
        let (mut truncated_packets, mut kept_bytes, mut truncated_bytes) = (0, 0, 0);
        for h in held {
            let full = match self.class(h) {
                Class::Full => true,
                Class::NotKept => false,
                Class::Alarm => {
                    let flow = h
                        .rec
                        .as_ref()
                        .and_then(|r| r.flow.as_ref())
                        .expect("alarm packets have a Flow");
                    let used = alarm_used.entry(flow).or_default();
                    *used += h.data.len() as u64;
                    *used <= cap.alarm_cap_bytes
                }
            };
            let keep = if full {
                h.data.len()
            } else {
                h.data.len().min(cap.truncate_to as usize)
            };
            if keep < h.data.len() {
                truncated_packets += 1;
                truncated_bytes += (h.data.len() - keep) as u64;
            }
            kept_bytes += keep as u64;
            stored.push(&h.data[..keep]);
        }
        let pcapng = chunk::pcapng(
            link.as_str(),
            held.iter().zip(&stored).map(|(h, data)| Packet {
                link_type: h.link_type,
                ts_ns: h.ts_ns,
                orig_len: h.orig_len,
                data,
            }),
        );
        let hashes: Vec<blake3::Hash> = held.iter().map(|h| blake3::hash(&h.data)).collect();
        let merkle_root = chunk::merkle_root(&hashes)
            .map(|h| mh::name(&h))
            .unwrap_or_default();
        let chunk_hash = mh::of(&pcapng);
        let compressed = zstd::bulk::compress(&pcapng, self.cfg.zstd_level)?;
        let key = format!(
            "raw/{}/{}/{}/{date}/{w}-{chunk_hash}.pcapng.zst",
            safe(&self.cfg.site),
            safe(&self.cfg.collector),
            safe(link.as_str())
        );
        let rec = ChunkRecord {
            link: link.clone(),
            window_start_ns: w,
            key: key.clone(),
            chunk_hash,
            merkle_root,
            packets: held.len() as u64,
            truncated_packets,
            kept_bytes,
            truncated_bytes,
            pcapng_len: pcapng.len() as u64,
            stored_len: compressed.len() as u64,
            parts: 1,
        };
        let part = usize::try_from(self.cfg.part_bytes.max(1)).unwrap_or(usize::MAX);
        let rec = if compressed.len() <= part {
            self.put(&key, compressed, Kind::Chunk)?;
            rec
        } else {
            let pieces = compressed.chunks(part);
            let parts = pieces.len() as u64;
            for (i, piece) in pieces.enumerate() {
                self.put(&format!("{key}-part{i}"), piece.to_vec(), Kind::Chunk)?;
            }
            ChunkRecord { parts, ..rec }
        };
        self.summary.chunks += 1;
        if let Some(r) = &self.reg {
            add(&r.capture_packets[0], rec.packets - truncated_packets);
            add(&r.capture_packets[1], truncated_packets);
            add(&r.capture_kept_bytes, kept_bytes);
            add(&r.capture_truncated_bytes, truncated_bytes);
        }
        Ok(rec)
    }

    /// Writes `bytes` once under `key`.
    fn put(&self, key: &str, bytes: Vec<u8>, kind: Kind) -> Result<(), StoreError> {
        let path = ObjectPath::from(key);
        let len = bytes.len() as u64;
        let opts = PutOptions {
            mode: PutMode::Create,
            ..PutOptions::default()
        };
        match block_on(self.store.put_opts(&path, PutPayload::from(bytes.clone()), opts)) {
            Ok(_) => {
                if let Some(r) = &self.reg {
                    add(&r.store_objects[kind as usize], 1);
                    add(&r.store_bytes[kind as usize], len);
                }
                Ok(())
            }
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = block_on(async { self.store.get(&path).await?.bytes().await })?;
                if existing[..] != bytes[..] {
                    return Err(StoreError::Conflict(key.to_string()));
                }
                if let Some(r) = &self.reg {
                    add(&r.store_existing, 1);
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Forgets spans no held packet can still need.
    fn prune(&mut self) {
        let mut low: HashMap<(FlowId, Dir), u64> = HashMap::new();
        for h in self.windows.values().flat_map(|w| w.chunks.values().flatten()) {
            if let Some((flow, dir, start, _)) = h.rec.as_ref().and_then(Self::range) {
                let l = low.entry((flow, dir)).or_insert(start);
                *l = (*l).min(start);
            }
        }
        self.spans.retain(|k, ds| match low.get(k) {
            None => false,
            Some(&l) => {
                ds.spans.retain(|_, s| s.start + s.len > l);
                true
            }
        });
        let held: HashSet<&FlowId> = low.keys().map(|(f, _)| f).collect();
        self.done.retain(|f| held.contains(f));
    }
}

/// What an object is, for the counters.
#[derive(Clone, Copy)]
enum Kind {
    Chunk = 0,
    Pack = 1,
    Index = 2,
}

/// A key part from a name: every character outside `[A-Za-z0-9._-]`
/// becomes `_`, so nothing from the capture goes into a key unchecked.
fn safe(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() || s.chars().all(|c| c == '.') {
        "_".into()
    } else {
        s
    }
}

/// `yyyy/mm/dd` of a capture time, in UTC.
fn date_path(ns: u64) -> String {
    let (y, m, d) = crate::stats::civil_date(ns);
    format!("{y:04}/{m:02}/{d:02}")
}

impl RecordSink for StoreSink<'_> {
    fn captured(&mut self, pkt: &CapturedPacket, at: PacketRef) {
        let held = Held {
            link_type: pkt.link_type,
            ts_ns: pkt.ts_ns,
            orig_len: pkt.orig_len,
            data: pkt.data.clone(),
            rec: None,
            flagged: false,
        };
        let chunk = self
            .windows
            .entry(at.window_start_ns)
            .or_default()
            .chunks
            .entry(pkt.link_id.clone())
            .or_default();
        debug_assert_eq!(chunk.len(), at.index as usize, "packets arrive in index order");
        chunk.push(held);
        self.inner.captured(pkt, at);
    }

    fn packet(&mut self, rec: &PacketRecord) {
        if let Some(win) = self.windows.get_mut(&rec.window_start_ns) {
            let flagged = rec
                .flow
                .clone()
                .is_some_and(|f| win.pending_flags.remove(&(rec.index, f)));
            if let Some(h) = win
                .chunks
                .get_mut(&rec.link)
                .and_then(|c| c.get_mut(rec.index as usize))
            {
                h.rec = Some(rec.clone());
                h.flagged |= flagged;
            }
        }
        self.row("packets", Some(rec.window_start_ns), rec);
        self.inner.packet(rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        self.row("segments", Some(rec.window_start_ns), rec);
        self.inner.segment(rec, data);
    }

    fn event(&mut self, rec: &EventRecord) {
        if !rec.kind.is_gap() {
            let at = rec.window_start_ns.zip(rec.index);
            if let Some((win, i)) = at.and_then(|(w, i)| Some((self.windows.get_mut(&w)?, i))) {
                let held = win.chunks.values_mut().find_map(|c| {
                    c.get_mut(i as usize)
                        .filter(|h| h.rec.as_ref().is_some_and(|r| r.flow.as_ref() == Some(&rec.flow)))
                });
                match held {
                    Some(h) => h.flagged = true,
                    // The packet's own record comes next: flag it then.
                    None => {
                        win.pending_flags.insert((i, rec.flow.clone()));
                    }
                }
            }
        }
        let w = rec.window_start_ns.or(self.current());
        self.row("events", w, rec);
        self.inner.event(rec);
    }

    fn spans(&mut self, flow: &FlowId, dir: Dir, spans: &[Span]) {
        let ds = self.spans.entry((flow.clone(), dir)).or_default();
        for s in spans {
            ds.cursor = ds.cursor.max(s.start + s.len);
            ds.spans.insert(s.start, s.clone());
        }
        self.inner.spans(flow, dir, spans);
    }

    fn flow(&mut self, rec: &FlowRecord) {
        if rec.slice.ended {
            self.done.insert(rec.slice.flow.clone());
        }
        self.row("flows", Some(rec.slice.window_start_ns), rec);
        self.inner.flow(rec);
    }

    fn exchange(&mut self, rec: &ExchangeRecord) {
        let w = self.current();
        self.row("http", w, rec);
        self.inner.exchange(rec);
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        let w = self.current();
        self.row("workunits", w, rec);
        match serde_json::to_vec(rec) {
            Ok(bytes) => self.item(Item {
                hash: mh::of(&bytes),
                kind: BlobKind::Workunit,
                workunit_id: Some(rec.workunit_id.clone()),
                bytes,
            }),
            Err(e) => {
                self.error.get_or_insert(e.into());
            }
        }
        self.inner.workunit(rec);
    }

    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        self.bodies
            .entry(key.clone())
            .or_default()
            .extend_from_slice(data);
        self.inner.body_data(key, data);
    }

    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        let bytes = self.bodies.remove(key).unwrap_or_default();
        if let Some(h) = hash.filter(|h| mh::parse(h).is_some()) {
            self.item(Item {
                hash: h.to_string(),
                kind: BlobKind::Body,
                workunit_id: None,
                bytes,
            });
        }
        self.inner.body_end(key, hash);
    }

    fn window_closed(&mut self, w: &WindowClose) {
        if let Some(win) = self.windows.get_mut(&w.window_start_ns) {
            win.closed = true;
        }
        self.seal_ready(w.window_start_ns);
        self.inner.window_closed(w);
    }
}

/// Runs the object store's futures. The S3 client needs a tokio runtime;
/// one worker is enough, since the store makes one request at a time.
fn block_on<F: Future>(f: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("object-store")
            .enable_all()
            .build()
            .expect("tokio runtime")
    });
    RT.block_on(f)
}

/// The store `--store` names: `s3://bucket[/prefix]`, or a local directory,
/// created if missing ([`local`]).
///
/// The endpoint must be given: `endpoint` (`--s3-endpoint`), else
/// `AWS_ENDPOINT` ([`s3_endpoint`]). Without either an `s3://` store is
/// refused; the Collector never falls back to AWS's default endpoint, so
/// evidence cannot leave for a store nobody named. The endpoint chosen is
/// logged, and pinned: no other `AWS_*` variable can move it.
///
/// Other S3 settings come from the environment, as for the AWS CLI:
/// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
/// `AWS_REGION`, and `AWS_ALLOW_HTTP=true` for a plain `http://` endpoint.
/// The store must honour `If-None-Match: *` on PutObject, or objects could
/// be overwritten.
pub fn open(store: &str, endpoint: Option<&str>) -> Result<Arc<dyn ObjectStore>, StoreError> {
    let Some(rest) = store.strip_prefix("s3://") else {
        std::fs::create_dir_all(store)?;
        return Ok(Arc::new(local(Path::new(store))?));
    };
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() {
        return Err(StoreError::Url(store.to_string()));
    }
    let endpoint = s3_endpoint(endpoint, std::env::var("AWS_ENDPOINT").ok().as_deref())?;
    let s3 = AmazonS3Builder::from_env()
        .with_bucket_name(bucket)
        // Both keys: `AWS_ENDPOINT_URL_S3` would otherwise win over it.
        .with_config(AmazonS3ConfigKey::Endpoint, &endpoint)
        .with_config(AmazonS3ConfigKey::S3Endpoint, &endpoint)
        .build()?;
    let prefix = ObjectPath::parse(prefix).map_err(|_| StoreError::Url(store.to_string()))?;
    info!(store, endpoint, "object store: S3");
    Ok(if prefix.as_ref().is_empty() {
        Arc::new(s3)
    } else {
        Arc::new(PrefixStore::new(s3, prefix))
    })
}

/// The S3 endpoint to use: `flag` (`--s3-endpoint`), else `env`
/// (`AWS_ENDPOINT`). Fails when neither is given, or the one given is not
/// an `http://` or `https://` URL with a host: there is no default.
pub fn s3_endpoint(flag: Option<&str>, env: Option<&str>) -> Result<String, StoreError> {
    let given = flag.or(env).map(str::trim).filter(|e| !e.is_empty());
    let Some(endpoint) = given else {
        return Err(StoreError::Endpoint(
            "an s3:// store needs its endpoint: --s3-endpoint or AWS_ENDPOINT; there is no default".into(),
        ));
    };
    let host = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
    match host {
        Some(h) if !h.is_empty() && !endpoint.contains(char::is_whitespace) => Ok(endpoint.to_string()),
        _ => Err(StoreError::Endpoint(format!(
            "S3 endpoint {endpoint:?}: expected http://host[:port] or https://host[:port]"
        ))),
    }
}

/// The local object store under `dir`. Each put syncs the object and the
/// directories it creates before it returns, so a manifest committed after
/// it never names an object a crash can lose.
pub fn local(dir: &Path) -> Result<LocalFileSystem, StoreError> {
    Ok(LocalFileSystem::new_with_prefix(dir)?.with_fsync(true))
}

/// Looks up a blob's bytes by hash through the `blobs` rows, and checks
/// them against the hash (spec §11: every read is verified).
pub fn fetch_blob(
    store: &dyn ObjectStore,
    blobs: &[BlobRecord],
    hash: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(b) = blobs.iter().find(|b| b.hash == hash) else {
        return Ok(None);
    };
    let path = ObjectPath::from(b.pack.as_str());
    let frame = block_on(store.get_range(&path, b.offset..b.offset + b.len))?;
    let bytes = zstd::bulk::decompress(&frame, b.raw_len as usize)?;
    verify(hash, &bytes)?;
    Ok(Some(bytes))
}

/// Reads an L0 chunk by key and part count (its `chunks` row),
/// decompressed, and checks it against the hash in its name.
pub fn fetch_chunk(store: &dyn ObjectStore, key: &str, parts: u64) -> Result<Vec<u8>, StoreError> {
    let get = |key: &str| {
        let path = ObjectPath::from(key);
        block_on(async { store.get(&path).await?.bytes().await })
    };
    let compressed = match parts {
        0 | 1 => get(key)?.to_vec(),
        n => {
            let mut all = Vec::new();
            for i in 0..n {
                all.extend_from_slice(&get(&format!("{key}-part{i}"))?);
            }
            all
        }
    };
    let bytes = zstd::stream::decode_all(&compressed[..])?;
    let name = key
        .rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".pcapng.zst"))
        .and_then(|f| f.rsplit('-').next())
        .unwrap_or_default();
    verify(name, &bytes)?;
    Ok(bytes)
}

fn verify(hash: &str, bytes: &[u8]) -> Result<(), StoreError> {
    if mh::parse(hash) != Some(blake3::hash(bytes)) {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bytes do not match {hash}"),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use object_store::memory::InMemory;

    use super::*;
    use crate::assembler::{DirStats, SliceRecord};
    use crate::capture::CaptureConfig;
    use crate::decode::{Bucket, Buckets, WorkunitTag};
    use crate::flow::{Endpoint, FlowKind, Tuple};

    const W: u64 = 1_000_000_000;

    /// Keeps the chunk records; drops everything else.
    #[derive(Default)]
    struct Chunks(Vec<ChunkRecord>);

    impl RecordSink for Chunks {
        fn packet(&mut self, _: &PacketRecord) {}
        fn segment(&mut self, _: &SegmentRecord, _: &[u8]) {}
        fn event(&mut self, _: &EventRecord) {}
        fn flow(&mut self, _: &FlowRecord) {}
        fn exchange(&mut self, _: &ExchangeRecord) {}
        fn workunit(&mut self, _: &WorkunitRecord) {}
        fn chunk(&mut self, rec: &ChunkRecord) {
            self.0.push(rec.clone());
        }
    }

    fn link() -> LinkId {
        LinkId::new("tap0")
    }

    fn ends() -> (Endpoint, Endpoint) {
        let ep = |last, port| Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        };
        (ep(1, 40000), ep(2, 8000))
    }

    fn flow_id() -> FlowId {
        let (a, b) = ends();
        FlowId::new(&Tuple::new(link(), FlowKind::Tcp, a, b), 0)
    }

    fn captured(len: usize, ts_ns: u64) -> CapturedPacket {
        CapturedPacket {
            link_id: link(),
            link_type: 1,
            ts_ns,
            orig_len: len as u32,
            data: vec![0; len],
        }
    }

    /// A TCP packet of [`flow_id`] carrying stream bytes `[off, off + len)`.
    fn tcp(index: u32, off: i64, len: u32) -> PacketRecord {
        PacketRecord {
            link: link(),
            window_start_ns: 0,
            index,
            ts_ns: u64::from(index),
            cap_len: 54 + len,
            orig_len: 54 + len,
            hash: String::new(),
            flow: Some(flow_id()),
            dir: Some(Dir::Orig),
            tcp_flags: None,
            stream_off: Some(off),
            payload_len: Some(len),
            note: None,
        }
    }

    fn span(start: u64, len: u64, bucket: Bucket, workunit: Option<&Arc<WorkunitTag>>) -> Span {
        Span {
            start,
            len,
            bucket,
            workunit: workunit.cloned(),
        }
    }

    /// With the alarm cap used up, a packet mixing `unexplained` bytes with
    /// `http_other` or kept Workunit bytes still stays whole (spec §7).
    #[test]
    fn full_bytes_beat_an_exhausted_alarm_cap() {
        let mut inner = Chunks::default();
        let mut cfg = StoreConfig::new(W);
        cfg.capture = CaptureConfig {
            alarm_cap_bytes: 0,
            truncate_to: 54,
            ..CaptureConfig::default()
        };
        let mut sink = StoreSink::new(&mut inner, Arc::new(InMemory::new()), cfg, None);
        let tag = Arc::new(WorkunitTag {
            workunit_id: mh::of(b"wu"),
            received_ts_ns: 0,
        });
        // Only `unexplained`; `unexplained` + `http_other`; `unexplained` +
        // a kept Workunit.
        for i in 0..3u32 {
            sink.captured(
                &captured(54 + 100, u64::from(i)),
                PacketRef {
                    window_start_ns: 0,
                    index: i,
                },
            );
            sink.packet(&tcp(i, i64::from(i) * 100, 100));
        }
        sink.spans(
            &flow_id(),
            Dir::Orig,
            &[
                span(0, 150, Bucket::Unexplained, None),
                span(150, 50, Bucket::HttpOther, None),
                span(200, 50, Bucket::Unexplained, None),
                span(250, 50, Bucket::Workunit, Some(&tag)),
            ],
        );
        sink.window_closed(&WindowClose {
            window_start_ns: 0,
            window_ns: W,
            capture_drops: None,
        });
        sink.finish().unwrap();
        let c = &inner.0[0];
        assert_eq!((c.packets, c.truncated_packets, c.truncated_bytes), (3, 1, 100));
    }

    /// A row whose window has been sealed goes in the newest window held
    /// (spec §8), not the oldest.
    #[test]
    fn late_rows_go_in_the_newest_window_held() {
        let mut inner = Chunks::default();
        let mut sink = StoreSink::new(&mut inner, Arc::new(InMemory::new()), StoreConfig::new(W), None);
        for w in 0..3 {
            sink.captured(
                &captured(60, w * W),
                PacketRef {
                    window_start_ns: w * W,
                    index: 0,
                },
            );
        }
        sink.window_closed(&WindowClose {
            window_start_ns: 0,
            window_ns: W,
            capture_drops: None,
        });
        assert_eq!(sink.windows.keys().copied().collect::<Vec<_>>(), [W, 2 * W]);
        let (orig, resp) = ends();
        let slice = SliceRecord {
            window_start_ns: 0,
            flow: flow_id(),
            link: link(),
            kind: FlowKind::Tcp,
            generation: 0,
            orig,
            resp,
            first_ts_ns: 0,
            slice_first_ts_ns: Some(0),
            slice_last_ts_ns: Some(0),
            mid_stream_start: false,
            syn: true,
            syn_ack: true,
            fin_orig: false,
            fin_resp: false,
            rst: false,
            ended: false,
            orig_stats: DirStats::default(),
            resp_stats: DirStats::default(),
        };
        sink.flow(&FlowRecord {
            slice,
            verdict: None,
            orig_bytes: Buckets::default(),
            resp_bytes: Buckets::default(),
            orig_desync: None,
            resp_desync: None,
        });
        let flows = |w: u64| sink.windows[&w].rows.get("flows").map_or(0, Vec::len);
        assert_eq!((flows(W), flows(2 * W)), (0, 1));
    }

    #[test]
    fn key_parts_are_safe() {
        assert_eq!(safe("lo"), "lo");
        assert_eq!(safe("eth0:1/../x"), "eth0_1_.._x");
        assert_eq!(safe(".."), "_");
        assert_eq!(safe(""), "_");
        assert_eq!(date_path(1_793_619_416_000_000_000), "2026/11/02");
    }

    /// An s3:// store has no default endpoint: one must be named.
    #[test]
    fn the_s3_endpoint_is_required() {
        for (flag, env) in [(None, None), (Some(""), None), (None, Some("  "))] {
            let err = s3_endpoint(flag, env).unwrap_err().to_string();
            assert!(err.contains("needs its endpoint"), "{err}");
        }
        for bad in [
            "s3.amazonaws.com",
            "ftp://x",
            "https://",
            "http:///bucket",
            "https://a b",
        ] {
            assert!(s3_endpoint(Some(bad), None).is_err(), "{bad}");
        }
        let e = |flag, env| s3_endpoint(flag, env).unwrap();
        assert_eq!(e(Some("http://127.0.0.1:7070"), None), "http://127.0.0.1:7070");
        assert_eq!(
            e(None, Some("https://s3.eu-west-1.amazonaws.com")),
            "https://s3.eu-west-1.amazonaws.com"
        );
        assert_eq!(e(Some("http://flag:1"), Some("http://env:2")), "http://flag:1");
        // `open` checks it before building any client.
        let err = open("s3://bucket", Some("nope")).err().unwrap().to_string();
        assert!(err.contains("expected http://host"), "{err}");
    }

    #[test]
    fn the_local_store_syncs_puts() {
        // `LocalFileSystem` exposes the setting only through `Debug`.
        let dir = tempfile::tempdir().unwrap();
        assert!(format!("{:?}", local(dir.path()).unwrap()).contains("fsync: true"));
    }
}
