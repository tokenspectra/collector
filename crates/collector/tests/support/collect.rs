//! Shared test helpers: run the Collector into memory or into JSONL files.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use collector::assembler::{EventRecord, PacketRecord, SegmentRecord, SliceRecord};
use collector::decode::{BodyKey, ExchangeRecord, FlowRecord, RecordSink, WorkunitRecord};
use collector::flow::Dir;
use collector::manifest::LOG;
use collector::observe::StatsSink;
use collector::output::{JsonlSink, BODIES, TABLES};
use collector::run::run;
use collector::stats::{Registry, Snapshot};
use collector::store::{StoreConfig, StoreSink};
use collector::{AssemblerConfig, DecoderConfig, FileSource, PacketSource};

pub const WINDOW_NS: u64 = 1_000_000_000;

/// Keeps everything in memory. Streams are rebuilt from segments; gap
/// bytes show as `~`.
#[derive(Default)]
pub struct Collected {
    pub packets: Vec<PacketRecord>,
    pub segments: Vec<SegmentRecord>,
    pub events: Vec<EventRecord>,
    pub slices: Vec<SliceRecord>,
    pub flows: Vec<FlowRecord>,
    pub exchanges: Vec<ExchangeRecord>,
    pub workunits: Vec<WorkunitRecord>,
    /// Kept bodies by hash name.
    pub bodies: BTreeMap<String, Vec<u8>>,
    open_bodies: BTreeMap<BodyKey, Vec<u8>>,
    pub streams: BTreeMap<(String, Dir), Vec<u8>>,
}

impl Collected {
    pub fn stream(&self, flow: &str, dir: Dir) -> String {
        let bytes = self
            .streams
            .get(&(flow.to_string(), dir))
            .cloned()
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn put(&mut self, flow: &str, dir: Dir, off: u64, data: &[u8]) {
        let s = self.streams.entry((flow.to_string(), dir)).or_default();
        assert_eq!(s.len() as u64, off, "stream delivered out of order");
        s.extend_from_slice(data);
    }
}

impl RecordSink for Collected {
    fn packet(&mut self, rec: &PacketRecord) {
        self.packets.push(rec.clone());
    }

    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        assert_eq!(rec.len, data.len() as u64);
        self.put(rec.flow.as_str(), rec.dir, rec.stream_off, data);
        self.segments.push(rec.clone());
    }

    fn event(&mut self, rec: &EventRecord) {
        if let (Some(dir), Some(off)) = (rec.dir, rec.stream_off) {
            if rec.kind.is_gap() {
                let fill = vec![b'~'; rec.len as usize];
                self.put(rec.flow.as_str(), dir, off, &fill);
            }
        }
        self.events.push(rec.clone());
    }

    fn flow(&mut self, rec: &FlowRecord) {
        self.slices.push(rec.slice.clone());
        self.flows.push(rec.clone());
    }

    fn exchange(&mut self, rec: &ExchangeRecord) {
        self.exchanges.push(rec.clone());
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        self.workunits.push(rec.clone());
    }

    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        self.open_bodies
            .entry(key.clone())
            .or_default()
            .extend_from_slice(data);
    }

    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        let body = self.open_bodies.remove(key).unwrap_or_default();
        if let Some(hash) = hash {
            self.bodies.insert(hash.to_string(), body);
        }
    }
}

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn fixture_paths(names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(|n| fixture_dir().join(n)).collect()
}

pub fn collect(source: &mut dyn PacketSource) -> Collected {
    let mut sink = Collected::default();
    run(
        source,
        WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut sink,
    )
    .expect("run");
    sink
}

/// Like [`collect`], through a [`StatsSink`]; returns the final counters too.
pub fn collect_observed(source: &mut dyn PacketSource) -> (Collected, Snapshot) {
    let mut sink = Collected::default();
    let reg = Registry::new();
    run(
        source,
        WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut StatsSink::new(&mut sink, reg.clone()),
    )
    .expect("run");
    (sink, reg.snapshot())
}

pub fn collect_files(names: &[&str]) -> Collected {
    collect(&mut FileSource::new(fixture_paths(names)))
}

/// (file name, bytes) per output file.
pub type Files = Vec<(String, Vec<u8>)>;

/// Runs `source` and returns each JSONL table's bytes, in [`TABLES`] order,
/// then the manifest log's.
pub fn tables(source: &mut dyn PacketSource) -> Files {
    tables_and_bodies(source, true).0
}

/// Like [`tables`], also returning the files in `bodies/` (name, bytes),
/// sorted by name.
pub fn tables_and_bodies(source: &mut dyn PacketSource, keep_bodies: bool) -> (Files, Files) {
    tables_and_bodies_with(source, keep_bodies, false)
}

/// Like [`tables_and_bodies`]; with `observe`, the sink is wrapped in a
/// [`StatsSink`] the way the CLI runs it.
pub fn tables_and_bodies_with(
    source: &mut dyn PacketSource,
    keep_bodies: bool,
    observe: bool,
) -> (Files, Files) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = DecoderConfig {
        keep_bodies,
        ..DecoderConfig::default()
    };
    run_stored(
        source,
        dir.path(),
        cfg,
        StoreConfig::new(WINDOW_NS),
        observe.then(Registry::new),
    );
    let mut bodies: Files = std::fs::read_dir(dir.path().join(BODIES))
        .map(|rd| {
            rd.map(|e| {
                let e = e.expect("entry");
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).expect("body"),
                )
            })
            .collect()
        })
        .unwrap_or_default();
    bodies.sort();
    let tables = TABLES
        .iter()
        .map(|t| format!("{t}.jsonl"))
        .chain([LOG.to_string()])
        .map(|name| {
            let bytes = std::fs::read(dir.path().join(&name)).expect("read table");
            (name, bytes)
        })
        .collect();
    (tables, bodies)
}

/// Runs `source` into `out` the way the CLI does: tables in `out`, the
/// object store in `out/store`, and with a registry, through a
/// [`StatsSink`].
pub fn run_stored(
    source: &mut dyn PacketSource,
    out: &Path,
    cfg: DecoderConfig,
    store_cfg: StoreConfig,
    reg: Option<std::sync::Arc<Registry>>,
) {
    let store_dir = out.join("store");
    std::fs::create_dir_all(&store_dir).expect("store dir");
    let store = std::sync::Arc::new(
        object_store::local::LocalFileSystem::new_with_prefix(&store_dir).expect("local store"),
    );
    let mut sink = JsonlSink::create(out).expect("sink");
    let mut stored = StoreSink::new(&mut sink, store, store_cfg, reg.clone());
    match reg {
        Some(reg) => {
            let mut stats = StatsSink::new(&mut stored, reg);
            run(source, WINDOW_NS, AssemblerConfig::default(), cfg, &mut stats).expect("run");
        }
        None => {
            run(source, WINDOW_NS, AssemblerConfig::default(), cfg, &mut stored).expect("run");
        }
    }
    stored.finish().expect("store");
    sink.finish().expect("finish");
}

/// Runs `source` into a fresh output directory, bodies, views and the
/// object store included, the way the CLI does.
pub fn run_to_dir(source: &mut dyn PacketSource) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    run_stored(
        source,
        dir.path(),
        DecoderConfig::default(),
        StoreConfig::new(WINDOW_NS),
        None,
    );
    collector::views::write(dir.path()).expect("views");
    dir
}
