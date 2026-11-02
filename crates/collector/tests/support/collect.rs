//! Shared test helpers: run the Collector into memory or into JSONL files.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use collector::assembler::{EventRecord, PacketRecord, SegmentRecord, SliceRecord};
use collector::decode::{ExchangeRecord, FlowRecord, RecordSink, WorkunitRecord};
use collector::flow::Dir;
use collector::output::{JsonlSink, TABLES};
use collector::run::run;
use collector::{AssemblerConfig, FileSource, PacketSource};

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
}

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn fixture_paths(names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(|n| fixture_dir().join(n)).collect()
}

pub fn collect(source: &mut dyn PacketSource) -> Collected {
    let mut sink = Collected::default();
    run(source, WINDOW_NS, AssemblerConfig::default(), &mut sink).expect("run");
    sink
}

pub fn collect_files(names: &[&str]) -> Collected {
    collect(&mut FileSource::new(fixture_paths(names)))
}

/// Runs `source` and returns each JSONL table's bytes, in [`TABLES`] order.
pub fn tables(source: &mut dyn PacketSource) -> Vec<(String, Vec<u8>)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = JsonlSink::create(dir.path()).expect("sink");
    run(source, WINDOW_NS, AssemblerConfig::default(), &mut sink).expect("run");
    sink.finish().expect("finish");
    TABLES
        .iter()
        .map(|t| {
            let name = format!("{t}.jsonl");
            let bytes = std::fs::read(dir.path().join(&name)).expect("read table");
            (name, bytes)
        })
        .collect()
}
