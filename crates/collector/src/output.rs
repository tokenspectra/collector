//! JSON Lines output, one file per table.
//!
//! `packets`, `segments` (stream offset → packet), `events` (gaps,
//! anomalies), `flows` (one row per Flow per Slice, with verdict and byte
//! accounting), `dns` (one row per DNS message), `features` (covert-channel
//! features, one row per Slice that has any), `http` (one row per HTTP exchange), `workunits` (Request
//! Workunits), and, when a [`StoreSink`](crate::store::StoreSink) writes the
//! object store in front of this sink, `chunks` (one row per L0 chunk) and
//! `blobs` (one row per pack item). Rows are written in a fixed order with fixed field order, so
//! the files are byte-identical across runs.
//!
//! Each window's manifest is signed, chained and appended to the manifest
//! log ([`manifest::LOG`](crate::manifest::LOG)) as the store seals it.
//!
//! HTTP bodies go to `bodies/{multihash}`, one file per distinct body, until
//! packs exist (spec §8). `b3sum` of a file prints the last 64 digits of its
//! name.
//!
//! The tables are flushed when each window closes, so a live run's files are
//! readable up to the last closed window, and an abrupt stop loses at most
//! the rows since then. The window's exchanges are added to `by-exchange/`
//! at the same point (`views`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::assembler::{EventRecord, PacketRecord, SegmentRecord};
use crate::decode::{BodyKey, ExchangeRecord, FlowRecord, RecordSink, WindowClose, WorkunitRecord};
use crate::dns::{DnsRecord, FeaturesRecord};
use crate::manifest::{Log, WindowManifest};
use crate::sign::KeyProvider;
use crate::store::{BlobRecord, ChunkRecord};
use crate::{mh, views};

pub const TABLES: [&str; 10] = [
    "packets",
    "segments",
    "events",
    "flows",
    "dns",
    "features",
    "http",
    "workunits",
    "chunks",
    "blobs",
];

/// Directory of kept bodies, inside the output directory.
pub const BODIES: &str = "bodies";

pub struct JsonlSink {
    packets: BufWriter<File>,
    segments: BufWriter<File>,
    events: BufWriter<File>,
    flows: BufWriter<File>,
    dns: BufWriter<File>,
    features: BufWriter<File>,
    http: BufWriter<File>,
    workunits: BufWriter<File>,
    chunks: BufWriter<File>,
    blobs: BufWriter<File>,
    log: Log,
    out: PathBuf,
    bodies: PathBuf,
    /// `http` rows not yet in `by-exchange/`; linked when the window closes,
    /// once their bodies are kept.
    unlinked: Vec<serde_json::Value>,
    /// Bodies being written, each to a temporary file until its hash is known.
    open: HashMap<BodyKey, (PathBuf, BufWriter<File>)>,
    next_tmp: u64,
    error: Option<io::Error>,
}

impl JsonlSink {
    /// Creates the table files in `dir`, which must exist, opens the
    /// manifest log there for appending, signed with `key`, and removes a
    /// `by-exchange/` left there by an earlier run.
    pub fn create(dir: &Path, key: Box<dyn KeyProvider>) -> io::Result<Self> {
        let stale = dir.join(views::BY_EXCHANGE);
        if stale.exists() {
            std::fs::remove_dir_all(stale)?;
        }
        let open = |name: &str| File::create(dir.join(format!("{name}.jsonl"))).map(BufWriter::new);
        Ok(JsonlSink {
            packets: open("packets")?,
            segments: open("segments")?,
            events: open("events")?,
            flows: open("flows")?,
            dns: open("dns")?,
            features: open("features")?,
            http: open("http")?,
            workunits: open("workunits")?,
            chunks: open("chunks")?,
            blobs: open("blobs")?,
            log: Log::open(dir, key)?,
            out: dir.to_owned(),
            bodies: dir.join(BODIES),
            unlinked: Vec::new(),
            open: HashMap::new(),
            next_tmp: 0,
            error: None,
        })
    }

    fn body_file(&mut self, key: &BodyKey) -> io::Result<&mut BufWriter<File>> {
        if !self.open.contains_key(key) {
            std::fs::create_dir_all(&self.bodies)?;
            let path = self.bodies.join(format!(".partial-{}", self.next_tmp));
            self.next_tmp += 1;
            let file = BufWriter::new(File::create(&path)?);
            self.open.insert(key.clone(), (path, file));
        }
        Ok(&mut self.open.get_mut(key).expect("just opened").1)
    }

    /// Moves a finished body to its name; an identical body may already be
    /// there.
    fn keep_body(&mut self, key: &BodyKey, hash: Option<&str>) -> io::Result<()> {
        let open = self.open.remove(key);
        let Some(hash) = hash.filter(|h| mh::parse(h).is_some()) else {
            if let Some((path, _)) = open {
                std::fs::remove_file(path)?;
            }
            return Ok(());
        };
        let target = self.bodies.join(hash);
        match open {
            Some((path, mut file)) => {
                file.flush()?;
                drop(file);
                if target.exists() {
                    std::fs::remove_file(path)?;
                } else {
                    std::fs::rename(path, target)?;
                }
            }
            None if !target.exists() => {
                std::fs::create_dir_all(&self.bodies)?;
                File::create(target)?;
            }
            None => {}
        }
        Ok(())
    }

    fn tables(&mut self) -> [&mut BufWriter<File>; 10] {
        [
            &mut self.packets,
            &mut self.segments,
            &mut self.events,
            &mut self.flows,
            &mut self.dns,
            &mut self.features,
            &mut self.http,
            &mut self.workunits,
            &mut self.chunks,
            &mut self.blobs,
        ]
    }

    /// Flushes every file and reports the first write error, if any.
    pub fn finish(mut self) -> io::Result<()> {
        for (_, (path, _)) in self.open.drain() {
            std::fs::remove_file(path)?;
        }
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        for w in self.tables() {
            w.flush()?;
        }
        Ok(())
    }
}

fn write_row<T: Serialize>(w: &mut BufWriter<File>, error: &mut Option<io::Error>, row: &T) {
    if error.is_some() {
        return;
    }
    let res = serde_json::to_writer(&mut *w, row)
        .map_err(io::Error::from)
        .and_then(|()| w.write_all(b"\n"));
    if let Err(e) = res {
        *error = Some(e);
    }
}

impl RecordSink for JsonlSink {
    fn packet(&mut self, rec: &PacketRecord) {
        write_row(&mut self.packets, &mut self.error, rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, _data: &[u8]) {
        write_row(&mut self.segments, &mut self.error, rec);
    }

    fn event(&mut self, rec: &EventRecord) {
        write_row(&mut self.events, &mut self.error, rec);
    }

    fn flow(&mut self, rec: &FlowRecord) {
        write_row(&mut self.flows, &mut self.error, rec);
    }

    fn dns(&mut self, rec: &DnsRecord) {
        write_row(&mut self.dns, &mut self.error, rec);
    }

    fn features(&mut self, rec: &FeaturesRecord) {
        write_row(&mut self.features, &mut self.error, rec);
    }

    fn exchange(&mut self, rec: &ExchangeRecord) {
        write_row(&mut self.http, &mut self.error, rec);
        match serde_json::to_value(rec) {
            Ok(row) => self.unlinked.push(row),
            Err(e) => {
                self.error.get_or_insert(e.into());
            }
        }
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        write_row(&mut self.workunits, &mut self.error, rec);
    }

    fn chunk(&mut self, rec: &ChunkRecord) {
        write_row(&mut self.chunks, &mut self.error, rec);
    }

    fn blob(&mut self, rec: &BlobRecord) {
        write_row(&mut self.blobs, &mut self.error, rec);
    }

    fn manifest(&mut self, rec: &WindowManifest) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.log.append(rec) {
            self.error = Some(e);
        }
    }

    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.body_file(key).and_then(|f| f.write_all(data)) {
            self.error = Some(e);
        }
    }

    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        if let Err(e) = self.keep_body(key, hash) {
            self.error.get_or_insert(e);
        }
    }

    fn window_closed(&mut self, _w: &WindowClose) {
        if self.error.is_some() {
            return;
        }
        let res = self.tables().into_iter().try_for_each(|w| w.flush());
        let res = res.and_then(|()| {
            for row in std::mem::take(&mut self.unlinked) {
                views::link_exchange(&self.out, &row)?;
            }
            Ok(())
        });
        if let Err(e) = res {
            self.error = Some(e);
        }
    }
}
