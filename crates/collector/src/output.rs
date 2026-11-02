//! JSON Lines output, one file per table.
//!
//! `packets`, `segments` (stream offset → packet), `events` (gaps,
//! anomalies), `flows` (one row per Flow per Slice, with verdict and byte
//! accounting), `http` (one row per HTTP exchange) and `workunits` (Request
//! Workunits). Rows are written in a fixed order with fixed field order, so
//! the files are byte-identical across runs.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::assembler::{EventRecord, PacketRecord, SegmentRecord};
use crate::decode::{ExchangeRecord, FlowRecord, RecordSink, WorkunitRecord};

pub const TABLES: [&str; 6] = ["packets", "segments", "events", "flows", "http", "workunits"];

pub struct JsonlSink {
    packets: BufWriter<File>,
    segments: BufWriter<File>,
    events: BufWriter<File>,
    flows: BufWriter<File>,
    http: BufWriter<File>,
    workunits: BufWriter<File>,
    error: Option<io::Error>,
}

impl JsonlSink {
    /// Creates the table files in `dir`, which must exist.
    pub fn create(dir: &Path) -> io::Result<Self> {
        let open = |name: &str| File::create(dir.join(format!("{name}.jsonl"))).map(BufWriter::new);
        Ok(JsonlSink {
            packets: open("packets")?,
            segments: open("segments")?,
            events: open("events")?,
            flows: open("flows")?,
            http: open("http")?,
            workunits: open("workunits")?,
            error: None,
        })
    }

    /// Flushes every file and reports the first write error, if any.
    pub fn finish(mut self) -> io::Result<()> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        for w in [
            &mut self.packets,
            &mut self.segments,
            &mut self.events,
            &mut self.flows,
            &mut self.http,
            &mut self.workunits,
        ] {
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

    fn exchange(&mut self, rec: &ExchangeRecord) {
        write_row(&mut self.http, &mut self.error, rec);
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        write_row(&mut self.workunits, &mut self.error, rec);
    }
}
