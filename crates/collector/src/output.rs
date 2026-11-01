//! JSON Lines output, one file per table.
//!
//! Stage 1 writes `packets.jsonl`, `segments.jsonl`, `events.jsonl` and
//! `flows.jsonl` (one row per Flow per Slice). Rows are written in a fixed
//! order with fixed field order, so the files are byte-identical across runs.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::assembler::{EventRecord, FlowSink, PacketRecord, SegmentRecord, SliceRecord};

pub const TABLES: [&str; 4] = ["packets", "segments", "events", "flows"];

pub struct JsonlSink {
    packets: BufWriter<File>,
    segments: BufWriter<File>,
    events: BufWriter<File>,
    flows: BufWriter<File>,
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

impl FlowSink for JsonlSink {
    fn packet(&mut self, rec: &PacketRecord) {
        write_row(&mut self.packets, &mut self.error, rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, _data: &[u8]) {
        write_row(&mut self.segments, &mut self.error, rec);
    }

    fn event(&mut self, rec: &EventRecord) {
        write_row(&mut self.events, &mut self.error, rec);
    }

    fn slice(&mut self, rec: &SliceRecord) {
        write_row(&mut self.flows, &mut self.error, rec);
    }
}
