//! Diagnostics beside the pipeline (spec §14): [`StatsSink`] counts and logs
//! everything on its way to the real sink, and the snapshot triggers print
//! the registry on demand.
//!
//! [`StatsSink`] forwards every call unchanged, so wrapping a sink never
//! changes what it writes. Wall-clock time appears only here, in logs and
//! in the lag gauge.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, trace, warn};

use crate::assembler::{EventKind, EventRecord, PacketRecord, SegmentRecord};
use crate::decode::{
    BodyKey, Bucket, ExchangeRecord, FlowRecord, RecordSink, Span, WindowClose, WorkunitRecord,
};
use crate::flow::{Dir, FlowId};
use crate::source::CapturedPacket;
use crate::stats::{
    add, bucket_str, dir_str, fmt_ts, pct, HttpClass, Outcome, Registry, Snapshot, VerdictLabel, WindowStats,
    BUCKETS, DIRS,
};
use crate::store::{BlobRecord, ChunkRecord};
use crate::window::PacketRef;

/// What is known about an open Flow.
#[derive(Default)]
struct Seen {
    rows: u64,
    workunits: u64,
}

/// The request of a Workunit, from its `http` row, for the DEBUG line.
struct Request {
    dir: Dir,
    method: Option<String>,
    target: Option<String>,
}

/// Wraps a [`RecordSink`]: updates the [`Registry`], logs, and forwards.
pub struct StatsSink<'a> {
    inner: &'a mut dyn RecordSink,
    reg: Arc<Registry>,
    open: HashMap<FlowId, Seen>,
    requests: HashMap<String, Request>,
    /// The registry when the last window closed.
    prev: Snapshot,
}

impl<'a> StatsSink<'a> {
    pub fn new(inner: &'a mut dyn RecordSink, reg: Arc<Registry>) -> Self {
        StatsSink {
            inner,
            reg,
            open: HashMap::new(),
            requests: HashMap::new(),
            prev: Snapshot::default(),
        }
    }
}

impl RecordSink for StatsSink<'_> {
    fn packet(&mut self, rec: &PacketRecord) {
        let r = &self.reg;
        add(&r.packets_seen, 1);
        add(&r.bytes_seen, u64::from(rec.orig_len));
        match &rec.flow {
            None => {
                let other = VerdictLabel::Other as usize;
                add(&r.packets[other], 1);
                add(&r.bytes[other], u64::from(rec.orig_len));
            }
            Some(flow) if !self.open.contains_key(flow) => {
                add(&r.flows_new, 1);
                debug!(flow = %flow, "flow new");
                self.open.insert(flow.clone(), Seen::default());
            }
            Some(_) => {}
        }
        self.inner.packet(rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        trace!(
            flow = %rec.flow,
            dir = %dir_str(rec.dir),
            stream_off = rec.stream_off,
            len = rec.len,
            window = rec.window_start_ns,
            index = rec.index,
            pkt_off = rec.pkt_off,
            "segment"
        );
        self.inner.segment(rec, data);
    }

    fn event(&mut self, rec: &EventRecord) {
        let r = &self.reg;
        let dir = rec.dir.map(dir_str).unwrap_or("-");
        if rec.kind.is_gap() {
            add(&r.gaps, 1);
            add(&r.gap_bytes, rec.len);
        }
        if rec.kind == EventKind::RetransmitDiffers {
            add(&r.retransmits_differing, 1);
        }
        let kind = serde_json::to_value(rec.kind).ok();
        let kind = kind.as_ref().and_then(|k| k.as_str()).unwrap_or("?");
        if rec.kind == EventKind::GapBufferLimit {
            warn!(flow = %rec.flow, dir = %dir, len = rec.len, "Flow hit the reassembly buffer cap; bytes left as a gap");
        } else {
            debug!(flow = %rec.flow, dir = %dir, kind = %kind, stream_off = rec.stream_off, len = rec.len, "event");
        }
        self.inner.event(rec);
    }

    fn flow(&mut self, rec: &FlowRecord) {
        let r = &self.reg;
        let s = &rec.slice;
        let label = VerdictLabel::of(s.kind, rec.verdict) as usize;
        let (o, p) = (&s.orig_stats, &s.resp_stats);
        add(&r.packets[label], o.packets + p.packets);
        add(&r.bytes[label], o.wire_bytes + p.wire_bytes);
        add(&r.retransmit_bytes, o.retransmit_bytes + p.retransmit_bytes);
        add(
            &r.retransmit_differing_bytes,
            o.retransmit_diff_bytes + p.retransmit_diff_bytes,
        );
        for (dir, b) in DIRS.into_iter().zip([&rec.orig_bytes, &rec.resp_bytes]) {
            for bucket in BUCKETS {
                r.add_accounted(bucket, dir, b.get(bucket));
            }
        }
        let seen = self.open.entry(s.flow.clone()).or_default();
        if seen.rows == 0 && s.mid_stream_start {
            add(&r.mid_stream_starts, 1);
        }
        seen.rows += 1;
        if s.ended {
            let seen = self.open.remove(&s.flow).unwrap_or_default();
            add(&r.flows[label], 1);
            if seen.workunits > 0 {
                add(&r.flows_with_workunit, 1);
            }
            debug!(
                flow = %s.flow,
                verdict = %VerdictLabel::ALL[label].as_str(),
                workunits = seen.workunits,
                mid_stream_start = s.mid_stream_start,
                "flow closed"
            );
        }
        self.inner.flow(rec);
    }

    fn exchange(&mut self, rec: &ExchangeRecord) {
        if let (Some(id), Some(req)) = (&rec.workunit_id, &rec.request) {
            self.requests.insert(
                id.clone(),
                Request {
                    dir: req.dir,
                    method: req.method.clone(),
                    target: req.target.clone(),
                },
            );
        }
        self.inner.exchange(rec);
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        let outcome = rec.outcome();
        self.reg
            .add_workunit(rec.protocol, outcome, HttpClass::of(rec.status));
        if let Some(seen) = self.open.get_mut(&rec.flow) {
            seen.workunits += 1;
        }
        let req = self.requests.remove(&rec.workunit_id);
        debug!(
            workunit_id = %rec.workunit_id,
            flow = %rec.flow,
            protocol = %rec.protocol,
            dir = %req.as_ref().map_or("-", |r| dir_str(r.dir)),
            method = %req.as_ref().and_then(|r| r.method.as_deref()).unwrap_or("-"),
            path = %req.as_ref().and_then(|r| r.target.as_deref()).unwrap_or(rec.endpoint),
            model = %rec.model.as_deref().unwrap_or("-"),
            status = rec.status,
            stream = rec.stream,
            request_bytes = rec.request_body_len,
            response_bytes = rec.response_body_len,
            outcome = %outcome.as_str(),
            "workunit"
        );
        self.inner.workunit(rec);
    }

    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        self.inner.body_data(key, data);
    }

    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        self.inner.body_end(key, hash);
    }

    fn captured(&mut self, pkt: &CapturedPacket, at: PacketRef) {
        self.inner.captured(pkt, at);
    }

    fn spans(&mut self, flow: &FlowId, dir: Dir, spans: &[Span]) {
        self.inner.spans(flow, dir, spans);
    }

    fn chunk(&mut self, rec: &ChunkRecord) {
        debug!(
            link = %rec.link,
            window = %fmt_ts(rec.window_start_ns),
            packets = rec.packets,
            truncated = rec.truncated_packets,
            key = %rec.key,
            "chunk stored"
        );
        self.inner.chunk(rec);
    }

    fn blob(&mut self, rec: &BlobRecord) {
        self.inner.blob(rec);
    }

    fn window_closed(&mut self, w: &WindowClose) {
        let r = &self.reg;
        if let Some(total) = w.capture_drops {
            let before = r
                .capture_drops
                .fetch_max(total, std::sync::atomic::Ordering::Relaxed);
            if total > before {
                warn!(dropped = total - before, total, "capture dropped packets");
            }
        }
        let now = r.snapshot();
        let ws = WindowStats::between(&self.prev, &now, w.window_start_ns, w.window_ns);
        let end_ns = w.window_start_ns.saturating_add(w.window_ns);
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let lag_s = (wall_ns as f64 - end_ns as f64) / 1e9;
        info!(
            window = %fmt_ts(w.window_start_ns),
            packets = ws.packets,
            bytes = ws.bytes,
            flows_new = ws.flows_new,
            flows_active = ws.flows_active,
            flows_closed = ws.flows_closed,
            workunits_ok = ws.workunits_ok,
            workunits_errored = ws.workunits_errored,
            workunits_incomplete = ws.workunits_incomplete,
            workunit_bytes = %pct(ws.workunit_bytes, ws.accounted_bytes),
            workunit_flows = %pct(now.flows_with_workunit, now.flows_closed()),
            gaps = ws.gaps,
            pps = %format_args!("{:.1}", ws.pps()),
            mbit_s = %format_args!("{:.3}", ws.mbit_s()),
            "window closed"
        );
        r.set_window(ws, lag_s);
        self.prev = now;
        self.inner.window_closed(w);
    }
}

/// The INFO summary at the end of a run.
pub fn log_summary(s: &Snapshot, out: &Path) {
    let total = s.accounted_total();
    info!(
        packets = s.packets_seen,
        bytes = s.bytes_seen,
        windows = s.windows_closed,
        flows = s.flows_closed(),
        flows_with_workunit = s.flows_with_workunit,
        workunits_ok = s.workunits_with(Outcome::Ok),
        workunits_errored = s.workunits_with(Outcome::Errored),
        workunits_incomplete = s.workunits_with(Outcome::Incomplete),
        workunit_bytes = %pct(s.bucket_bytes(Bucket::Workunit), total),
        workunit_flows = %pct(s.flows_with_workunit, s.flows_closed()),
        unexplained_bytes = %pct(s.bucket_bytes(Bucket::Unexplained), total),
        gaps = s.gaps,
        capture_drops = s.capture_drops,
        out = %out.display(),
        "run finished"
    );
    for b in BUCKETS {
        debug!(bucket = %bucket_str(b), bytes = s.bucket_bytes(b), "accounted bytes");
    }
}

/// Prints the snapshot table to stdout; as one JSON line under `json`.
pub fn print_snapshot(reg: &Registry, json: bool) {
    use std::io::Write;
    let table = crate::stats::render_table(&reg.snapshot());
    let mut out = std::io::stdout().lock();
    let _ = if json {
        writeln!(out, "{}", serde_json::json!({ "snapshot": table }))
    } else {
        write!(out, "{table}")
    };
    let _ = out.flush();
}

/// Snapshot triggers: `SIGUSR1` always, and `s` or Enter when stdin is a
/// terminal. Keypresses are read without waiting for a line, so stdin's
/// terminal mode is changed; [`Triggers`] restores it when dropped, and on
/// SIGINT/SIGTERM before the default action runs.
///
/// With a `stop_pid` (dumpcap, for `ring`), the first SIGINT/SIGTERM does not
/// kill the Collector: it is forwarded to dumpcap as SIGINT, which closes its
/// last ring file and exits; the packet source then ends and the run finishes
/// normally (store, tables, summary). A second signal takes the default action.
#[cfg(unix)]
pub mod triggers {
    use std::io::{IsTerminal, Read};
    use std::sync::{Arc, Mutex};

    use signal_hook::consts::{SIGINT, SIGTERM, SIGUSR1};
    use signal_hook::iterator::Signals;

    use super::print_snapshot;
    use crate::stats::Registry;

    /// The terminal settings to put back.
    type Saved = Arc<Mutex<Option<libc::termios>>>;

    pub struct Triggers {
        saved: Saved,
        /// Whether keypresses trigger a snapshot.
        pub keys: bool,
    }

    fn restore(saved: &Saved) {
        if let Some(t) = saved.lock().unwrap_or_else(|e| e.into_inner()).take() {
            // SAFETY: fd 0 and a termios read from it by tcgetattr.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) };
        }
    }

    /// Turns off canonical mode and echo on stdin, keeping signals (Ctrl-C).
    fn raw_keys() -> Option<libc::termios> {
        // SAFETY: tcgetattr fills the struct; zeroed is a valid termios.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
                return None;
            }
            let saved = t;
            t.c_lflag &= !(libc::ICANON | libc::ECHO);
            t.c_cc[libc::VMIN] = 1;
            t.c_cc[libc::VTIME] = 0;
            (libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) == 0).then_some(saved)
        }
    }

    pub fn spawn(reg: Arc<Registry>, json: bool, stop_pid: Option<u32>) -> std::io::Result<Triggers> {
        let saved: Saved = Arc::new(Mutex::new(None));
        let keys = std::io::stdin().is_terminal();
        if keys {
            *saved.lock().unwrap_or_else(|e| e.into_inner()) = raw_keys();
        }
        let mut sigs = vec![SIGUSR1];
        if keys || stop_pid.is_some() {
            sigs.extend([SIGINT, SIGTERM]);
        }
        let mut signals = Signals::new(&sigs)?;
        let (r, s) = (reg.clone(), saved.clone());
        std::thread::Builder::new()
            .name("snapshot-signal".into())
            .spawn(move || {
                let mut stopping = false;
                for sig in signals.forever() {
                    if sig == SIGUSR1 {
                        print_snapshot(&r, json);
                    } else if let Some(pid) = stop_pid.filter(|_| !stopping) {
                        stopping = true;
                        tracing::info!(signal = sig, "stopping: asking dumpcap to close its last file");
                        // SAFETY: plain kill(2) on dumpcap's pid; an error just means it already exited.
                        unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) };
                    } else {
                        restore(&s);
                        let _ = signal_hook::low_level::emulate_default_handler(sig);
                    }
                }
            })?;
        if keys {
            std::thread::Builder::new()
                .name("snapshot-keys".into())
                .spawn(move || {
                    let mut stdin = std::io::stdin().lock();
                    let mut b = [0u8; 1];
                    while let Ok(1) = stdin.read(&mut b) {
                        if matches!(b[0], b's' | b'S' | b'\n' | b'\r') {
                            print_snapshot(&reg, json);
                        }
                    }
                })?;
        }
        Ok(Triggers { saved, keys })
    }

    impl Drop for Triggers {
        fn drop(&mut self) {
            restore(&self.saved);
        }
    }
}
