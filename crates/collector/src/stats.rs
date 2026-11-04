//! The counter registry (spec §14): one set of counters, updated by the
//! pipeline through [`StatsSink`](crate::observe::StatsSink) and read by
//! three views: the INFO line per closed window, the on-demand snapshot
//! table ([`render_table`]) and Prometheus `/metrics` ([`render_prometheus`],
//! [`serve_metrics`]).
//!
//! Counters are atomics, so the views read them from other threads while
//! the pipeline runs. Nothing here feeds back into the pipeline: stats are
//! diagnostics, never part of the deterministic outputs.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::decode::{Bucket, Verdict};
use crate::flow::{Dir, FlowKind};

/// Prefix of every exported metric.
pub const PREFIX: &str = "ts_collector_";

/// The `verdict` label: the [`Verdict`] of TCP Flows, `udp` for UDP Flows,
/// and `other` for other IP protocols, packets with no Flow and Flows with
/// no payload yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictLabel {
    Http1,
    Http2,
    Tls,
    Grpc,
    Opaque,
    Udp,
    Other,
}

impl VerdictLabel {
    pub const ALL: [VerdictLabel; 7] = [
        VerdictLabel::Http1,
        VerdictLabel::Http2,
        VerdictLabel::Tls,
        VerdictLabel::Grpc,
        VerdictLabel::Opaque,
        VerdictLabel::Udp,
        VerdictLabel::Other,
    ];

    pub fn of(kind: FlowKind, verdict: Option<Verdict>) -> Self {
        match (kind, verdict) {
            (FlowKind::Udp, _) => VerdictLabel::Udp,
            (FlowKind::Ip(_), _) | (FlowKind::Tcp, None) => VerdictLabel::Other,
            (FlowKind::Tcp, Some(Verdict::Http1)) => VerdictLabel::Http1,
            (FlowKind::Tcp, Some(Verdict::Http2)) => VerdictLabel::Http2,
            (FlowKind::Tcp, Some(Verdict::Tls)) => VerdictLabel::Tls,
            (FlowKind::Tcp, Some(Verdict::Grpc)) => VerdictLabel::Grpc,
            (FlowKind::Tcp, Some(Verdict::Opaque)) => VerdictLabel::Opaque,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VerdictLabel::Http1 => "http1",
            VerdictLabel::Http2 => "http2",
            VerdictLabel::Tls => "tls",
            VerdictLabel::Grpc => "grpc",
            VerdictLabel::Opaque => "opaque",
            VerdictLabel::Udp => "udp",
            VerdictLabel::Other => "other",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

pub const BUCKETS: [Bucket; 5] = [
    Bucket::Workunit,
    Bucket::HttpOther,
    Bucket::Framing,
    Bucket::Unexplained,
    Bucket::Gap,
];

pub fn bucket_str(b: Bucket) -> &'static str {
    match b {
        Bucket::Workunit => "workunit",
        Bucket::HttpOther => "http_other",
        Bucket::Framing => "framing",
        Bucket::Unexplained => "unexplained",
        Bucket::Gap => "gap",
    }
}

fn bucket_idx(b: Bucket) -> usize {
    BUCKETS.iter().position(|x| *x == b).expect("listed")
}

pub const DIRS: [Dir; 2] = [Dir::Orig, Dir::Resp];

pub fn dir_str(d: Dir) -> &'static str {
    match d {
        Dir::Orig => "orig",
        Dir::Resp => "resp",
    }
}

/// How a Request Workunit ended (the `outcome` label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Request and response fully parsed, no gap.
    Ok,
    /// A gap, or the Flow ended mid-message.
    Incomplete,
    /// The response could not be read as OpenAI JSON.
    Errored,
}

impl Outcome {
    pub const ALL: [Outcome; 3] = [Outcome::Ok, Outcome::Incomplete, Outcome::Errored];

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Incomplete => "incomplete",
            Outcome::Errored => "errored",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

/// The `http_class` label, from the response status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpClass {
    S2xx,
    S4xx,
    S5xx,
    None,
}

impl HttpClass {
    pub const ALL: [HttpClass; 4] = [HttpClass::S2xx, HttpClass::S4xx, HttpClass::S5xx, HttpClass::None];

    /// `none` for no status, and for 1xx and 3xx, which never end a Workunit.
    pub fn of(status: u16) -> Self {
        match status {
            200..=299 => HttpClass::S2xx,
            400..=499 => HttpClass::S4xx,
            500..=599 => HttpClass::S5xx,
            _ => HttpClass::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            HttpClass::S2xx => "2xx",
            HttpClass::S4xx => "4xx",
            HttpClass::S5xx => "5xx",
            HttpClass::None => "none",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

type Labeled<const N: usize> = [AtomicU64; N];

fn zeros<const N: usize>() -> Labeled<N> {
    std::array::from_fn(|_| AtomicU64::new(0))
}

fn load<const N: usize>(a: &Labeled<N>) -> [u64; N] {
    std::array::from_fn(|i| a[i].load(Ordering::Relaxed))
}

/// Object kinds in the store (spec §8), the `kind` label.
pub const STORE_KINDS: [&str; 3] = ["chunk", "pack", "index"];

/// The counters. Shared as `Arc<Registry>` between the pipeline and the
/// views.
pub struct Registry {
    pub(crate) packets_seen: AtomicU64,
    pub(crate) bytes_seen: AtomicU64,
    pub(crate) packets: Labeled<7>,
    pub(crate) bytes: Labeled<7>,
    pub(crate) flows: Labeled<7>,
    pub(crate) flows_new: AtomicU64,
    pub(crate) flows_with_workunit: AtomicU64,
    accounted: [Labeled<2>; 5],
    /// `[outcome][http_class]` by Wire Protocol id.
    workunits: Mutex<BTreeMap<&'static str, [[u64; 4]; 3]>>,
    pub(crate) gaps: AtomicU64,
    pub(crate) gap_bytes: AtomicU64,
    pub(crate) retransmit_bytes: AtomicU64,
    pub(crate) retransmit_differing_bytes: AtomicU64,
    pub(crate) retransmits_differing: AtomicU64,
    pub(crate) mid_stream_starts: AtomicU64,
    pub(crate) capture_drops: AtomicU64,
    pub(crate) windows_closed: AtomicU64,
    /// Packets stored `[full, truncated]` by the Capture Rate cut.
    pub(crate) capture_packets: Labeled<2>,
    pub(crate) capture_kept_bytes: AtomicU64,
    pub(crate) capture_truncated_bytes: AtomicU64,
    /// Objects written and their bytes, by [`STORE_KINDS`].
    pub(crate) store_objects: Labeled<3>,
    pub(crate) store_bytes: Labeled<3>,
    pub(crate) store_existing: AtomicU64,
    /// Objects the uploader put to the remote store, their bytes, and those
    /// it found already there (spec §8, the spool).
    pub(crate) uploads: AtomicU64,
    pub(crate) upload_bytes: AtomicU64,
    pub(crate) uploads_existing: AtomicU64,
    /// Upload attempts that failed and are retried.
    pub(crate) upload_retries: AtomicU64,
    /// Objects and bytes in the spool, waiting to be uploaded.
    spool_objects: AtomicU64,
    spool_bytes: AtomicU64,
    /// `f64` bits.
    last_window_lag: AtomicU64,
    last_window: Mutex<Option<WindowStats>>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            packets_seen: AtomicU64::new(0),
            bytes_seen: AtomicU64::new(0),
            packets: zeros(),
            bytes: zeros(),
            flows: zeros(),
            flows_new: AtomicU64::new(0),
            flows_with_workunit: AtomicU64::new(0),
            accounted: std::array::from_fn(|_| zeros()),
            // Built-in protocols are listed from the start, at zero.
            workunits: Mutex::new(
                crate::wire::BUILTIN
                    .iter()
                    .map(|p| (p.id(), [[0; 4]; 3]))
                    .collect(),
            ),
            gaps: AtomicU64::new(0),
            gap_bytes: AtomicU64::new(0),
            retransmit_bytes: AtomicU64::new(0),
            retransmit_differing_bytes: AtomicU64::new(0),
            retransmits_differing: AtomicU64::new(0),
            mid_stream_starts: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
            windows_closed: AtomicU64::new(0),
            capture_packets: zeros(),
            capture_kept_bytes: AtomicU64::new(0),
            capture_truncated_bytes: AtomicU64::new(0),
            store_objects: zeros(),
            store_bytes: zeros(),
            store_existing: AtomicU64::new(0),
            uploads: AtomicU64::new(0),
            upload_bytes: AtomicU64::new(0),
            uploads_existing: AtomicU64::new(0),
            upload_retries: AtomicU64::new(0),
            spool_objects: AtomicU64::new(0),
            spool_bytes: AtomicU64::new(0),
            last_window_lag: AtomicU64::new(0f64.to_bits()),
            last_window: Mutex::new(None),
        }
    }
}

pub(crate) fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Registry::default())
    }

    pub(crate) fn add_accounted(&self, bucket: Bucket, dir: Dir, n: u64) {
        add(&self.accounted[bucket_idx(bucket)][dir.idx()], n);
    }

    pub(crate) fn add_workunit(&self, protocol: &'static str, outcome: Outcome, class: HttpClass) {
        let mut w = self.workunits.lock().unwrap_or_else(|e| e.into_inner());
        w.entry(protocol).or_insert([[0; 4]; 3])[outcome.idx()][class.idx()] += 1;
    }

    pub(crate) fn set_spool(&self, objects: u64, bytes: u64) {
        self.spool_objects.store(objects, Ordering::Relaxed);
        self.spool_bytes.store(bytes, Ordering::Relaxed);
    }

    pub(crate) fn set_window(&self, w: WindowStats, lag_s: f64) {
        add(&self.windows_closed, 1);
        self.last_window_lag.store(lag_s.to_bits(), Ordering::Relaxed);
        *self.last_window.lock().unwrap_or_else(|e| e.into_inner()) = Some(w);
    }

    /// The counters as they are now.
    pub fn snapshot(&self) -> Snapshot {
        let flows = load(&self.flows);
        let closed: u64 = flows.iter().sum();
        Snapshot {
            packets_seen: self.packets_seen.load(Ordering::Relaxed),
            bytes_seen: self.bytes_seen.load(Ordering::Relaxed),
            packets: load(&self.packets),
            bytes: load(&self.bytes),
            flows,
            flows_active: self.flows_new.load(Ordering::Relaxed).saturating_sub(closed),
            flows_new: self.flows_new.load(Ordering::Relaxed),
            flows_with_workunit: self.flows_with_workunit.load(Ordering::Relaxed),
            accounted: std::array::from_fn(|b| load(&self.accounted[b])),
            workunits_by_protocol: self.workunits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            gaps: self.gaps.load(Ordering::Relaxed),
            gap_bytes: self.gap_bytes.load(Ordering::Relaxed),
            retransmit_bytes: self.retransmit_bytes.load(Ordering::Relaxed),
            retransmit_differing_bytes: self.retransmit_differing_bytes.load(Ordering::Relaxed),
            retransmits_differing: self.retransmits_differing.load(Ordering::Relaxed),
            mid_stream_starts: self.mid_stream_starts.load(Ordering::Relaxed),
            capture_drops: self.capture_drops.load(Ordering::Relaxed),
            windows_closed: self.windows_closed.load(Ordering::Relaxed),
            capture_packets: load(&self.capture_packets),
            capture_kept_bytes: self.capture_kept_bytes.load(Ordering::Relaxed),
            capture_truncated_bytes: self.capture_truncated_bytes.load(Ordering::Relaxed),
            store_objects: load(&self.store_objects),
            store_bytes: load(&self.store_bytes),
            store_existing: self.store_existing.load(Ordering::Relaxed),
            uploads: self.uploads.load(Ordering::Relaxed),
            upload_bytes: self.upload_bytes.load(Ordering::Relaxed),
            uploads_existing: self.uploads_existing.load(Ordering::Relaxed),
            upload_retries: self.upload_retries.load(Ordering::Relaxed),
            spool_objects: self.spool_objects.load(Ordering::Relaxed),
            spool_bytes: self.spool_bytes.load(Ordering::Relaxed),
            last_window_lag_s: f64::from_bits(self.last_window_lag.load(Ordering::Relaxed)),
            last_window: self.last_window.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        }
    }
}

/// A copy of every counter at one moment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    /// Packets and wire bytes as they arrive; the per-window rates use these.
    pub packets_seen: u64,
    pub bytes_seen: u64,
    /// By [`VerdictLabel`], counted as each Flow row (Flow per Slice) is
    /// written, plus packets with no Flow under `other`. Equal to
    /// `packets_seen`/`bytes_seen` at the end of a run.
    pub packets: [u64; 7],
    pub bytes: [u64; 7],
    /// Closed Flows by final verdict.
    pub flows: [u64; 7],
    pub flows_new: u64,
    pub flows_active: u64,
    /// Closed Flows that carried at least one Request Workunit.
    pub flows_with_workunit: u64,
    /// `[bucket][dir]`, in [`BUCKETS`] and [`DIRS`] order.
    pub accounted: [[u64; 2]; 5],
    /// `[outcome][http_class]`, in [`Outcome::ALL`] and [`HttpClass::ALL`]
    /// order, by Wire Protocol id.
    pub workunits_by_protocol: BTreeMap<&'static str, [[u64; 4]; 3]>,
    pub gaps: u64,
    pub gap_bytes: u64,
    pub retransmit_bytes: u64,
    pub retransmit_differing_bytes: u64,
    pub retransmits_differing: u64,
    pub mid_stream_starts: u64,
    pub capture_drops: u64,
    pub windows_closed: u64,
    /// Packets written to L0 chunks `[full, truncated]` (spec §7).
    pub capture_packets: [u64; 2],
    /// Captured bytes written to chunks, and captured bytes cut off.
    pub capture_kept_bytes: u64,
    pub capture_truncated_bytes: u64,
    /// Objects and bytes written, by [`STORE_KINDS`].
    pub store_objects: [u64; 3],
    pub store_bytes: [u64; 3],
    /// Puts that found the same object already there.
    pub store_existing: u64,
    /// The uploader's puts to the remote store, their bytes, and those that
    /// found the same object already there.
    pub uploads: u64,
    pub upload_bytes: u64,
    pub uploads_existing: u64,
    /// Upload attempts that failed and are retried.
    pub upload_retries: u64,
    /// Objects and bytes in the spool, waiting to be uploaded.
    pub spool_objects: u64,
    pub spool_bytes: u64,
    pub last_window_lag_s: f64,
    pub last_window: Option<WindowStats>,
}

impl Snapshot {
    pub fn packets_by(&self, v: VerdictLabel) -> u64 {
        self.packets[v.idx()]
    }

    pub fn bytes_by(&self, v: VerdictLabel) -> u64 {
        self.bytes[v.idx()]
    }

    pub fn flows_by(&self, v: VerdictLabel) -> u64 {
        self.flows[v.idx()]
    }

    pub fn flows_closed(&self) -> u64 {
        self.flows.iter().sum()
    }

    pub fn accounted_by(&self, b: Bucket, d: Dir) -> u64 {
        self.accounted[bucket_idx(b)][d.idx()]
    }

    /// Bytes in one bucket, both directions.
    pub fn bucket_bytes(&self, b: Bucket) -> u64 {
        self.accounted[bucket_idx(b)].iter().sum()
    }

    pub fn accounted_total(&self) -> u64 {
        self.accounted.iter().flatten().sum()
    }

    /// `[outcome][http_class]` over every protocol.
    pub fn workunits(&self) -> [[u64; 4]; 3] {
        let mut t = [[0; 4]; 3];
        for w in self.workunits_by_protocol.values() {
            for (o, row) in w.iter().enumerate() {
                for (c, n) in row.iter().enumerate() {
                    t[o][c] += n;
                }
            }
        }
        t
    }

    pub fn workunits_by(&self, o: Outcome, c: HttpClass) -> u64 {
        self.workunits()[o.idx()][c.idx()]
    }

    pub fn workunits_with(&self, o: Outcome) -> u64 {
        self.workunits()[o.idx()].iter().sum()
    }

    pub fn workunits_total(&self) -> u64 {
        self.workunits().iter().flatten().sum()
    }
}

/// What one closed window added, for the INFO line and the snapshot's rates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WindowStats {
    pub window_start_ns: u64,
    pub window_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub flows_new: u64,
    pub flows_active: u64,
    pub flows_closed: u64,
    pub workunits_ok: u64,
    pub workunits_errored: u64,
    pub workunits_incomplete: u64,
    pub workunit_bytes: u64,
    pub accounted_bytes: u64,
    pub flows_with_workunit: u64,
    pub gaps: u64,
}

impl WindowStats {
    /// The change from `prev` to `now`, over a window of `window_ns`.
    pub fn between(prev: &Snapshot, now: &Snapshot, window_start_ns: u64, window_ns: u64) -> Self {
        WindowStats {
            window_start_ns,
            window_ns,
            packets: now.packets_seen - prev.packets_seen,
            bytes: now.bytes_seen - prev.bytes_seen,
            flows_new: now.flows_new - prev.flows_new,
            flows_active: now.flows_active,
            flows_closed: now.flows_closed() - prev.flows_closed(),
            workunits_ok: now.workunits_with(Outcome::Ok) - prev.workunits_with(Outcome::Ok),
            workunits_errored: now.workunits_with(Outcome::Errored) - prev.workunits_with(Outcome::Errored),
            workunits_incomplete: now.workunits_with(Outcome::Incomplete)
                - prev.workunits_with(Outcome::Incomplete),
            workunit_bytes: now.bucket_bytes(Bucket::Workunit) - prev.bucket_bytes(Bucket::Workunit),
            accounted_bytes: now.accounted_total() - prev.accounted_total(),
            flows_with_workunit: now.flows_with_workunit - prev.flows_with_workunit,
            gaps: now.gaps - prev.gaps,
        }
    }

    fn secs(&self) -> f64 {
        self.window_ns as f64 / 1e9
    }

    /// Packets per second of capture time.
    pub fn pps(&self) -> f64 {
        self.packets as f64 / self.secs()
    }

    pub fn mbit_s(&self) -> f64 {
        self.bytes as f64 * 8.0 / 1e6 / self.secs()
    }
}

/// `part / whole` as a percentage with one decimal, or `-` when `whole` is 0.
pub fn pct(part: u64, whole: u64) -> String {
    if whole == 0 {
        "-".into()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

/// The UTC calendar date (year, month, day) of a capture time.
pub fn civil_date(ns: u64) -> (i64, i64, i64) {
    let days = ns / 1_000_000_000 / 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// A capture time (ns since the Unix epoch) as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn fmt_ts(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let ms = (ns / 1_000_000) % 1000;
    let rem = secs % 86_400;
    let (y, m, d) = civil_date(ns);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// The on-demand snapshot: cumulative totals, then the last window's rates.
pub fn render_table(s: &Snapshot) -> String {
    let mut t = String::new();
    let row = |t: &mut String, k: &str, v: String| {
        let _ = writeln!(t, "  {k:<28} {v}");
    };
    let _ = writeln!(t, "TokenSpectra Collector snapshot");
    let _ = writeln!(t, "totals");
    row(&mut t, "packets", s.packets_seen.to_string());
    row(&mut t, "bytes", s.bytes_seen.to_string());
    for v in VerdictLabel::ALL {
        let (p, b) = (s.packets_by(v), s.bytes_by(v));
        if p > 0 {
            row(
                &mut t,
                &format!("  {}", v.as_str()),
                format!("{p} packets, {b} bytes"),
            );
        }
    }
    row(
        &mut t,
        "flows",
        format!(
            "{} new, {} active, {} closed",
            s.flows_new,
            s.flows_active,
            s.flows_closed()
        ),
    );
    for v in VerdictLabel::ALL {
        if s.flows_by(v) > 0 {
            row(&mut t, &format!("  {}", v.as_str()), s.flows_by(v).to_string());
        }
    }
    row(
        &mut t,
        "flows with workunits",
        format!(
            "{} ({} of closed Flows)",
            s.flows_with_workunit,
            pct(s.flows_with_workunit, s.flows_closed())
        ),
    );
    row(
        &mut t,
        "request workunits",
        format!(
            "{} ok, {} errored, {} incomplete",
            s.workunits_with(Outcome::Ok),
            s.workunits_with(Outcome::Errored),
            s.workunits_with(Outcome::Incomplete)
        ),
    );
    let total = s.accounted_total();
    row(&mut t, "accounted bytes", total.to_string());
    for b in BUCKETS {
        let n = s.bucket_bytes(b);
        row(
            &mut t,
            &format!("  {}", bucket_str(b)),
            format!("{n} ({})", pct(n, total)),
        );
    }
    row(&mut t, "gaps", format!("{} ({} bytes)", s.gaps, s.gap_bytes));
    row(
        &mut t,
        "retransmitted bytes",
        format!(
            "{} ({} differing)",
            s.retransmit_bytes, s.retransmit_differing_bytes
        ),
    );
    row(&mut t, "mid-stream starts", s.mid_stream_starts.to_string());
    row(&mut t, "capture drops", s.capture_drops.to_string());
    row(&mut t, "windows closed", s.windows_closed.to_string());
    let [full, truncated] = s.capture_packets;
    row(
        &mut t,
        "capture rate cut",
        format!(
            "{full} packets full, {truncated} truncated; {} bytes kept, {} cut",
            s.capture_kept_bytes, s.capture_truncated_bytes
        ),
    );
    for (i, k) in STORE_KINDS.iter().enumerate() {
        row(
            &mut t,
            &format!("store {k} objects"),
            format!("{} ({} bytes)", s.store_objects[i], s.store_bytes[i]),
        );
    }
    row(
        &mut t,
        "store objects already there",
        s.store_existing.to_string(),
    );
    if s.uploads + s.uploads_existing + s.upload_retries + s.spool_objects > 0 {
        row(
            &mut t,
            "uploaded",
            format!(
                "{} objects ({} bytes), {} already there, {} retries",
                s.uploads, s.upload_bytes, s.uploads_existing, s.upload_retries
            ),
        );
        row(
            &mut t,
            "spooled",
            format!("{} objects ({} bytes)", s.spool_objects, s.spool_bytes),
        );
    }
    match &s.last_window {
        None => {
            let _ = writeln!(t, "last window: none closed yet");
        }
        Some(w) => {
            let _ = writeln!(t, "last window ({}, {}s)", fmt_ts(w.window_start_ns), w.secs());
            row(&mut t, "packets", format!("{} ({:.1}/s)", w.packets, w.pps()));
            row(&mut t, "bytes", format!("{} ({:.3} Mbit/s)", w.bytes, w.mbit_s()));
            row(
                &mut t,
                "flows",
                format!(
                    "{} new, {} active, {} closed",
                    w.flows_new, w.flows_active, w.flows_closed
                ),
            );
            row(
                &mut t,
                "request workunits",
                format!(
                    "{} ok, {} errored, {} incomplete",
                    w.workunits_ok, w.workunits_errored, w.workunits_incomplete
                ),
            );
            row(&mut t, "workunit bytes", pct(w.workunit_bytes, w.accounted_bytes));
            row(&mut t, "gaps", w.gaps.to_string());
            row(&mut t, "lag", format!("{:.1}s", s.last_window_lag_s));
        }
    }
    t
}

/// Prometheus text exposition format, version 0.0.4. Raw counters and
/// gauges only: ratios are left to PromQL.
pub fn render_prometheus(s: &Snapshot) -> String {
    let mut p = Prom(String::new());
    for (name, help, vals) in [
        (
            "packets_total",
            "Packets, by the verdict of their Flow.",
            &s.packets,
        ),
        (
            "bytes_total",
            "Wire bytes, by the verdict of their Flow.",
            &s.bytes,
        ),
        ("flows_total", "Closed Flows, by final verdict.", &s.flows),
    ] {
        p.family(name, "counter", help);
        for v in VerdictLabel::ALL {
            p.sample(name, &format!("verdict=\"{}\"", v.as_str()), vals[v.idx()]);
        }
    }
    p.scalar(
        "flows_active",
        "gauge",
        "Flows seen and not yet closed.",
        s.flows_active,
    );
    p.scalar(
        "flows_with_workunit_total",
        "counter",
        "Closed Flows that carried at least one Request Workunit.",
        s.flows_with_workunit,
    );
    let name = "accounted_bytes_total";
    p.family(
        name,
        "counter",
        "Stream bytes by byte-accounting bucket and direction (spec §5).",
    );
    for b in BUCKETS {
        for d in DIRS {
            let labels = format!("bucket=\"{}\",direction=\"{}\"", bucket_str(b), dir_str(d));
            p.sample(name, &labels, s.accounted_by(b, d));
        }
    }
    let name = "workunits_total";
    p.family(
        name,
        "counter",
        "Request Workunits by Wire Protocol, outcome and response status class.",
    );
    for (protocol, w) in &s.workunits_by_protocol {
        for o in Outcome::ALL {
            for c in HttpClass::ALL {
                let labels = format!(
                    "protocol=\"{protocol}\",outcome=\"{}\",http_class=\"{}\"",
                    o.as_str(),
                    c.as_str()
                );
                p.sample(name, &labels, w[o.idx()][c.idx()]);
            }
        }
    }
    for (name, help, v) in [
        ("gaps_total", "Gaps: stream bytes never captured.", s.gaps),
        ("gap_bytes_total", "Bytes in gaps.", s.gap_bytes),
        (
            "retransmit_bytes_total",
            "Retransmitted stream bytes.",
            s.retransmit_bytes,
        ),
        (
            "retransmit_differing_bytes_total",
            "Retransmitted bytes that differ from the first copy.",
            s.retransmit_differing_bytes,
        ),
        (
            "retransmits_differing_total",
            "Retransmits whose bytes differ from the first copy.",
            s.retransmits_differing,
        ),
        (
            "mid_stream_starts_total",
            "Flows first seen without their handshake.",
            s.mid_stream_starts,
        ),
        (
            "capture_drops_total",
            "Packets the capture reported dropped.",
            s.capture_drops,
        ),
        ("windows_closed_total", "Windows closed.", s.windows_closed),
        (
            "capture_kept_bytes_total",
            "Captured bytes written to L0 chunks (spec §7).",
            s.capture_kept_bytes,
        ),
        (
            "capture_truncated_bytes_total",
            "Captured bytes the Capture Rate cut from L0 chunks.",
            s.capture_truncated_bytes,
        ),
        (
            "store_existing_total",
            "Object puts that found the same bytes already there.",
            s.store_existing,
        ),
        (
            "uploads_total",
            "Spooled objects the uploader put to the remote store.",
            s.uploads,
        ),
        (
            "upload_bytes_total",
            "Bytes the uploader put to the remote store.",
            s.upload_bytes,
        ),
        (
            "uploads_existing_total",
            "Uploads that found the same bytes already in the remote store.",
            s.uploads_existing,
        ),
        (
            "upload_retries_total",
            "Upload attempts that failed and are retried.",
            s.upload_retries,
        ),
    ] {
        p.scalar(name, "counter", help, v);
    }
    let name = "capture_packets_total";
    p.family(
        name,
        "counter",
        "Packets written to L0 chunks, full or truncated.",
    );
    for (i, cut) in ["full", "truncated"].iter().enumerate() {
        p.sample(name, &format!("cut=\"{cut}\""), s.capture_packets[i]);
    }
    for (name, help, vals) in [
        (
            "store_objects_total",
            "Objects written to the store, by kind.",
            &s.store_objects,
        ),
        (
            "store_bytes_total",
            "Bytes written to the store, by kind.",
            &s.store_bytes,
        ),
    ] {
        p.family(name, "counter", help);
        for (i, k) in STORE_KINDS.iter().enumerate() {
            p.sample(name, &format!("kind=\"{k}\""), vals[i]);
        }
    }
    p.scalar(
        "spool_objects",
        "gauge",
        "Objects in the spool, waiting to be uploaded.",
        s.spool_objects,
    );
    p.scalar(
        "spool_bytes",
        "gauge",
        "Bytes in the spool, waiting to be uploaded.",
        s.spool_bytes,
    );
    p.scalar(
        "last_window_lag_seconds",
        "gauge",
        "Wall-clock time from the end of the last closed window to its close.",
        s.last_window_lag_s,
    );
    p.0
}

struct Prom(String);

impl Prom {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {PREFIX}{name} {help}");
        let _ = writeln!(self.0, "# TYPE {PREFIX}{name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &str, v: impl std::fmt::Display) {
        let _ = writeln!(self.0, "{PREFIX}{name}{{{labels}}} {v}");
    }

    fn scalar(&mut self, name: &str, kind: &str, help: &str, v: impl std::fmt::Display) {
        self.family(name, kind, help);
        let _ = writeln!(self.0, "{PREFIX}{name} {v}");
    }
}

/// Serves `GET /metrics` on `addr` from a background thread, for as long as
/// the process runs. Returns the bound address (useful with port 0).
pub fn serve_metrics(addr: impl ToSocketAddrs, registry: Arc<Registry>) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::Builder::new()
        .name("metrics".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        if let Err(e) = respond(stream, &registry) {
                            tracing::debug!(error = %e, "metrics request failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "metrics: accept failed"),
                }
            }
        })?;
    Ok(local)
}

fn respond(mut stream: TcpStream, registry: &Registry) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    // Only the request line matters; read until the end of the headers.
    let mut req = Vec::new();
    let mut buf = [0u8; 1024];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16 << 10 {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
    }
    let line = req.split(|&b| b == b'\n').next().unwrap_or_default();
    let mut parts = line.split(|&b| b == b' ');
    let (method, path) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let path = path.split(|&b| b == b'?').next().unwrap_or_default();
    let (status, ctype, body) = match (method, path) {
        (b"GET", b"/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_prometheus(&registry.snapshot()),
        ),
        (b"GET", _) => ("404 Not Found", "text/plain", "not found; try /metrics\n".into()),
        _ => ("405 Method Not Allowed", "text/plain", "GET only\n".into()),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_utc() {
        assert_eq!(fmt_ts(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(fmt_ts(1_793_620_800_123_000_000), "2026-11-02T12:00:00.123Z");
        assert_eq!(fmt_ts(951_782_400_000_000_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn labels() {
        assert_eq!(HttpClass::of(200).as_str(), "2xx");
        assert_eq!(HttpClass::of(429).as_str(), "4xx");
        assert_eq!(HttpClass::of(503).as_str(), "5xx");
        assert_eq!(HttpClass::of(0).as_str(), "none");
        assert_eq!(
            VerdictLabel::of(FlowKind::Udp, Some(Verdict::Opaque)),
            VerdictLabel::Udp
        );
        assert_eq!(VerdictLabel::of(FlowKind::Tcp, None), VerdictLabel::Other);
        assert_eq!(
            VerdictLabel::of(FlowKind::Ip(1), Some(Verdict::Opaque)),
            VerdictLabel::Other
        );
    }

    #[test]
    fn prometheus_lists_every_series() {
        let r = Registry::default();
        r.add_accounted(Bucket::Workunit, Dir::Resp, 7);
        r.add_workunit("openai", Outcome::Ok, HttpClass::S2xx);
        let text = render_prometheus(&r.snapshot());
        assert!(
            text.contains("ts_collector_accounted_bytes_total{bucket=\"workunit\",direction=\"resp\"} 7\n")
        );
        assert!(text.contains(
            "ts_collector_workunits_total{protocol=\"openai\",outcome=\"ok\",http_class=\"2xx\"} 1\n"
        ));
        assert!(text.contains("ts_collector_packets_total{verdict=\"other\"} 0\n"));
        let samples = text.lines().filter(|l| !l.starts_with('#')).count();
        assert!(text.contains("ts_collector_capture_packets_total{cut=\"truncated\"} 0\n"));
        assert!(text.contains("ts_collector_store_objects_total{kind=\"chunk\"} 0\n"));
        assert!(text.contains("ts_collector_spool_bytes 0\n"));
        // + capture and store: 3 scalars, packets by cut, objects and bytes by kind.
        // + uploads: 4 counters and 2 spool gauges.
        // Workunits: outcome by HTTP class, for every built-in protocol.
        let workunits = 3 * 4 * crate::wire::BUILTIN.len();
        assert_eq!(
            samples,
            3 * 7 + 2 + 5 * 2 + workunits + 8 + 1 + 3 + 2 + 2 * 3 + 4 + 2
        );
    }
}
