//! Protocol identification, HTTP and the OpenAI Wire Protocol on top of
//! Flow assembly (L2–L3, spec §5).
//!
//! [`Decoder`] sits between the [`Assembler`](crate::Assembler) and the
//! output. For each TCP Flow it:
//!
//! - gives a verdict from the first bytes of each direction: the HTTP/2
//!   preface → `http2`; an HTTP/1 request or status line → `http1`; a TLS
//!   record header → `tls`; `content-type: application/grpc` refines
//!   `http2` to `grpc`; anything else → `opaque`. Ports never count;
//! - parses HTTP/1.1 (chunked included) or h2c, pairs requests with
//!   responses, and decides which pairs are Request Workunits;
//! - puts every stream byte in one bucket (`workunit`, `http_other`,
//!   `framing`, `unexplained`, `gap`) and reports the buckets per Flow,
//!   direction and Slice.
//!
//! A request's bytes are only known to be a Workunit once its response
//! head arrives, so a Slice's row waits until every byte in it has a
//! bucket. Rows stay in capture order per Flow. The Decoder reports
//! verdicts and buckets; it never assigns a status.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::Serialize;

use crate::assembler::{EventRecord, FlowSink, PacketRecord, SegmentRecord, SliceRecord};
use crate::flow::{Dir, FlowId, FlowKind};
use crate::http::{Head, HeadReply, Lab, Out, StartLine};
use crate::http1::{parse_request_line, parse_status_line, H1};
use crate::http2::{H2, PREFACE};
use crate::mh;
use crate::openai;
use crate::sse::{self, Sse};

/// Bytes held per direction while the verdict is open.
const MAX_DETECT: usize = 16 << 10;

#[derive(Clone, Debug)]
pub struct DecoderConfig {
    /// Largest request body, or JSON response body, kept in memory to read
    /// record fields from. Larger bodies are still hashed and counted; a
    /// larger request cannot be checked as JSON, so it is `http_other`.
    pub max_body: usize,
    /// Hand every HTTP body to [`RecordSink::body_data`] so it can be kept
    /// (spec §8). Off with `--no-bodies`: hashes and tables stay the same.
    pub keep_bodies: bool,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        DecoderConfig {
            max_body: 16 << 20,
            keep_bodies: true,
        }
    }
}

/// Names one HTTP body while it streams in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BodyKey {
    pub flow: FlowId,
    pub exchange: u64,
    pub dir: Dir,
}

/// A Flow's protocol verdict (spec §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Http1,
    Http2,
    Tls,
    Grpc,
    Opaque,
}

/// Byte-accounting buckets (spec §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    Workunit,
    HttpOther,
    Framing,
    Unexplained,
    Gap,
}

/// Bytes per bucket for one direction of one Slice. For TCP they sum to
/// the Slice's stream range (`stream_end - stream_start`); for UDP and
/// other IP protocols, to the payload bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Buckets {
    pub workunit: u64,
    pub http_other: u64,
    pub framing: u64,
    pub unexplained: u64,
    pub gap: u64,
}

impl Buckets {
    fn add(&mut self, b: Bucket, n: u64) {
        *match b {
            Bucket::Workunit => &mut self.workunit,
            Bucket::HttpOther => &mut self.http_other,
            Bucket::Framing => &mut self.framing,
            Bucket::Unexplained => &mut self.unexplained,
            Bucket::Gap => &mut self.gap,
        } += n;
    }

    pub fn total(&self) -> u64 {
        self.workunit + self.http_other + self.framing + self.unexplained + self.gap
    }
}

/// One Flow during one window, with its verdict and byte accounting (the
/// `flows` table, spec §8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowRecord {
    #[serde(flatten)]
    pub slice: SliceRecord,
    /// `null` while no payload byte has been seen.
    pub verdict: Option<Verdict>,
    pub orig_bytes: Buckets,
    pub resp_bytes: Buckets,
    /// Why parsing of a direction stopped, if it did.
    pub orig_desync: Option<&'static str>,
    pub resp_desync: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersion {
    Http1,
    Http2,
}

/// One HTTP message (L2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MessageRecord {
    pub dir: Dir,
    /// Stream offset of its first byte, and one past its last (HTTP/2: of
    /// its first and last frame; other streams' frames may lie between).
    pub stream_start: u64,
    pub stream_end: Option<u64>,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    /// Body bytes as on the wire (chunked encoding removed, content coding
    /// kept), gaps included.
    pub body_len: u64,
    pub body_gap_bytes: u64,
    /// BLAKE3 of the body as a multihash (`f1e20…`, spec §6); `null` when
    /// part of it was never captured.
    pub body_hash: Option<String>,
    /// The message reached its declared end.
    pub complete: bool,
}

/// One request and its response (the HTTP index table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExchangeRecord {
    pub flow: FlowId,
    /// Order of the exchange within its Flow.
    pub exchange: u64,
    pub http: HttpVersion,
    pub h2_stream: Option<u32>,
    pub bucket: Bucket,
    pub workunit_id: Option<String>,
    pub request: Option<MessageRecord>,
    pub response: Option<MessageRecord>,
    pub interim_responses: u32,
    pub reset: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SseEventRecord {
    pub body_off: u64,
    pub len: u64,
    pub ts_ns: u64,
}

/// A Request Workunit as seen on the Link (the `workunits` table). Field
/// names follow the TS-15 capture record where the Collector can observe
/// the field.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WorkunitRecord {
    /// Multihash BLAKE3 of (Flow id, 0x00, request direction, request start
    /// offset as u64 big-endian): unique, and stable across re-runs.
    pub workunit_id: String,
    pub flow: FlowId,
    pub exchange: u64,
    pub http: HttpVersion,
    pub h2_stream: Option<u32>,
    pub endpoint: &'static str,
    /// First byte of the request, last byte of the response.
    pub received_ts_ns: u64,
    pub completed_ts_ns: Option<u64>,
    pub model: Option<String>,
    pub stream: bool,
    pub seed: Option<serde_json::Value>,
    pub n: Option<serde_json::Value>,
    pub status: u16,
    pub response_content_type: Option<String>,
    /// The request body hash, for the cross-check with the API Tap.
    pub request_body_hash: Option<String>,
    pub request_body_len: u64,
    pub response_body_hash: Option<String>,
    pub response_body_len: u64,
    pub response_id: Option<String>,
    pub response_model: Option<String>,
    pub finish_reason: Vec<openai::FinishReason>,
    pub usage: Option<serde_json::Value>,
    pub sse_events: Option<Vec<SseEventRecord>>,
    pub sse_done: Option<bool>,
    /// Both messages reached their end with no gap.
    pub complete: bool,
}

/// Receives everything the Collector produces.
pub trait RecordSink {
    fn packet(&mut self, rec: &PacketRecord);
    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]);
    fn event(&mut self, rec: &EventRecord);
    fn flow(&mut self, rec: &FlowRecord);
    fn exchange(&mut self, rec: &ExchangeRecord);
    fn workunit(&mut self, rec: &WorkunitRecord);
    /// More bytes of a body, as hashed: chunked encoding removed, content
    /// coding kept. Only called when [`DecoderConfig::keep_bodies`] is set.
    fn body_data(&mut self, _key: &BodyKey, _data: &[u8]) {}
    /// The body is complete: keep it under `hash` (its `body_hash`), or drop it
    /// when `None` (a gap). Called once per body that had `body_data`, and
    /// for empty bodies.
    fn body_end(&mut self, _key: &BodyKey, _hash: Option<&str>) {}
}

pub struct Decoder<'a> {
    cfg: DecoderConfig,
    sink: &'a mut dyn RecordSink,
    flows: HashMap<FlowId, FlowState>,
}

impl<'a> Decoder<'a> {
    pub fn new(cfg: DecoderConfig, sink: &'a mut dyn RecordSink) -> Self {
        Decoder {
            cfg,
            sink,
            flows: HashMap::new(),
        }
    }
}

impl FlowSink for Decoder<'_> {
    fn packet(&mut self, rec: &PacketRecord) {
        self.sink.packet(rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        self.sink.segment(rec, data);
        let f = self
            .flows
            .entry(rec.flow.clone())
            .or_insert_with(|| FlowState::new(rec.flow.clone()));
        f.input(rec.dir, Piece::Data(data, rec.ts_ns), &self.cfg, self.sink);
    }

    fn event(&mut self, rec: &EventRecord) {
        self.sink.event(rec);
        if let (true, Some(dir), Some(_)) = (rec.kind.is_gap(), rec.dir, rec.stream_off) {
            let f = self
                .flows
                .entry(rec.flow.clone())
                .or_insert_with(|| FlowState::new(rec.flow.clone()));
            f.input(dir, Piece::Gap(rec.len), &self.cfg, self.sink);
        }
    }

    fn slice(&mut self, rec: &SliceRecord) {
        if rec.kind != FlowKind::Tcp {
            let bytes = |s: &crate::assembler::DirStats| Buckets {
                unexplained: s.payload_bytes - s.gap_bytes,
                gap: s.gap_bytes,
                ..Buckets::default()
            };
            self.sink.flow(&FlowRecord {
                slice: rec.clone(),
                verdict: Some(Verdict::Opaque),
                orig_bytes: bytes(&rec.orig_stats),
                resp_bytes: bytes(&rec.resp_stats),
                orig_desync: None,
                resp_desync: None,
            });
            return;
        }
        let sink = &mut *self.sink;
        let f = self
            .flows
            .entry(rec.flow.clone())
            .or_insert_with(|| FlowState::new(rec.flow.clone()));
        f.held.push_back(rec.clone());
        f.emit_ready(sink);
        if rec.ended {
            self.flows.remove(&rec.flow);
        }
    }

    fn flow_end(&mut self, flow: &FlowId, slice_pending: bool) {
        if !self.flows.contains_key(flow) {
            return;
        }
        let sink = &mut *self.sink;
        let f = self.flows.get_mut(flow).expect("present");
        f.end(&self.cfg, sink);
        f.emit_ready(sink);
        if !slice_pending {
            self.flows.remove(flow);
        }
    }
}

impl Decoder<'_> {
    /// Flows with protocol state still held.
    pub fn open_flows(&self) -> usize {
        self.flows.len()
    }
}

/// Bytes (with their capture time) or a gap delivered for one direction.
enum Piece<B> {
    Data(B, u64),
    Gap(u64),
}

impl Piece<Vec<u8>> {
    fn borrowed(&self) -> Piece<&[u8]> {
        match self {
            Piece::Data(d, ts) => Piece::Data(d, *ts),
            Piece::Gap(n) => Piece::Gap(*n),
        }
    }
}

enum Parser {
    H1(H1),
    H2(H2),
    Opaque,
}

impl Parser {
    fn feed(&mut self, piece: Piece<&[u8]>, out: &mut dyn Out) {
        match (self, piece) {
            (Parser::H1(p), Piece::Data(d, ts)) => p.data(d, ts, out),
            (Parser::H1(p), Piece::Gap(n)) => p.gap(n, out),
            (Parser::H2(p), Piece::Data(d, ts)) => p.data(d, ts, out),
            (Parser::H2(p), Piece::Gap(n)) => p.gap(n, out),
            (Parser::Opaque, Piece::Data(d, _)) => out.span(d.len() as u64, Lab::Unexplained),
            (Parser::Opaque, Piece::Gap(n)) => out.span(n, Lab::Gap),
        }
    }

    fn finish(&mut self, out: &mut dyn Out) {
        match self {
            Parser::H1(p) => p.finish(out),
            Parser::H2(p) => p.finish(out),
            Parser::Opaque => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Bucket(Bucket),
    /// Belongs to an exchange whose bucket is not known yet.
    Exchange(u64),
}

/// The labeled bytes of one direction not yet reported in a Slice row.
#[derive(Default)]
struct Ledger {
    /// Stream offset where the first span starts.
    base: u64,
    /// Stream offset one past the last labeled byte.
    cursor: u64,
    /// `(len, label)`, contiguous from `base`.
    spans: VecDeque<(u64, Label)>,
}

impl Ledger {
    fn push(&mut self, len: u64, label: Label) {
        self.cursor += len;
        match self.spans.back_mut() {
            Some((n, l)) if *l == label => *n += len,
            _ => self.spans.push_back((len, label)),
        }
    }

    fn resolve(&mut self, id: u64, bucket: Bucket) {
        for (_, l) in self.spans.iter_mut() {
            if *l == Label::Exchange(id) {
                *l = Label::Bucket(bucket);
            }
        }
    }

    /// Buckets for `[start, end)`, if every byte there has one.
    fn tally(&self, start: u64, end: u64) -> Option<Buckets> {
        if self.cursor < end {
            return None;
        }
        let mut out = Buckets::default();
        let mut at = self.base;
        for &(len, label) in &self.spans {
            let (s, e) = (at.max(start), (at + len).min(end));
            at += len;
            if s < e {
                match label {
                    Label::Bucket(b) => out.add(b, e - s),
                    Label::Exchange(_) => return None,
                }
            }
            if at >= end {
                break;
            }
        }
        Some(out)
    }

    /// Forgets spans before `end`.
    fn prune(&mut self, end: u64) {
        while let Some(&(len, label)) = self.spans.front() {
            if self.base + len <= end {
                self.base += len;
                self.spans.pop_front();
            } else {
                if self.base < end {
                    let cut = end - self.base;
                    self.spans[0] = (len - cut, label);
                    self.base = end;
                }
                break;
            }
        }
    }
}

struct Body {
    len: u64,
    gap: u64,
    hasher: blake3::Hasher,
    /// Kept for JSON parsing, up to the configured limit.
    keep: bool,
    buf: Vec<u8>,
    over_limit: bool,
    sse: Option<Sse>,
    events: Vec<SseEventRecord>,
    /// Still streaming to the sink (keep_bodies on, no gap yet).
    stored: bool,
}

impl Body {
    fn new(keep: bool, sse: bool) -> Self {
        Body {
            len: 0,
            gap: 0,
            hasher: blake3::Hasher::new(),
            keep,
            buf: Vec::new(),
            over_limit: false,
            sse: sse.then(Sse::default),
            events: Vec::new(),
            stored: false,
        }
    }

    /// Adds body bytes; SSE events they complete go to `events`.
    fn push(&mut self, data: &[u8], ts: u64, max: usize, events: &mut Vec<sse::Event>) {
        self.len += data.len() as u64;
        self.hasher.update(data);
        if self.keep && !self.over_limit {
            if self.buf.len() + data.len() <= max {
                self.buf.extend_from_slice(data);
            } else {
                self.over_limit = true;
                self.buf = Vec::new();
            }
        }
        if let Some(s) = &mut self.sse {
            s.push(data, ts, events);
            self.events.extend(events.iter().map(|e| SseEventRecord {
                body_off: e.body_off,
                len: e.len,
                ts_ns: e.ts_ns,
            }));
        }
    }

    fn gap(&mut self, len: u64) {
        self.len += len;
        self.gap += len;
        if let Some(s) = &mut self.sse {
            s.gap();
        }
    }

    fn hash(&self) -> Option<String> {
        (self.gap == 0).then(|| mh::name(&self.hasher.finalize()))
    }
}

struct Msg {
    dir: Dir,
    start: u64,
    end: Option<u64>,
    first_ts: u64,
    last_ts: u64,
    head: Head,
    body: Body,
    done: bool,
    complete: bool,
}

impl Msg {
    fn record(&self) -> MessageRecord {
        let (method, target, status) = match &self.head.start {
            StartLine::Request { method, target } => (Some(method.clone()), Some(target.clone()), None),
            StartLine::Response { status } => (None, None, Some(*status)),
            StartLine::Trailers => (None, None, None),
        };
        MessageRecord {
            dir: self.dir,
            stream_start: self.start,
            stream_end: self.end,
            first_ts_ns: self.first_ts,
            last_ts_ns: self.last_ts,
            method,
            target,
            status,
            content_type: self.head.header_str("content-type"),
            content_encoding: self.head.header_str("content-encoding"),
            body_len: self.body.len,
            body_gap_bytes: self.body.gap,
            body_hash: self.body.hash(),
            complete: self.complete && self.body.gap == 0,
        }
    }

    /// No content coding, or `identity`.
    fn identity(&self) -> bool {
        self.head
            .header_str("content-encoding")
            .is_none_or(|c| c.is_empty() || c.eq_ignore_ascii_case("identity"))
    }
}

struct Exchange {
    seq: u64,
    h2_stream: Option<u32>,
    req: Option<Msg>,
    resp: Option<Msg>,
    interim: u32,
    reset: bool,
    endpoint: Option<&'static str>,
    request: Option<openai::Request>,
    response: openai::Response,
    bucket: Option<Bucket>,
}

/// Which way a direction's first bytes point.
#[derive(Debug, PartialEq, Eq)]
enum Detect {
    Need,
    H2Preface,
    RequestLine,
    StatusLine,
    Tls,
    Opaque,
}

/// Classifies the first bytes of a direction. `closed`: no more bytes will
/// be added to `prefix`.
fn detect(prefix: &[u8], closed: bool) -> Detect {
    let need = if closed { Detect::Opaque } else { Detect::Need };
    if prefix.is_empty() {
        return need;
    }
    if prefix.starts_with(PREFACE) {
        return Detect::H2Preface;
    }
    if PREFACE.starts_with(prefix) {
        return need;
    }
    if prefix[0] == 0x16 {
        return match prefix {
            [_, 3, v, ..] if *v <= 4 => Detect::Tls,
            [_] | [_, 3] => need,
            _ => Detect::Opaque,
        };
    }
    match prefix.windows(2).position(|w| w == b"\r\n") {
        Some(i) => {
            let line = &prefix[..i];
            if parse_request_line(line).is_some() {
                Detect::RequestLine
            } else if parse_status_line(line).is_some() {
                Detect::StatusLine
            } else {
                Detect::Opaque
            }
        }
        None if prefix.iter().all(|&b| (0x20..0x7f).contains(&b) || b == b'\r') => need,
        None => Detect::Opaque,
    }
}

struct FlowState {
    id: FlowId,
    verdict: Option<Verdict>,
    grpc: bool,
    /// Pieces held per direction until the verdict.
    detect: [Vec<Piece<Vec<u8>>>; 2],
    detect_bytes: [usize; 2],
    parsers: Option<[Parser; 2]>,
    client: Dir,
    ledgers: [Ledger; 2],
    exchanges: BTreeMap<u64, Exchange>,
    next_seq: u64,
    /// HTTP/1: exchanges waiting for a final response, oldest first.
    awaiting: VecDeque<u64>,
    /// HTTP/1: the exchange of the message in progress per direction.
    current: [Option<u64>; 2],
    /// HTTP/2: stream id → exchange.
    streams: HashMap<u32, u64>,
    dead: [Option<&'static str>; 2],
    ended: bool,
    held: VecDeque<SliceRecord>,
}

impl FlowState {
    fn new(id: FlowId) -> Self {
        FlowState {
            id,
            verdict: None,
            grpc: false,
            detect: [Vec::new(), Vec::new()],
            detect_bytes: [0, 0],
            parsers: None,
            client: Dir::Orig,
            ledgers: Default::default(),
            exchanges: BTreeMap::new(),
            next_seq: 0,
            awaiting: VecDeque::new(),
            current: [None, None],
            streams: HashMap::new(),
            dead: [None, None],
            ended: false,
            held: VecDeque::new(),
        }
    }

    fn input(&mut self, dir: Dir, piece: Piece<&[u8]>, cfg: &DecoderConfig, sink: &mut dyn RecordSink) {
        if self.parsers.is_some() {
            return self.feed(dir, piece, cfg, sink);
        }
        let owned = match piece {
            Piece::Data(d, ts) => {
                self.detect_bytes[dir.idx()] += d.len();
                Piece::Data(d.to_vec(), ts)
            }
            Piece::Gap(n) => Piece::Gap(n),
        };
        self.detect[dir.idx()].push(owned);
        self.decide(false, cfg, sink);
    }

    fn feed(&mut self, dir: Dir, piece: Piece<&[u8]>, cfg: &DecoderConfig, sink: &mut dyn RecordSink) {
        let mut parsers = self.parsers.take().expect("decided");
        parsers[dir.idx()].feed(
            piece,
            &mut Ctx {
                f: self,
                dir,
                cfg,
                sink,
            },
        );
        self.parsers = Some(parsers);
    }

    /// The data before the first gap, and whether it can still grow.
    fn prefix(&self, dir: Dir) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        for p in &self.detect[dir.idx()] {
            match p {
                Piece::Data(d, _) => out.extend_from_slice(d),
                Piece::Gap(_) => return (out, true),
            }
        }
        let full = self.detect_bytes[dir.idx()] >= MAX_DETECT;
        (out, full)
    }

    /// Sets the verdict once the first bytes allow it (or `force`).
    fn decide(&mut self, force: bool, cfg: &DecoderConfig, sink: &mut dyn RecordSink) {
        let mut found = None;
        for dir in [Dir::Orig, Dir::Resp] {
            if self.detect[dir.idx()].is_empty() {
                continue;
            }
            let (prefix, closed) = self.prefix(dir);
            match detect(&prefix, closed || force) {
                Detect::Need => return,
                d => {
                    found = Some((d, dir));
                    break;
                }
            }
        }
        let (d, dir) = match found {
            Some(f) => f,
            None if force => {
                // No payload at all: nothing to identify.
                self.parsers = Some([Parser::Opaque, Parser::Opaque]);
                return;
            }
            None => return,
        };
        let (verdict, client, parsers) = match d {
            Detect::H2Preface => (
                Verdict::Http2,
                dir,
                [Parser::H2(H2::new(true)), Parser::H2(H2::new(false))],
            ),
            Detect::RequestLine => (
                Verdict::Http1,
                dir,
                [Parser::H1(H1::new(true)), Parser::H1(H1::new(false))],
            ),
            Detect::StatusLine => (
                Verdict::Http1,
                dir.other(),
                [Parser::H1(H1::new(true)), Parser::H1(H1::new(false))],
            ),
            Detect::Tls => (Verdict::Tls, Dir::Orig, [Parser::Opaque, Parser::Opaque]),
            Detect::Opaque | Detect::Need => (Verdict::Opaque, Dir::Orig, [Parser::Opaque, Parser::Opaque]),
        };
        self.verdict = Some(verdict);
        self.client = client;
        // parsers[0] is the client side; store them by direction.
        let [c, s] = parsers;
        self.parsers = Some(if client == Dir::Orig { [c, s] } else { [s, c] });
        // Replay the client side first, so requests come before responses.
        for d in [client, client.other()] {
            for piece in std::mem::take(&mut self.detect[d.idx()]) {
                self.feed(d, piece.borrowed(), cfg, sink);
            }
        }
    }

    /// The Flow ended: finish parsing and settle every exchange.
    fn end(&mut self, cfg: &DecoderConfig, sink: &mut dyn RecordSink) {
        if self.parsers.is_none() {
            self.decide(true, cfg, sink);
        }
        let mut parsers = self.parsers.take().expect("decided");
        for dir in [self.client, self.client.other()] {
            parsers[dir.idx()].finish(&mut Ctx {
                f: self,
                dir,
                cfg,
                sink,
            });
        }
        self.parsers = Some(parsers);
        self.ended = true;
        self.settle_all(sink);
    }

    /// Emits held Slice rows whose bytes all have buckets, in order.
    fn emit_ready(&mut self, sink: &mut dyn RecordSink) {
        while let Some(slice) = self.held.front() {
            let range =
                |s: &crate::assembler::DirStats| (s.stream_start.unwrap_or(0), s.stream_end.unwrap_or(0));
            let (os, oe) = range(&slice.orig_stats);
            let (rs, re) = range(&slice.resp_stats);
            let (Some(mut ob), Some(mut rb)) = (self.ledgers[0].tally(os, oe), self.ledgers[1].tally(rs, re))
            else {
                return;
            };
            if self.grpc {
                for b in [&mut ob, &mut rb] {
                    b.unexplained += b.workunit + b.http_other + b.framing;
                    (b.workunit, b.http_other, b.framing) = (0, 0, 0);
                }
            }
            let slice = self.held.pop_front().expect("front");
            self.ledgers[0].prune(oe);
            self.ledgers[1].prune(re);
            let verdict = if self.grpc {
                Some(Verdict::Grpc)
            } else {
                self.verdict
            };
            sink.flow(&FlowRecord {
                slice,
                verdict,
                orig_bytes: ob,
                resp_bytes: rb,
                orig_desync: self.dead[0],
                resp_desync: self.dead[1],
            });
        }
    }

    fn new_exchange(&mut self, h2_stream: Option<u32>) -> u64 {
        let id = self.next_seq;
        self.next_seq += 1;
        self.exchanges.insert(
            id,
            Exchange {
                seq: id,
                h2_stream,
                req: None,
                resp: None,
                interim: 0,
                reset: false,
                endpoint: None,
                request: None,
                response: openai::Response::default(),
                bucket: None,
            },
        );
        if let Some(s) = h2_stream {
            self.streams.insert(s, id);
        }
        id
    }

    /// The exchange that bytes of `stream` in `dir` belong to.
    fn exchange_of(&self, dir: Dir, stream: u32) -> Option<u64> {
        match self.verdict {
            Some(Verdict::Http2) => self.streams.get(&stream).copied(),
            _ => self.current[dir.idx()],
        }
        .filter(|id| self.exchanges.contains_key(id))
    }

    /// Decides the exchange's bucket once the facts allow, then writes the
    /// exchange (and Workunit) record once nothing more can arrive for it.
    fn settle(&mut self, id: u64, sink: &mut dyn RecordSink) {
        let client = self.client;
        let server = client.other();
        let req_closed = self.ended || self.dead[client.idx()].is_some();
        let resp_closed = self.ended || self.dead[server.idx()].is_some();
        let Some(ex) = self.exchanges.get_mut(&id) else {
            return;
        };
        if ex.bucket.is_none() {
            ex.bucket = classify(ex, self.grpc, req_closed, resp_closed);
            if let Some(b) = ex.bucket {
                for l in &mut self.ledgers {
                    l.resolve(id, b);
                }
            }
        }
        let finished = ex.reset || resp_closed || ex.resp.as_ref().is_some_and(|r| r.done);
        let Some(bucket) = ex.bucket else { return };
        if !finished || (!ex.req.as_ref().is_none_or(|r| r.done) && !req_closed && !ex.reset) {
            return;
        }
        let ex = self.exchanges.remove(&id).expect("present");
        if let Some(s) = ex.h2_stream {
            if self.streams.get(&s) == Some(&id) {
                self.streams.remove(&s);
            }
        }
        self.write(ex, bucket, sink);
    }

    fn write(&self, mut ex: Exchange, bucket: Bucket, sink: &mut dyn RecordSink) {
        let http = match self.verdict {
            Some(Verdict::Http2) => HttpVersion::Http2,
            _ => HttpVersion::Http1,
        };
        let workunit_id = (bucket == Bucket::Workunit).then(|| {
            let req = ex.req.as_ref().expect("a Workunit has a request");
            let mut h = blake3::Hasher::new();
            h.update(self.id.as_str().as_bytes());
            h.update(&[0, req.dir.idx() as u8]);
            h.update(&req.start.to_be_bytes());
            mh::name(&h.finalize())
        });
        sink.exchange(&ExchangeRecord {
            flow: self.id.clone(),
            exchange: ex.seq,
            http,
            h2_stream: ex.h2_stream,
            bucket,
            workunit_id: workunit_id.clone(),
            request: ex.req.as_ref().map(Msg::record),
            response: ex.resp.as_ref().map(Msg::record),
            interim_responses: ex.interim,
            reset: ex.reset,
        });
        for m in [&ex.req, &ex.resp].into_iter().flatten() {
            if m.body.stored {
                let key = BodyKey {
                    flow: self.id.clone(),
                    exchange: ex.seq,
                    dir: m.dir,
                };
                sink.body_end(&key, m.body.hash().as_deref());
            }
        }
        let Some(workunit_id) = workunit_id else { return };
        let (Some(req), Some(resp)) = (&ex.req, &mut ex.resp) else {
            return;
        };
        let request = ex.request.clone().unwrap_or_default();
        // A JSON response is read whole; SSE was read event by event.
        let sse = resp.body.sse.is_some();
        if !sse && resp.done && resp.body.gap == 0 && !resp.body.over_limit && resp.identity() {
            ex.response.absorb(&resp.body.buf);
        }
        let complete = req.complete && resp.complete && req.body.gap == 0 && resp.body.gap == 0 && !ex.reset;
        let status = match resp.head.start {
            StartLine::Response { status } => status,
            _ => 0,
        };
        sink.workunit(&WorkunitRecord {
            workunit_id,
            flow: self.id.clone(),
            exchange: ex.seq,
            http,
            h2_stream: ex.h2_stream,
            endpoint: ex.endpoint.unwrap_or_default(),
            received_ts_ns: req.first_ts,
            completed_ts_ns: resp.done.then_some(resp.last_ts),
            model: request.model,
            stream: request.stream,
            seed: request.seed,
            n: request.n,
            status,
            response_content_type: resp.head.media_type(),
            request_body_hash: req.body.hash(),
            request_body_len: req.body.len,
            response_body_hash: resp.body.hash(),
            response_body_len: resp.body.len,
            response_id: ex.response.id.clone(),
            response_model: ex.response.model.clone(),
            finish_reason: ex.response.finish_reasons(),
            usage: ex.response.usage.clone(),
            sse_events: sse.then(|| std::mem::take(&mut resp.body.events)),
            sse_done: sse.then_some(ex.response.done),
            complete,
        });
    }

    fn settle_all(&mut self, sink: &mut dyn RecordSink) {
        let ids: Vec<u64> = self.exchanges.keys().copied().collect();
        for id in ids {
            self.settle(id, sink);
        }
    }
}

/// The exchange's bucket, or `None` while it depends on bytes still to come.
fn classify(ex: &mut Exchange, grpc: bool, req_closed: bool, resp_closed: bool) -> Option<Bucket> {
    if grpc {
        // Parsed as HTTP/2, but the payload is opaque (spec §5).
        return Some(Bucket::Unexplained);
    }
    let Some(req) = &ex.req else {
        // A response without a request we saw.
        return Some(Bucket::HttpOther);
    };
    if ex.endpoint.is_none() {
        return Some(Bucket::HttpOther);
    }
    if ex.request.is_none() {
        if !req.done {
            return (req_closed || ex.reset).then_some(Bucket::HttpOther);
        }
        let readable = req.complete && req.body.gap == 0 && !req.body.over_limit && req.identity();
        match readable.then(|| openai::parse_request(&req.body.buf)).flatten() {
            Some(r) => ex.request = Some(r),
            None => return Some(Bucket::HttpOther),
        }
    }
    let stream = ex.request.as_ref().is_some_and(|r| r.stream);
    match &ex.resp {
        Some(resp) => Some(
            if openai::response_matches(resp.head.media_type().as_deref(), stream) {
                Bucket::Workunit
            } else {
                Bucket::HttpOther
            },
        ),
        None => (resp_closed || ex.reset).then_some(Bucket::HttpOther),
    }
}

/// A parser's view of the Flow, for one direction.
struct Ctx<'a> {
    f: &'a mut FlowState,
    dir: Dir,
    cfg: &'a DecoderConfig,
    sink: &'a mut dyn RecordSink,
}

impl Ctx<'_> {
    fn is_client(&self) -> bool {
        self.dir == self.f.client
    }

    fn msg(&mut self, stream: u32) -> Option<&mut Msg> {
        let id = self.f.exchange_of(self.dir, stream)?;
        let client = self.is_client();
        let ex = self.f.exchanges.get_mut(&id)?;
        if client {
            ex.req.as_mut()
        } else {
            ex.resp.as_mut()
        }
    }

    fn new_msg(&self, start: u64, ts: u64, head: Head, keep: bool) -> Msg {
        let sse = !self.is_client()
            && head.media_type().as_deref() == Some("text/event-stream")
            && head
                .header_str("content-encoding")
                .is_none_or(|c| c.eq_ignore_ascii_case("identity"));
        Msg {
            dir: self.dir,
            start,
            end: None,
            first_ts: ts,
            last_ts: ts,
            head,
            body: Body {
                stored: self.cfg.keep_bodies,
                ..Body::new(keep, sse)
            },
            done: false,
            complete: false,
        }
    }

    fn settle(&mut self, id: u64) {
        self.f.settle(id, self.sink);
    }
}

impl Out for Ctx<'_> {
    fn span(&mut self, len: u64, lab: Lab) {
        let label = match lab {
            Lab::Framing => Label::Bucket(Bucket::Framing),
            Lab::Other => Label::Bucket(Bucket::HttpOther),
            Lab::Unexplained => Label::Bucket(Bucket::Unexplained),
            Lab::Gap => Label::Bucket(Bucket::Gap),
            Lab::Msg(s) => match self.f.exchange_of(self.dir, s) {
                Some(id) => match self.f.exchanges[&id].bucket {
                    Some(b) => Label::Bucket(b),
                    None => Label::Exchange(id),
                },
                None => Label::Bucket(Bucket::Unexplained),
            },
        };
        self.f.ledgers[self.dir.idx()].push(len, label);
    }

    fn head(&mut self, stream: u32, start: u64, ts: u64, head: Head) -> HeadReply {
        let h2 = self.f.verdict == Some(Verdict::Http2);
        let h2_stream = h2.then_some(stream);
        let mut reply = HeadReply::default();
        if self.is_client() {
            let StartLine::Request { method, target } = &head.start else {
                // HTTP/2 trailers: part of the request already open.
                return reply;
            };
            if h2
                && head
                    .media_type()
                    .is_some_and(|t| t.starts_with("application/grpc"))
            {
                self.f.grpc = true;
            }
            let endpoint = openai::endpoint(method, target);
            let id = self.f.new_exchange(h2_stream);
            if !h2 {
                self.f.current[self.dir.idx()] = Some(id);
                self.f.awaiting.push_back(id);
            }
            let msg = self.new_msg(start, ts, head, endpoint.is_some());
            let ex = self.f.exchanges.get_mut(&id).expect("new");
            ex.endpoint = endpoint;
            ex.req = Some(msg);
            self.settle(id);
            return reply;
        }
        let status = match head.start {
            StartLine::Response { status } => status,
            _ => return reply,
        };
        let interim = (100..200).contains(&status) && status != 101;
        let id = if h2 {
            self.f.exchange_of(self.dir, stream)
        } else if interim {
            self.f.awaiting.front().copied()
        } else {
            self.f.awaiting.pop_front()
        }
        .filter(|id| self.f.exchanges.get(id).is_some_and(|e| e.resp.is_none()))
        .unwrap_or_else(|| self.f.new_exchange(h2_stream));
        if !h2 {
            self.f.current[self.dir.idx()] = Some(id);
        }
        let candidate = self.f.exchanges[&id].endpoint.is_some();
        let msg = (!interim).then(|| {
            let json = head.media_type().as_deref() == Some("application/json");
            self.new_msg(start, ts, head, candidate && json)
        });
        let ex = self.f.exchanges.get_mut(&id).expect("exists");
        if let Some(StartLine::Request { method, .. }) = ex.req.as_ref().map(|r| &r.head.start) {
            reply.no_body = method == "HEAD";
            reply.tunnel = method == "CONNECT";
        }
        match msg {
            Some(m) => ex.resp = Some(m),
            None => ex.interim += 1,
        }
        self.settle(id);
        reply
    }

    fn body(&mut self, stream: u32, data: &[u8], ts: u64) {
        let Some(id) = self.f.exchange_of(self.dir, stream) else {
            return;
        };
        let client = self.is_client();
        let ex = self.f.exchanges.get_mut(&id).expect("exists");
        let Some(m) = (if client { ex.req.as_mut() } else { ex.resp.as_mut() }) else {
            return;
        };
        let mut events = Vec::new();
        m.body.push(data, ts, self.cfg.max_body, &mut events);
        m.last_ts = ts;
        if m.body.stored && !data.is_empty() {
            let key = BodyKey {
                flow: self.f.id.clone(),
                exchange: id,
                dir: self.dir,
            };
            self.sink.body_data(&key, data);
        }
        for e in events {
            ex.response.absorb(&e.data);
        }
    }

    fn body_gap(&mut self, stream: u32, len: u64) {
        let Some(id) = self.f.exchange_of(self.dir, stream) else {
            return;
        };
        let flow = self.f.id.clone();
        let dir = self.dir;
        let Some(m) = self.msg(stream) else { return };
        m.body.gap(len);
        // A body with a gap has no hash, so it is not kept.
        if std::mem::take(&mut m.body.stored) {
            let key = BodyKey {
                flow,
                exchange: id,
                dir,
            };
            self.sink.body_end(&key, None);
        }
    }

    fn end(&mut self, stream: u32, end: u64, ts: u64, complete: bool) {
        let Some(id) = self.f.exchange_of(self.dir, stream) else {
            return;
        };
        if let Some(m) = self.msg(stream) {
            m.end = Some(end);
            m.last_ts = m.last_ts.max(ts);
            m.done = true;
            m.complete = complete;
        }
        self.settle(id);
    }

    fn reset(&mut self, stream: u32) {
        let Some(id) = self.f.exchange_of(self.dir, stream) else {
            return;
        };
        if let Some(ex) = self.f.exchanges.get_mut(&id) {
            ex.reset = true;
        }
        self.settle(id);
    }

    fn desync(&mut self, reason: &'static str) {
        let d = &mut self.f.dead[self.dir.idx()];
        if d.is_none() {
            *d = Some(reason);
        }
        self.f.settle_all(self.sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_first_bytes() {
        assert_eq!(detect(b"PRI * HTTP/2.0\r\n", false), Detect::Need);
        assert_eq!(detect(PREFACE, false), Detect::H2Preface);
        assert_eq!(
            detect(b"POST /v1/completions HTTP/1.1\r\n", false),
            Detect::RequestLine
        );
        assert_eq!(detect(b"POST /v1/comp", false), Detect::Need);
        assert_eq!(detect(b"POST /v1/comp", true), Detect::Opaque);
        assert_eq!(detect(b"HTTP/1.1 200 OK\r\n", false), Detect::StatusLine);
        assert_eq!(detect(b"\x16\x03\x01\x02\x00", false), Detect::Tls);
        assert_eq!(detect(b"\x16", false), Detect::Need);
        assert_eq!(detect(b"\x16\x02\x01", false), Detect::Opaque);
        assert_eq!(detect(b"*1\r\n$4\r\nPING\r\n", false), Detect::Opaque);
        assert_eq!(detect(b"SSH-2.0-OpenSSH\x00", false), Detect::Opaque);
    }

    #[test]
    fn ledger_tally_and_prune() {
        let mut l = Ledger::default();
        l.push(10, Label::Bucket(Bucket::Framing));
        l.push(5, Label::Exchange(1));
        l.push(5, Label::Bucket(Bucket::Gap));
        assert_eq!(l.tally(0, 10).unwrap().framing, 10);
        assert_eq!(l.tally(0, 12), None);
        assert_eq!(l.tally(0, 21), None);
        l.resolve(1, Bucket::Workunit);
        let b = l.tally(8, 20).unwrap();
        assert_eq!((b.framing, b.workunit, b.gap, b.total()), (2, 5, 5, 12));
        l.prune(12);
        assert_eq!(l.base, 12);
        assert_eq!(l.tally(12, 20).unwrap().workunit, 3);
    }

    #[test]
    fn decoder_starts_empty() {
        struct Nop;
        impl RecordSink for Nop {
            fn packet(&mut self, _: &PacketRecord) {}
            fn segment(&mut self, _: &SegmentRecord, _: &[u8]) {}
            fn event(&mut self, _: &EventRecord) {}
            fn flow(&mut self, _: &FlowRecord) {}
            fn exchange(&mut self, _: &ExchangeRecord) {}
            fn workunit(&mut self, _: &WorkunitRecord) {}
        }
        let mut nop = Nop;
        assert_eq!(Decoder::new(DecoderConfig::default(), &mut nop).open_flows(), 0);
    }
}
