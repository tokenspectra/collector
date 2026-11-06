//! Protocol identification, HTTP and the Wire Protocols on top of Flow
//! assembly (L2–L3, spec §5).
//!
//! [`Decoder`] sits between the [`Assembler`](crate::Assembler) and the
//! output. For each TCP Flow it:
//!
//! - gives a verdict from the first bytes of each direction: the HTTP/2
//!   preface → `http2`; an HTTP/1 request or status line → `http1`; a TLS
//!   record header → `tls`; `content-type: application/grpc` refines
//!   `http2` to `grpc`; anything else → `opaque`. Ports never count;
//! - parses HTTP/1.1 (chunked included) or h2c, pairs requests with
//!   responses, and asks the registered Wire Protocols ([`crate::wire`])
//!   which pairs are Request Workunits;
//! - puts every stream byte in one bucket (`workunit`, `http_other`,
//!   `framing`, `unexplained`, `gap`) and reports the buckets per Flow,
//!   direction and Slice.
//!
//! For each UDP Flow it tries every datagram as DNS ([`crate::dns`]); on a
//! `tls` Flow it reads the ClientHello ([`crate::tls`]).
//!
//! A request's bytes are only known to be a Workunit once its response
//! head arrives, so a Slice's row waits until every byte in it has a
//! bucket. Rows stay in capture order per Flow. The Decoder reports
//! verdicts and buckets; it never assigns a status.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use serde::Serialize;

use crate::assembler::{EventRecord, FlowSink, PacketRecord, SegmentRecord, SliceRecord};
use crate::coding::{self, DecodeError, Decoding, Encoding};
use crate::dns::{self, Datagram, DnsFeatures, DnsRecord, Tally};
use crate::flow::{Dir, FlowId, FlowKind};
use crate::http::{Head, HeadReply, Lab, Out, StartLine};
use crate::http1::{parse_request_line, parse_status_line, H1};
use crate::http2::{H2, PREFACE};
use crate::mh;
use crate::packet::{CapturedPacket, LinkId, PacketRef};
use crate::tls::{ClientHello, TlsFeatures, TlsRecord};
use crate::wire::framing::{Framed, Framer};
use crate::wire::{self, Claim, Frame, Framing, Protocols, ResponseDecoder};

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
    /// The Wire Protocols requests are matched against (spec §5).
    pub protocols: Protocols,
    /// How far a body under a content coding may decode (spec §6).
    pub decode_limits: coding::Limits,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        DecoderConfig {
            max_body: 16 << 20,
            keep_bodies: true,
            protocols: Protocols::default(),
            decode_limits: coding::Limits::default(),
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
    /// Inside a protocol fact: a whole DNS message in a UDP datagram, or a
    /// TLS ClientHello.
    Fact,
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
    pub fact: u64,
}

impl Buckets {
    fn add(&mut self, b: Bucket, n: u64) {
        *match b {
            Bucket::Workunit => &mut self.workunit,
            Bucket::HttpOther => &mut self.http_other,
            Bucket::Framing => &mut self.framing,
            Bucket::Unexplained => &mut self.unexplained,
            Bucket::Gap => &mut self.gap,
            Bucket::Fact => &mut self.fact,
        } += n;
    }

    pub fn get(&self, b: Bucket) -> u64 {
        match b {
            Bucket::Workunit => self.workunit,
            Bucket::HttpOther => self.http_other,
            Bucket::Framing => self.framing,
            Bucket::Unexplained => self.unexplained,
            Bucket::Gap => self.gap,
            Bucket::Fact => self.fact,
        }
    }

    pub fn total(&self) -> u64 {
        self.workunit + self.http_other + self.framing + self.unexplained + self.gap + self.fact
    }
}

/// Covert-channel features of one Flow during one Slice (the `features`
/// table): one family of columns per protocol-fact decoder.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FeaturesRecord {
    pub window_start_ns: u64,
    pub flow: FlowId,
    pub link: LinkId,
    pub dns: Option<DnsFeatures>,
    pub tls: Option<TlsFeatures>,
}

impl FeaturesRecord {
    /// Writes the row of `slice`, if any family has something in it.
    fn emit(
        slice: &SliceRecord,
        dns: Option<DnsFeatures>,
        tls: Option<TlsFeatures>,
        sink: &mut dyn RecordSink,
    ) {
        if dns.is_some() || tls.is_some() {
            sink.features(&FeaturesRecord {
                window_start_ns: slice.window_start_ns,
                flow: slice.flow.clone(),
                link: slice.link.clone(),
                dns,
                tls,
            });
        }
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
    /// Under a content coding: the body's bytes once decoded, and their
    /// BLAKE3, set only when decoding reached the end of the coded stream.
    /// `null` with no content coding (`body_hash` covers the bytes read).
    pub decoded_len: Option<u64>,
    pub decoded_hash: Option<String>,
    /// Why the coded body was not decoded to its end.
    pub decode_error: Option<DecodeError>,
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
    /// The route pattern the request matched, e.g. `/v1/chat/completions`.
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
    /// BLAKE3 of the decoded request body, under a content coding.
    pub request_decoded_hash: Option<String>,
    pub response_body_hash: Option<String>,
    pub response_body_len: u64,
    /// BLAKE3 of the decoded response body, under a content coding.
    pub response_decoded_hash: Option<String>,
    pub response_id: Option<String>,
    pub response_model: Option<String>,
    pub finish_reason: Vec<wire::FinishReason>,
    pub usage: Option<serde_json::Value>,
    pub sse_events: Option<Vec<SseEventRecord>>,
    pub sse_done: Option<bool>,
    /// Both messages reached their end with no gap.
    pub complete: bool,
    /// The Wire Protocol's id ([`wire::WireProtocol::id`]).
    pub protocol: &'static str,
    /// Token counts from the usage the protocol reports, if it does.
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Protocol-specific fields, as one JSON object ([`wire::extra`]).
    pub extra: Option<serde_json::Value>,
    /// The protocol read the response: the whole body, or every frame.
    /// Diagnostics only, never written to the table.
    #[serde(skip)]
    pub response_parsed: bool,
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

    pub(crate) fn idx(self) -> usize {
        self as usize
    }
}

impl WorkunitRecord {
    /// `incomplete` on a gap or a message cut short, else `errored` when the
    /// response could not be read, else `ok`.
    pub fn outcome(&self) -> Outcome {
        if !self.complete {
            Outcome::Incomplete
        } else if !self.response_parsed {
            Outcome::Errored
        } else {
            Outcome::Ok
        }
    }
}

/// A window has closed: every packet in it has been pushed (spec §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowClose {
    pub window_start_ns: u64,
    pub window_ns: u64,
    /// Packets the capture reported dropped so far, when it reports them.
    pub capture_drops: Option<u64>,
}

/// Names the Request Workunit some stream bytes belong to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkunitTag {
    pub workunit_id: String,
    /// Capture time of the request's first byte.
    pub received_ts_ns: u64,
}

/// Stream bytes `[start, start + len)` of one direction and their bucket,
/// with the Request Workunit when the bucket is `workunit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub len: u64,
    pub bucket: Bucket,
    pub workunit: Option<Arc<WorkunitTag>>,
}

/// Receives everything the parser produces.
pub trait RecordSink {
    fn packet(&mut self, rec: &PacketRecord);
    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]);
    fn event(&mut self, rec: &EventRecord);
    fn flow(&mut self, rec: &FlowRecord);
    fn exchange(&mut self, rec: &ExchangeRecord);
    fn workunit(&mut self, rec: &WorkunitRecord);
    /// A DNS message in a UDP datagram, before its packet's record.
    fn dns(&mut self, rec: &DnsRecord);
    /// A TLS ClientHello, once all of it is in.
    fn tls(&mut self, rec: &TlsRecord);
    /// A Slice's covert-channel features, right after its Flow row.
    fn features(&mut self, rec: &FeaturesRecord);
    /// More bytes of a body, as hashed: chunked encoding removed, content
    /// coding kept. Only called when [`DecoderConfig::keep_bodies`] is set.
    fn body_data(&mut self, _key: &BodyKey, _data: &[u8]) {}
    /// The body is complete: keep it under `hash` (its `body_hash`), or drop it
    /// when `None` (a gap). Called once per body that had `body_data`, and
    /// for empty bodies.
    fn body_end(&mut self, _key: &BodyKey, _hash: Option<&str>) {}
    /// A window closed. Its Flow rows may still follow, once their bytes
    /// have buckets.
    fn window_closed(&mut self, _w: &WindowClose) {}
    /// A packet as captured, placed at `at` in L0, before its
    /// [`packet`](Self::packet) record.
    fn captured(&mut self, _pkt: &CapturedPacket, _at: PacketRef) {}
    /// The bucketed spans of one TCP direction covered by the Flow row that
    /// follows, in stream order.
    fn spans(&mut self, _flow: &FlowId, _dir: Dir, _spans: &[Span]) {}
}

/// Watches rows on their way to a sink, for counters and logs (spec §14).
/// It gets a shared look at a row and gives nothing back, and it holds no
/// sink: [`Observed`] forwards, so an observer can't change the output.
pub trait Observer {
    fn packet(&mut self, _rec: &PacketRecord) {}
    fn segment(&mut self, _rec: &SegmentRecord) {}
    fn event(&mut self, _rec: &EventRecord) {}
    fn flow(&mut self, _rec: &FlowRecord) {}
    fn exchange(&mut self, _rec: &ExchangeRecord) {}
    fn workunit(&mut self, _rec: &WorkunitRecord) {}
    fn window_closed(&mut self, _w: &WindowClose) {}
}

/// A [`RecordSink`] that shows each row to an [`Observer`], then hands it,
/// untouched, to the sink it wraps.
pub struct Observed<'a, O> {
    sink: &'a mut dyn RecordSink,
    observer: O,
}

impl<'a, O: Observer> Observed<'a, O> {
    pub fn new(sink: &'a mut dyn RecordSink, observer: O) -> Self {
        Observed { sink, observer }
    }
}

impl<O: Observer> RecordSink for Observed<'_, O> {
    fn packet(&mut self, rec: &PacketRecord) {
        self.observer.packet(rec);
        self.sink.packet(rec);
    }

    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        self.observer.segment(rec);
        self.sink.segment(rec, data);
    }

    fn event(&mut self, rec: &EventRecord) {
        self.observer.event(rec);
        self.sink.event(rec);
    }

    fn flow(&mut self, rec: &FlowRecord) {
        self.observer.flow(rec);
        self.sink.flow(rec);
    }

    fn exchange(&mut self, rec: &ExchangeRecord) {
        self.observer.exchange(rec);
        self.sink.exchange(rec);
    }

    fn workunit(&mut self, rec: &WorkunitRecord) {
        self.observer.workunit(rec);
        self.sink.workunit(rec);
    }

    fn dns(&mut self, rec: &DnsRecord) {
        self.sink.dns(rec);
    }

    fn tls(&mut self, rec: &TlsRecord) {
        self.sink.tls(rec);
    }

    fn features(&mut self, rec: &FeaturesRecord) {
        self.sink.features(rec);
    }

    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        self.sink.body_data(key, data);
    }

    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        self.sink.body_end(key, hash);
    }

    fn window_closed(&mut self, w: &WindowClose) {
        self.observer.window_closed(w);
        self.sink.window_closed(w);
    }

    fn captured(&mut self, pkt: &CapturedPacket, at: PacketRef) {
        self.sink.captured(pkt, at);
    }

    fn spans(&mut self, flow: &FlowId, dir: Dir, spans: &[Span]) {
        self.sink.spans(flow, dir, spans);
    }
}

pub struct Decoder<'a> {
    cfg: DecoderConfig,
    window_ns: u64,
    sink: &'a mut dyn RecordSink,
    flows: HashMap<FlowId, FlowState>,
    /// What each UDP Flow's datagrams added up to in the current Slice.
    udp: HashMap<FlowId, Tally>,
}

impl<'a> Decoder<'a> {
    /// A decoder for Slices of `window_ns`.
    pub fn new(cfg: DecoderConfig, window_ns: u64, sink: &'a mut dyn RecordSink) -> Self {
        Decoder {
            cfg,
            window_ns,
            sink,
            flows: HashMap::new(),
            udp: HashMap::new(),
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
        let at = PacketRef {
            window_start_ns: rec.window_start_ns,
            index: rec.index,
        };
        f.input(rec.dir, Piece::Data(data, rec.ts_ns, at), &self.cfg, self.sink);
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

    fn datagram(&mut self, d: &Datagram<'_>) {
        let tally = self.udp.entry(d.flow.clone()).or_default();
        match dns::decode(d) {
            Some(r) => {
                tally.add(&r);
                self.sink.dns(&r);
            }
            None => tally.other(),
        }
    }

    fn slice(&mut self, rec: &SliceRecord) {
        if rec.kind != FlowKind::Tcp {
            let tally = self.udp.remove(&rec.flow).unwrap_or_default();
            // Every payload byte is a fact (a whole DNS message), a gap (cut
            // by the capture) or unexplained.
            let bytes = |s: &crate::assembler::DirStats, fact: u64| Buckets {
                unexplained: s.payload_bytes - s.gap_bytes - fact,
                gap: s.gap_bytes,
                fact,
                ..Buckets::default()
            };
            self.sink.flow(&FlowRecord {
                slice: rec.clone(),
                verdict: Some(Verdict::Opaque),
                orig_bytes: bytes(&rec.orig_stats, tally.fact[0]),
                resp_bytes: bytes(&rec.resp_stats, tally.fact[1]),
                orig_desync: None,
                resp_desync: None,
            });
            FeaturesRecord::emit(rec, tally.finish(self.window_ns), None, self.sink);
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
    pub fn window_closed(&mut self, w: &WindowClose) {
        self.sink.window_closed(w);
    }

    /// Hands the sink a packet as captured, before the assembler sees it.
    pub fn captured(&mut self, pkt: &CapturedPacket, at: PacketRef) {
        self.sink.captured(pkt, at);
    }

    /// Flows with protocol state still held.
    pub fn open_flows(&self) -> usize {
        self.flows.len() + self.udp.len()
    }
}

/// Bytes (with their capture time and packet) or a gap delivered for one
/// direction.
enum Piece<B> {
    Data(B, u64, PacketRef),
    Gap(u64),
}

impl Piece<Vec<u8>> {
    fn borrowed(&self) -> Piece<&[u8]> {
        match self {
            Piece::Data(d, ts, at) => Piece::Data(d, *ts, *at),
            Piece::Gap(n) => Piece::Gap(*n),
        }
    }
}

enum Parser {
    H1(H1),
    H2(H2),
    Tls(ClientHello),
    Opaque,
}

impl Parser {
    fn feed(&mut self, piece: Piece<&[u8]>, out: &mut dyn Out) {
        match (self, piece) {
            (Parser::H1(p), Piece::Data(d, ts, _)) => p.data(d, ts, out),
            (Parser::H1(p), Piece::Gap(n)) => p.gap(n, out),
            (Parser::H2(p), Piece::Data(d, ts, _)) => p.data(d, ts, out),
            (Parser::H2(p), Piece::Gap(n)) => p.gap(n, out),
            (Parser::Tls(p), Piece::Data(d, ts, at)) => p.data(d, ts, at, out),
            (Parser::Tls(p), Piece::Gap(n)) => {
                p.stop(out);
                out.span(n, Lab::Gap);
            }
            (Parser::Opaque, Piece::Data(d, ..)) => out.span(d.len() as u64, Lab::Unexplained),
            (Parser::Opaque, Piece::Gap(n)) => out.span(n, Lab::Gap),
        }
    }

    fn finish(&mut self, out: &mut dyn Out) {
        match self {
            Parser::H1(p) => p.finish(out),
            Parser::H2(p) => p.finish(out),
            Parser::Tls(p) => p.stop(out),
            Parser::Opaque => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Label {
    Bucket(Bucket),
    /// Bucket `workunit`, in this Request Workunit.
    Workunit(Arc<WorkunitTag>),
    /// Belongs to an exchange whose bucket is not known yet.
    Exchange(u64),
}

impl Label {
    fn settled(bucket: Bucket, tag: &Option<Arc<WorkunitTag>>) -> Self {
        match (bucket, tag) {
            (Bucket::Workunit, Some(t)) => Label::Workunit(t.clone()),
            (b, _) => Label::Bucket(b),
        }
    }

    fn bucket(&self) -> Option<Bucket> {
        match self {
            Label::Bucket(b) => Some(*b),
            Label::Workunit(_) => Some(Bucket::Workunit),
            Label::Exchange(_) => None,
        }
    }
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

    fn resolve(&mut self, id: u64, label: &Label) {
        for (_, l) in self.spans.iter_mut() {
            if *l == Label::Exchange(id) {
                *l = label.clone();
            }
        }
    }

    /// Buckets for `[start, end)`, if every byte there has one.
    fn tally(&self, start: u64, end: u64) -> Option<Buckets> {
        if self.cursor < end {
            return None;
        }
        let mut out = Buckets::default();
        for (s, e, label) in self.within(start, end) {
            out.add(label.bucket()?, e - s);
        }
        Some(out)
    }

    /// The labeled pieces of `[start, end)`, clipped to it.
    fn within(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64, &Label)> {
        let mut at = self.base;
        self.spans
            .iter()
            .map_while(move |(len, label)| {
                let piece = (at.max(start), (at + len).min(end), label);
                let before = at;
                at += len;
                (before < end).then_some(piece)
            })
            .filter(|(s, e, _)| s < e)
    }

    /// The spans of `[start, end)`, which must all be settled.
    fn settled(&self, start: u64, end: u64, grpc: bool) -> Vec<Span> {
        self.within(start, end)
            .map(|(s, e, label)| {
                let (bucket, workunit) = match label {
                    _ if grpc => (Bucket::Unexplained, None),
                    Label::Workunit(t) => (Bucket::Workunit, Some(t.clone())),
                    l => (l.bucket().expect("settled"), None),
                };
                Span {
                    start: s,
                    len: e - s,
                    bucket,
                    workunit,
                }
            })
            .collect()
    }

    /// Forgets spans before `end`.
    fn prune(&mut self, end: u64) {
        while let Some((len, _)) = self.spans.front_mut() {
            if self.base + *len <= end {
                self.base += *len;
                self.spans.pop_front();
            } else {
                if self.base < end {
                    *len -= end - self.base;
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
    /// Over the wire bytes: the body hash.
    hasher: blake3::Hasher,
    /// Removes the content coding, when there is one. Everything below sees
    /// the decoded bytes.
    decoding: Option<Decoding>,
    /// Kept for JSON parsing, up to the configured limit.
    keep: bool,
    buf: Vec<u8>,
    over_limit: bool,
    /// Bytes held while the response's protocol is still open, to replay
    /// into its framer once it is known.
    pending: Option<Pending>,
    /// Still streaming to the sink (keep_bodies on, no gap yet).
    stored: bool,
}

enum Held {
    Data(Vec<u8>, u64),
    Gap(u64),
}

#[derive(Default)]
struct Pending {
    pieces: Vec<Held>,
    bytes: usize,
    /// Passed the size cap, so it cannot be replayed.
    over_limit: bool,
}

impl Body {
    fn new(keep: bool, decoding: Option<Decoding>) -> Self {
        Body {
            len: 0,
            gap: 0,
            hasher: blake3::Hasher::new(),
            decoding,
            keep,
            buf: Vec::new(),
            over_limit: false,
            pending: None,
            stored: false,
        }
    }

    /// More wire bytes; returns them as the protocol reads them, decoded.
    fn push<'d>(&mut self, data: &'d [u8], ts: u64, max: usize) -> Cow<'d, [u8]> {
        self.len += data.len() as u64;
        self.hasher.update(data);
        let plain = match &mut self.decoding {
            None => Cow::Borrowed(data),
            Some(d) => Cow::Owned(d.push(data)),
        };
        self.take(&plain, ts, max);
        plain
    }

    /// The body reached its declared end: the last decoded bytes.
    fn end(&mut self, ts: u64, max: usize) -> Vec<u8> {
        let Some(d) = &mut self.decoding else {
            return Vec::new();
        };
        let tail = d.finish();
        self.take(&tail, ts, max);
        tail
    }

    /// Keeps decoded bytes for JSON parsing and replay.
    fn take(&mut self, data: &[u8], ts: u64, max: usize) {
        if self.keep && !self.over_limit {
            if self.buf.len() + data.len() <= max {
                self.buf.extend_from_slice(data);
            } else {
                self.over_limit = true;
                self.buf = Vec::new();
            }
        }
        if let Some(p) = &mut self.pending {
            if p.over_limit || data.is_empty() {
            } else if p.bytes + data.len() <= max {
                p.bytes += data.len();
                p.pieces.push(Held::Data(data.to_vec(), ts));
            } else {
                *p = Pending {
                    over_limit: true,
                    ..Pending::default()
                };
            }
        }
    }

    fn gap(&mut self, len: u64) {
        self.len += len;
        self.gap += len;
        if let Some(d) = &mut self.decoding {
            d.gap();
        }
        if let Some(p) = &mut self.pending {
            p.pieces.push(Held::Gap(len));
        }
    }

    fn hash(&self) -> Option<String> {
        (self.gap == 0).then(|| mh::name(&self.hasher.finalize()))
    }

    fn decoded_hash(&self) -> Option<String> {
        self.decoding.as_ref().and_then(Decoding::hash)
    }

    /// Every byte the protocol reads is here: no content coding, or one
    /// decoded to its end.
    fn plain(&self) -> bool {
        self.decoding.as_ref().is_none_or(Decoding::done)
    }

    /// Decoding has not stopped on bad bytes, a cap or an unknown coding.
    fn decodable(&self) -> bool {
        self.decoding.as_ref().is_none_or(|d| !d.failed())
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
            decoded_len: self.body.decoding.as_ref().and_then(Decoding::decoded_len),
            decoded_hash: self.body.decoded_hash(),
            decode_error: self.body.decoding.as_ref().and_then(Decoding::error),
            complete: self.complete && self.body.gap == 0,
        }
    }
}

struct Exchange {
    seq: u64,
    h2_stream: Option<u32>,
    req: Option<Msg>,
    resp: Option<Msg>,
    interim: u32,
    reset: bool,
    /// The Wire Protocols that claim the request, best first.
    claims: Vec<Claim>,
    /// The claim that read the request body, and what it read.
    owner: Option<(Claim, wire::Request)>,
    /// Reads the response once its protocol is known.
    reader: Option<Reader>,
    bucket: Option<Bucket>,
    /// Set once the bucket is `workunit`.
    tag: Option<Arc<WorkunitTag>>,
}

impl Exchange {
    /// Starts reading the response once both its head and its protocol are
    /// known, replaying any body bytes that arrived before.
    fn start_reader(&mut self) {
        if self.reader.is_some() {
            return;
        }
        let Some(resp) = &mut self.resp else { return };
        if self.bucket.is_some_and(|b| b != Bucket::Workunit) {
            resp.body.pending = None;
            return;
        }
        let Some((claim, request)) = &self.owner else {
            return;
        };
        let (p, endpoint) = (claim.protocol, claim.endpoint);
        let pending = resp.body.pending.take();
        let Some(framing) = p.response_framing(endpoint, request, resp.head.media_type().as_deref()) else {
            return;
        };
        // A coding that cannot be decoded hides the frames.
        let framer = (framing.is_stream() && resp.body.decodable())
            .then(|| Framer::new(framing))
            .flatten();
        let mut reader = Reader {
            framing,
            framer,
            decoder: p.decoder(endpoint, request),
            events: Vec::new(),
            lost: 0,
        };
        resp.body.keep = framing == Framing::Json;
        if let Some(pending) = pending {
            if pending.over_limit {
                resp.body.over_limit |= resp.body.keep;
                reader.lost += 1;
            }
            for piece in pending.pieces {
                match piece {
                    Held::Data(d, ts) => {
                        if resp.body.keep {
                            resp.body.buf.extend_from_slice(&d);
                        }
                        reader.push(&d, ts);
                    }
                    Held::Gap(n) => reader.gap(n),
                }
            }
        }
        if resp.done && resp.complete {
            reader.finish(resp.last_ts);
        }
        self.reader = Some(reader);
    }
}

/// A response on its way through its protocol's framer and decoder.
struct Reader {
    framing: Framing,
    /// `None` for a whole JSON body, or a stream under a coding that
    /// cannot be decoded.
    framer: Option<Framer>,
    decoder: Box<dyn ResponseDecoder>,
    /// SSE events, for the record.
    events: Vec<SseEventRecord>,
    /// Bytes that could not be replayed (over the size cap).
    lost: u64,
}

impl Reader {
    fn push(&mut self, data: &[u8], ts: u64) {
        let Some(f) = self.framer.as_mut().filter(|_| !data.is_empty()) else {
            return;
        };
        let mut out = Vec::new();
        f.push(data, ts, &mut out);
        self.take(out);
    }

    fn gap(&mut self, len: u64) {
        if let Some(f) = &mut self.framer {
            f.gap(len);
        }
    }

    fn finish(&mut self, ts: u64) {
        let Some(f) = &mut self.framer else { return };
        let mut out = Vec::new();
        f.finish(ts, &mut out);
        self.take(out);
    }

    fn take(&mut self, frames: Vec<Framed>) {
        for e in frames {
            if self.framing == Framing::Sse {
                self.events.push(SseEventRecord {
                    body_off: e.body_off,
                    len: e.len,
                    ts_ns: e.ts_ns,
                });
            }
            self.decoder.frame(e.frame());
        }
    }

    /// Frames the protocol never saw.
    fn lost(&self) -> u64 {
        self.lost + self.framer.as_ref().map_or(0, Framer::lost)
    }
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
    /// The ClientHello's features, until the Slice of its first byte.
    hello: Option<TlsFeatures>,
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
            hello: None,
        }
    }

    fn input(&mut self, dir: Dir, piece: Piece<&[u8]>, cfg: &DecoderConfig, sink: &mut dyn RecordSink) {
        if self.parsers.is_some() {
            return self.feed(dir, piece, cfg, sink);
        }
        let owned = match piece {
            Piece::Data(d, ts, at) => {
                self.detect_bytes[dir.idx()] += d.len();
                Piece::Data(d.to_vec(), ts, at)
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
                Piece::Data(d, ..) => out.extend_from_slice(d),
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
            Detect::Tls => (
                Verdict::Tls,
                dir,
                [
                    Parser::Tls(ClientHello::new(self.id.clone(), dir)),
                    Parser::Opaque,
                ],
            ),
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
            for (dir, (s, e)) in [(Dir::Orig, (os, oe)), (Dir::Resp, (rs, re))] {
                if s < e {
                    sink.spans(&self.id, dir, &self.ledgers[dir.idx()].settled(s, e, self.grpc));
                }
            }
            self.ledgers[0].prune(oe);
            self.ledgers[1].prune(re);
            let verdict = if self.grpc {
                Some(Verdict::Grpc)
            } else {
                self.verdict
            };
            let client = [(os, oe), (rs, re)][self.client.idx()];
            let hello = if client.0 < client.1 {
                self.hello.take()
            } else {
                None
            };
            let row = FlowRecord {
                slice,
                verdict,
                orig_bytes: ob,
                resp_bytes: rb,
                orig_desync: self.dead[0],
                resp_desync: self.dead[1],
            };
            sink.flow(&row);
            FeaturesRecord::emit(&row.slice, None, hello, sink);
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
                claims: Vec::new(),
                owner: None,
                reader: None,
                bucket: None,
                tag: None,
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
                if b == Bucket::Workunit {
                    let req = ex.req.as_ref().expect("a Workunit has a request");
                    ex.tag = Some(Arc::new(WorkunitTag {
                        workunit_id: workunit_id(&self.id, req),
                        received_ts_ns: req.first_ts,
                    }));
                }
                let label = Label::settled(b, &ex.tag);
                for l in &mut self.ledgers {
                    l.resolve(id, &label);
                }
            }
        }
        ex.start_reader();
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
        let workunit_id = ex.tag.as_ref().map(|t| t.workunit_id.clone());
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
            if m.body.over_limit {
                tracing::warn!(
                    flow = %self.id,
                    exchange = ex.seq,
                    dir = %m.dir.as_str(),
                    body_bytes = m.body.len,
                    "body over the size cap: hashed and counted, not read as JSON"
                );
            }
            if let Some(e @ (DecodeError::OverCap | DecodeError::OverRatio)) =
                m.body.decoding.as_ref().and_then(Decoding::error)
            {
                tracing::warn!(
                    flow = %self.id,
                    exchange = ex.seq,
                    dir = %m.dir.as_str(),
                    body_bytes = m.body.len,
                    decoded_bytes = m.body.decoding.as_ref().and_then(Decoding::decoded_len).unwrap_or(0),
                    cap = e.as_str(),
                    "decoded body over the cap: hashed and counted, decoding stopped"
                );
            }
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
        let (claim, request) = ex.owner.take().expect("a Workunit has an owner");
        let reader = ex.reader.take();
        let framing = reader.as_ref().map(|r| r.framing);
        // A JSON response is read whole; a stream was read frame by frame.
        let streamed = reader.as_ref().is_some_and(|r| r.framer.is_some());
        let read = (streamed && resp.body.decodable())
            || (framing == Some(Framing::Json)
                && resp.done
                && resp.body.gap == 0
                && !resp.body.over_limit
                && resp.body.plain());
        let (response, events, lost) = match reader {
            Some(mut r) => {
                if !streamed && read {
                    r.decoder.frame(Frame {
                        event: None,
                        data: &resp.body.buf,
                    });
                }
                let lost = r.lost();
                (r.decoder.finish(), std::mem::take(&mut r.events), lost)
            }
            None => (wire::Response::default(), Vec::new(), 0),
        };
        let sse = streamed && framing == Some(Framing::Sse);
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
            endpoint: claim.endpoint,
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
            request_decoded_hash: req.body.decoded_hash(),
            response_body_hash: resp.body.hash(),
            response_body_len: resp.body.len,
            response_decoded_hash: resp.body.decoded_hash(),
            response_id: response.id,
            response_model: response.model,
            finish_reason: response.finish_reason,
            usage: response.usage,
            sse_events: sse.then_some(events),
            sse_done: sse.then_some(response.done),
            complete,
            protocol: claim.protocol.id(),
            input_tokens: response.input_tokens,
            output_tokens: response.output_tokens,
            extra: response.extra,
            response_parsed: read && response.unreadable == 0 && lost == 0,
        });
    }

    fn settle_all(&mut self, sink: &mut dyn RecordSink) {
        let ids: Vec<u64> = self.exchanges.keys().copied().collect();
        for id in ids {
            self.settle(id, sink);
        }
    }
}

/// `blake3(flow_id ‖ 0x00 ‖ request direction ‖ request start offset as u64
/// big-endian)`: unique and stable across re-runs, not a content hash
/// (spec §6).
fn workunit_id(flow: &FlowId, req: &Msg) -> String {
    let mut h = blake3::Hasher::new();
    h.update(flow.as_str().as_bytes());
    h.update(&[0, req.dir.idx() as u8]);
    h.update(&req.start.to_be_bytes());
    mh::name(&h.finalize())
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
    if ex.claims.is_empty() {
        return Some(Bucket::HttpOther);
    }
    if ex.owner.is_none() {
        if !req.done {
            return (req_closed || ex.reset).then_some(Bucket::HttpOther);
        }
        let readable = req.complete && req.body.gap == 0 && !req.body.over_limit && req.body.plain();
        // Body sniffing: the first claim that reads the body owns it.
        let owner = readable
            .then(|| {
                ex.claims
                    .iter()
                    .find_map(|c| c.protocol.request(c.endpoint, &req.body.buf).map(|r| (*c, r)))
            })
            .flatten();
        match owner {
            Some(o) => ex.owner = Some(o),
            None => return Some(Bucket::HttpOther),
        }
    }
    let (claim, request) = ex.owner.as_ref().expect("set above");
    match &ex.resp {
        Some(resp) => Some(
            match claim
                .protocol
                .response_framing(claim.endpoint, request, resp.head.media_type().as_deref())
            {
                Some(_) => Bucket::Workunit,
                None => Bucket::HttpOther,
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
        let encoding = Encoding::of(head.header_str("content-encoding").as_deref());
        let decoding = Decoding::of(encoding, self.cfg.decode_limits);
        Msg {
            dir: self.dir,
            start,
            end: None,
            first_ts: ts,
            last_ts: ts,
            head,
            body: Body {
                stored: self.cfg.keep_bodies,
                ..Body::new(keep, decoding)
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
    fn client_hello(&mut self, rec: &TlsRecord) {
        self.f.hello = Some(rec.features());
        self.sink.tls(rec);
    }

    fn span(&mut self, len: u64, lab: Lab) {
        let label = match lab {
            Lab::Fact => Label::Bucket(Bucket::Fact),
            Lab::Framing => Label::Bucket(Bucket::Framing),
            Lab::Other => Label::Bucket(Bucket::HttpOther),
            Lab::Unexplained => Label::Bucket(Bucket::Unexplained),
            Lab::Gap => Label::Bucket(Bucket::Gap),
            Lab::Msg(s) => match self.f.exchange_of(self.dir, s) {
                Some(id) => {
                    let ex = &self.f.exchanges[&id];
                    match ex.bucket {
                        Some(b) => Label::settled(b, &ex.tag),
                        None => Label::Exchange(id),
                    }
                }
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
            let claims = self.cfg.protocols.claims(method, target, &head.headers);
            let id = self.f.new_exchange(h2_stream);
            if !h2 {
                self.f.current[self.dir.idx()] = Some(id);
                self.f.awaiting.push_back(id);
            }
            let msg = self.new_msg(start, ts, head, !claims.is_empty());
            let ex = self.f.exchanges.get_mut(&id).expect("new");
            ex.claims = claims;
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
        let ex = &self.f.exchanges[&id];
        // Until a protocol owns the request, hold the body to replay.
        let hold = !ex.claims.is_empty() && ex.owner.is_none() && ex.bucket.is_none();
        let msg = (!interim).then(|| {
            let mut m = self.new_msg(start, ts, head, false);
            m.body.pending = hold.then(Pending::default);
            m
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
        let plain = m.body.push(data, ts, self.cfg.max_body);
        m.last_ts = ts;
        if m.body.stored && !data.is_empty() {
            let key = BodyKey {
                flow: self.f.id.clone(),
                exchange: id,
                dir: self.dir,
            };
            self.sink.body_data(&key, data);
        }
        if !client {
            if let Some(r) = &mut ex.reader {
                r.push(&plain, ts);
            }
        }
    }

    fn body_gap(&mut self, stream: u32, len: u64) {
        let Some(id) = self.f.exchange_of(self.dir, stream) else {
            return;
        };
        let flow = self.f.id.clone();
        let dir = self.dir;
        if !self.is_client() {
            if let Some(r) = self.f.exchanges.get_mut(&id).and_then(|e| e.reader.as_mut()) {
                r.gap(len);
            }
        }
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
        let max = self.cfg.max_body;
        let mut tail = Vec::new();
        if let Some(m) = self.msg(stream) {
            m.end = Some(end);
            m.last_ts = m.last_ts.max(ts);
            m.done = true;
            m.complete = complete;
            if complete {
                tail = m.body.end(ts, max);
            }
        }
        if complete && !self.is_client() {
            if let Some(r) = self.f.exchanges.get_mut(&id).and_then(|e| e.reader.as_mut()) {
                r.push(&tail, ts);
                r.finish(ts);
            }
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
        l.resolve(1, &Label::Bucket(Bucket::Workunit));
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
            fn dns(&mut self, _: &DnsRecord) {}
            fn tls(&mut self, _: &TlsRecord) {}
            fn features(&mut self, _: &FeaturesRecord) {}
        }
        let mut nop = Nop;
        assert_eq!(
            Decoder::new(DecoderConfig::default(), 1, &mut nop).open_flows(),
            0
        );
    }
}
