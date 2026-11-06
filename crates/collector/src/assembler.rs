//! Flow assembly (L1, spec §4).
//!
//! Turns windowed packets into Flows: TCP reassembled per direction with a
//! stream offset → (chunk, packet, offset in packet) map, UDP as datagrams,
//! other IP protocols counted in bytes. Flow state carries across windows
//! and chunks. Every decision depends only on packet order and capture
//! timestamps, so the output is deterministic.

use std::collections::HashMap;

use serde::Serialize;

use crate::dns::Datagram;
use crate::flow::{Dir, Endpoint, FlowId, FlowKind, Tuple};
use crate::mh;
use crate::net::{self, Decoded, Transport, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::source::{CapturedPacket, LinkId};
use crate::tcp::{Emit, TcpDir};
use crate::window::PacketRef;

const SECOND: u64 = 1_000_000_000;

#[derive(Clone, Debug)]
pub struct AssemblerConfig {
    /// A TCP tuple idle this long starts a new Flow generation.
    pub tcp_idle_ns: u64,
    /// A UDP tuple idle this long starts a new Flow generation.
    pub udp_idle_ns: u64,
    /// Same, for other IP protocols.
    pub other_idle_ns: u64,
    /// A closed (FIN both ways, or RST) TCP Flow is dropped after this long
    /// without packets. Late packets before that still join it.
    pub closed_linger_ns: u64,
    /// Out-of-order bytes held per direction before the hole is declared a gap.
    pub max_pending_bytes: u64,
    /// Delivered bytes kept per direction to compare retransmits against.
    pub retransmit_window_bytes: u64,
}

impl Default for AssemblerConfig {
    fn default() -> Self {
        AssemblerConfig {
            tcp_idle_ns: 300 * SECOND,
            udp_idle_ns: 60 * SECOND,
            other_idle_ns: 60 * SECOND,
            closed_linger_ns: 30 * SECOND,
            max_pending_bytes: 4 << 20,
            retransmit_window_bytes: 1 << 20,
        }
    }
}

impl AssemblerConfig {
    fn idle_ns(&self, kind: FlowKind) -> u64 {
        match kind {
            FlowKind::Tcp => self.tcp_idle_ns,
            FlowKind::Udp => self.udp_idle_ns,
            FlowKind::Ip(_) => self.other_idle_ns,
        }
    }
}

/// One captured packet (the future `packets` table, spec §8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PacketRecord {
    pub link: LinkId,
    pub window_start_ns: u64,
    pub index: u32,
    pub ts_ns: u64,
    pub cap_len: u32,
    pub orig_len: u32,
    /// BLAKE3 of the captured bytes, as a multihash name (spec §6). The
    /// chunk index commits to these in a Merkle root.
    pub hash: String,
    pub flow: Option<FlowId>,
    pub dir: Option<Dir>,
    pub tcp_flags: Option<String>,
    /// Stream offset of the first payload byte (TCP). Negative before the
    /// stream's start.
    pub stream_off: Option<i64>,
    /// Transport payload length on the wire.
    pub payload_len: Option<u32>,
    /// Why the packet has no Flow (`not_ip`, `truncated_header`, …).
    pub note: Option<&'static str>,
}

/// Stream bytes `[stream_off, stream_off + len)` of one direction are bytes
/// `[pkt_off, pkt_off + len)` of packet `index` in the chunk of window
/// `window_start_ns` (the stream offset map, spec §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SegmentRecord {
    pub flow: FlowId,
    pub dir: Dir,
    pub stream_off: u64,
    pub len: u64,
    pub window_start_ns: u64,
    pub index: u32,
    pub pkt_off: u32,
    /// Capture time of that packet.
    pub ts_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Bytes the receiver acknowledged but the Tap never saw.
    GapLost,
    /// Bytes cut off by the capture's snap length.
    GapTruncated,
    /// A hole still open when the Flow ended or the input ran out.
    GapUnfilled,
    /// A hole given up on because too many bytes were waiting behind it.
    GapBufferLimit,
    /// A second copy of stream bytes that differs from the first. The first
    /// copy is kept; this may be an attack on the reassembler.
    RetransmitDiffers,
    /// Bytes before stream offset 0 of a Flow first seen mid-stream.
    BeforeStreamStart,
    /// A SYN whose sequence number disagrees with the one already seen.
    SynChanged,
    /// A FIN at a different stream offset than an earlier FIN.
    FinChanged,
    /// Bytes past the FIN.
    DataAfterFin,
    /// An IP fragment; v1 does not reassemble IP fragments.
    IpFragment,
}

impl EventKind {
    /// Whether this event stands for stream bytes that were never captured.
    pub fn is_gap(self) -> bool {
        matches!(
            self,
            EventKind::GapLost | EventKind::GapTruncated | EventKind::GapUnfilled | EventKind::GapBufferLimit
        )
    }
}

/// A gap or anomaly in one Flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventRecord {
    pub flow: FlowId,
    pub dir: Option<Dir>,
    pub kind: EventKind,
    pub stream_off: Option<u64>,
    pub len: u64,
    /// The packet that caused it, when one did.
    pub window_start_ns: Option<u64>,
    pub index: Option<u32>,
}

/// Per-direction counters for one Slice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DirStats {
    pub packets: u64,
    /// Sum of on-the-wire packet lengths.
    pub wire_bytes: u64,
    /// Sum of transport payload lengths on the wire.
    pub payload_bytes: u64,
    /// TCP: the stream range `[stream_start, stream_end)` this Slice covers,
    /// gaps included.
    pub stream_start: Option<u64>,
    pub stream_end: Option<u64>,
    pub gap_bytes: u64,
    pub retransmit_bytes: u64,
    pub retransmit_diff_bytes: u64,
    pub datagrams: u64,
    /// The Slice hash chain of this direction (spec §6), as a multihash name.
    /// Set on every Slice row; gap bytes are left out of it.
    pub slice_hash: Option<String>,
}

/// One Flow during one window (the future `flows` table, spec §4 and §8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SliceRecord {
    pub window_start_ns: u64,
    pub flow: FlowId,
    pub link: LinkId,
    pub kind: FlowKind,
    pub generation: u32,
    pub orig: Endpoint,
    pub resp: Endpoint,
    pub first_ts_ns: u64,
    pub slice_first_ts_ns: Option<u64>,
    pub slice_last_ts_ns: Option<u64>,
    pub mid_stream_start: bool,
    pub syn: bool,
    pub syn_ack: bool,
    pub fin_orig: bool,
    pub fin_resp: bool,
    pub rst: bool,
    pub ended: bool,
    pub orig_stats: DirStats,
    pub resp_stats: DirStats,
}

/// Receives the assembler's output.
pub trait FlowSink {
    fn packet(&mut self, rec: &PacketRecord);
    /// Stream bytes delivered in order, with where they came from.
    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]);
    fn event(&mut self, rec: &EventRecord);
    /// A UDP datagram, before its packet's record.
    fn datagram(&mut self, _d: &Datagram<'_>) {}
    fn slice(&mut self, rec: &SliceRecord);
    /// The Flow ended: no more bytes will come for it. `slice_pending` says
    /// whether one last Slice of it will still be emitted.
    fn flow_end(&mut self, _flow: &FlowId, _slice_pending: bool) {}
}

/// One direction's Slice hash chain (spec §6):
/// `slice_hash[n] = blake3(slice_hash[n-1] ‖ flow_id ‖ 0x00 ‖ dir ‖ bytes)`,
/// where `dir` is `0` (orig) or `1` (resp) and `bytes` are the stream bytes
/// delivered in Slice `n`, gaps left out. UDP and other IP protocols have no
/// stream: each datagram's captured payload goes in with its length as a
/// u32 big-endian prefix, so datagram boundaries are committed too.
/// `slice_hash[-1]` is [`genesis`].
pub(crate) struct Chain {
    pub hasher: blake3::Hasher,
}

impl Chain {
    fn start(prev: &blake3::Hash, flow: &FlowId, dir: Dir) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev.as_bytes());
        hasher.update(flow.as_str().as_bytes());
        hasher.update(&[0, dir.idx() as u8]);
        Chain { hasher }
    }

    /// Ends the Slice: returns its hash and starts the next one.
    fn advance(&mut self, flow: &FlowId, dir: Dir) -> blake3::Hash {
        let h = self.hasher.finalize();
        *self = Chain::start(&h, flow, dir);
        h
    }
}

/// The Flow's first-seen record, which seeds both chains:
/// `blake3(flow_id ‖ 0x00 ‖ first_ts_ns as u64 big-endian)`.
pub fn genesis(flow: &FlowId, first_ts_ns: u64) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    h.update(flow.as_str().as_bytes());
    h.update(&[0]);
    h.update(&first_ts_ns.to_be_bytes());
    h.finalize()
}

struct FlowState {
    id: FlowId,
    tuple: Tuple,
    generation: u32,
    orig: Endpoint,
    resp: Endpoint,
    first_ts_ns: u64,
    last_ts_ns: u64,
    mid_stream_start: bool,
    syn: bool,
    syn_ack: bool,
    fin: [bool; 2],
    rst: bool,
    ended: bool,
    tcp: [TcpDir; 2],
    stats: [DirStats; 2],
    chains: [Chain; 2],
    slice_first_ts_ns: Option<u64>,
    slice_last_ts_ns: Option<u64>,
    active: bool,
}

impl FlowState {
    fn closed(&self) -> bool {
        self.rst || (self.fin[0] && self.fin[1])
    }

    fn expired(&self, now_ns: u64, cfg: &AssemblerConfig) -> bool {
        let idle = now_ns.saturating_sub(self.last_ts_ns);
        idle > cfg.idle_ns(self.tuple.kind) || (self.closed() && idle > cfg.closed_linger_ns)
    }

    /// Whether a SYN (without ACK) from `src` starts a new connection on
    /// this tuple rather than repeating this Flow's own SYN.
    fn is_new_syn(&self, src: Endpoint, seq: u32) -> bool {
        let orig = &self.tcp[Dir::Orig.idx()];
        let same = orig.syn_isn == Some(seq)
            || (orig.syn_isn.is_none() && orig.base_seq == Some(seq.wrapping_add(1)));
        !(src == self.orig && same)
    }

    fn dir_of(&self, src: Endpoint) -> Dir {
        if src == self.orig {
            Dir::Orig
        } else {
            Dir::Resp
        }
    }

    /// Ends the Flow: every remaining hole becomes a gap.
    fn end(&mut self, sink: &mut dyn FlowSink) {
        if self.tuple.kind == FlowKind::Tcp {
            for dir in [Dir::Orig, Dir::Resp] {
                let mut e = Emit {
                    sink: &mut *sink,
                    flow: &self.id,
                    dir,
                    stats: &mut self.stats[dir.idx()],
                    hash: &mut self.chains[dir.idx()].hasher,
                };
                if self.tcp[dir.idx()].flush(&mut e) {
                    self.active = true;
                }
            }
        }
        self.ended = true;
        sink.flow_end(&self.id, self.active);
    }

    fn take_slice(&mut self, window_start_ns: u64) -> SliceRecord {
        let mut stats = std::mem::take(&mut self.stats);
        for (dir, s) in [Dir::Orig, Dir::Resp].into_iter().zip(stats.iter_mut()) {
            let h = self.chains[dir.idx()].advance(&self.id, dir);
            s.slice_hash = Some(mh::name(&h));
        }
        if self.tuple.kind == FlowKind::Tcp {
            for (s, t) in stats.iter_mut().zip(self.tcp.iter_mut()) {
                s.stream_start = Some(t.slice_start);
                s.stream_end = Some(t.delivered);
                t.slice_start = t.delivered;
            }
        }
        let [orig_stats, resp_stats] = stats;
        let rec = SliceRecord {
            window_start_ns,
            flow: self.id.clone(),
            link: self.tuple.link.clone(),
            kind: self.tuple.kind,
            generation: self.generation,
            orig: self.orig,
            resp: self.resp,
            first_ts_ns: self.first_ts_ns,
            slice_first_ts_ns: self.slice_first_ts_ns.take(),
            slice_last_ts_ns: self.slice_last_ts_ns.take(),
            mid_stream_start: self.mid_stream_start,
            syn: self.syn,
            syn_ack: self.syn_ack,
            fin_orig: self.fin[0],
            fin_resp: self.fin[1],
            rst: self.rst,
            ended: self.ended,
            orig_stats,
            resp_stats,
        };
        self.active = false;
        rec
    }
}

fn pair<T>(arr: &mut [T; 2], dir: Dir) -> (&mut T, &mut T) {
    let [a, b] = arr;
    match dir {
        Dir::Orig => (a, b),
        Dir::Resp => (b, a),
    }
}

/// Assembles Flows from packets in capture order.
pub struct Assembler {
    cfg: AssemblerConfig,
    flows: HashMap<Tuple, FlowState>,
    /// Next generation per tuple. Kept after a Flow ends so ids stay unique.
    generations: HashMap<Tuple, u32>,
    /// Flows ended during the current window, waiting for their last Slice.
    ended: Vec<FlowState>,
}

impl Assembler {
    pub fn new(cfg: AssemblerConfig) -> Self {
        Assembler {
            cfg,
            flows: HashMap::new(),
            generations: HashMap::new(),
            ended: Vec::new(),
        }
    }

    /// Number of Flows currently open.
    pub fn open_flows(&self) -> usize {
        self.flows.len()
    }

    /// Processes one packet, placed at `at` in L0.
    pub fn push(&mut self, pkt: &CapturedPacket, at: PacketRef, sink: &mut dyn FlowSink) {
        let mut rec = PacketRecord {
            link: pkt.link_id.clone(),
            window_start_ns: at.window_start_ns,
            index: at.index,
            ts_ns: pkt.ts_ns,
            cap_len: pkt.data.len() as u32,
            orig_len: pkt.orig_len,
            hash: mh::of(&pkt.data),
            flow: None,
            dir: None,
            tcp_flags: None,
            stream_off: None,
            payload_len: None,
            note: None,
        };
        let d = match net::decode(pkt.link_type, &pkt.data) {
            Ok(d) => d,
            Err(err) => {
                rec.note = Some(err.code());
                sink.packet(&rec);
                return;
            }
        };
        let (sport, dport, tcp) = match d.transport {
            Transport::Tcp(t) => (t.src_port, t.dst_port, Some(t)),
            Transport::Udp { src_port, dst_port } => (src_port, dst_port, None),
            Transport::Other => (0, 0, None),
        };
        let src = Endpoint {
            ip: d.src,
            port: sport,
        };
        let dst = Endpoint {
            ip: d.dst,
            port: dport,
        };
        let kind = FlowKind::from_proto(d.proto, d.fragment);
        let tuple = Tuple::new(pkt.link_id.clone(), kind, src, dst);
        let bare_syn = tcp.filter(|t| t.has(TCP_SYN) && !t.has(TCP_ACK));

        if let Some(f) = self.flows.get(&tuple) {
            let idle = pkt.ts_ns.saturating_sub(f.last_ts_ns) > self.cfg.idle_ns(kind);
            let reused = bare_syn.is_some_and(|t| f.is_new_syn(src, t.seq));
            if idle || reused {
                let mut old = self.flows.remove(&tuple).expect("present");
                old.end(sink);
                self.ended.push(old);
            }
        }

        let flow = match self.flows.get_mut(&tuple) {
            Some(f) => f,
            None => {
                let next = self.generations.entry(tuple.clone()).or_insert(0);
                let generation = *next;
                *next += 1;
                let syn_ack = tcp.is_some_and(|t| t.has(TCP_SYN) && t.has(TCP_ACK));
                let (orig, resp) = if syn_ack { (dst, src) } else { (src, dst) };
                let max_pending = self.cfg.max_pending_bytes;
                let max_recent = self.cfg.retransmit_window_bytes;
                let id = FlowId::new(&tuple, generation);
                let seed = genesis(&id, pkt.ts_ns);
                let state = FlowState {
                    chains: [
                        Chain::start(&seed, &id, Dir::Orig),
                        Chain::start(&seed, &id, Dir::Resp),
                    ],
                    id,
                    tuple: tuple.clone(),
                    generation,
                    orig,
                    resp,
                    first_ts_ns: pkt.ts_ns,
                    last_ts_ns: pkt.ts_ns,
                    mid_stream_start: tcp.is_some_and(|t| !t.has(TCP_SYN)),
                    syn: false,
                    syn_ack: false,
                    fin: [false; 2],
                    rst: false,
                    ended: false,
                    tcp: [
                        TcpDir::new(max_pending, max_recent),
                        TcpDir::new(max_pending, max_recent),
                    ],
                    stats: Default::default(),
                    slice_first_ts_ns: None,
                    slice_last_ts_ns: None,
                    active: false,
                };
                self.flows.entry(tuple).or_insert(state)
            }
        };

        let dir = flow.dir_of(src);
        flow.last_ts_ns = flow.last_ts_ns.max(pkt.ts_ns);
        flow.slice_first_ts_ns.get_or_insert(pkt.ts_ns);
        flow.slice_last_ts_ns = Some(pkt.ts_ns);
        flow.active = true;
        {
            let s = &mut flow.stats[dir.idx()];
            s.packets += 1;
            s.wire_bytes += u64::from(pkt.orig_len);
            s.payload_bytes += u64::from(d.payload_len);
        }
        rec.flow = Some(flow.id.clone());
        rec.dir = Some(dir);
        rec.payload_len = Some(d.payload_len);

        match (kind, tcp) {
            (FlowKind::Tcp, Some(t)) => {
                rec.tcp_flags = Some(t.flag_letters());
                rec.stream_off = Some(tcp_packet(flow, dir, &t, &d, at, pkt.ts_ns, sink));
            }
            (FlowKind::Udp, _) => {
                let s = &mut flow.stats[dir.idx()];
                s.datagrams += 1;
                s.gap_bytes += u64::from(d.payload_len) - d.payload.len() as u64;
                datagram(&mut flow.chains[dir.idx()], d.payload);
                sink.datagram(&Datagram {
                    flow: &flow.id,
                    dir,
                    at,
                    ts_ns: pkt.ts_ns,
                    payload: d.payload,
                    payload_len: d.payload_len,
                });
            }
            _ => {
                datagram(&mut flow.chains[dir.idx()], d.payload);
                if d.fragment {
                    sink.event(&EventRecord {
                        flow: flow.id.clone(),
                        dir: Some(dir),
                        kind: EventKind::IpFragment,
                        stream_off: None,
                        len: u64::from(d.payload_len),
                        window_start_ns: Some(at.window_start_ns),
                        index: Some(at.index),
                    });
                }
            }
        }
        sink.packet(&rec);
    }

    /// Closes the window starting at `window_start_ns`: ends Flows that are
    /// idle (or closed and lingering) as of `now_ns`, then emits one Slice
    /// per Flow active in the window, sorted by Flow id.
    pub fn close_window(&mut self, window_start_ns: u64, now_ns: u64, sink: &mut dyn FlowSink) {
        let mut expired: Vec<Tuple> = self
            .flows
            .iter()
            .filter(|(_, f)| f.expired(now_ns, &self.cfg))
            .map(|(t, _)| t.clone())
            .collect();
        expired.sort_by(|a, b| self.flows[a].id.cmp(&self.flows[b].id));
        for tuple in expired {
            let mut f = self.flows.remove(&tuple).expect("present");
            f.end(sink);
            self.ended.push(f);
        }

        let mut active: Vec<&mut FlowState> = self
            .flows
            .values_mut()
            .chain(self.ended.iter_mut())
            .filter(|f| f.active)
            .collect();
        active.sort_by(|a, b| a.id.cmp(&b.id));
        for f in active {
            sink.slice(&f.take_slice(window_start_ns));
        }
        self.ended.clear();
    }

    /// Ends every Flow and closes the last window (end of input).
    pub fn finish(&mut self, window_start_ns: u64, sink: &mut dyn FlowSink) {
        self.close_window(window_start_ns, u64::MAX, sink);
    }
}

/// Adds one datagram's captured payload to a Slice hash chain.
fn datagram(chain: &mut Chain, payload: &[u8]) {
    chain.hasher.update(&(payload.len() as u32).to_be_bytes());
    chain.hasher.update(payload);
}

/// Handles one TCP segment captured at `ts_ns`; returns the stream offset of
/// its first payload byte.
fn tcp_packet(
    flow: &mut FlowState,
    dir: Dir,
    t: &net::TcpHeader,
    d: &Decoded,
    at: PacketRef,
    ts_ns: u64,
    sink: &mut dyn FlowSink,
) -> i64 {
    let FlowState {
        id,
        tcp,
        stats,
        chains,
        syn,
        syn_ack,
        fin,
        rst,
        ..
    } = flow;
    let (me, other) = pair(tcp, dir);
    let (my_stats, other_stats) = pair(stats, dir);
    let (my_chain, other_chain) = pair(chains, dir);
    let mut e = Emit {
        sink: &mut *sink,
        flow: id,
        dir,
        stats: my_stats,
        hash: &mut my_chain.hasher,
    };

    let is_syn = t.has(TCP_SYN);
    if is_syn {
        if t.has(TCP_ACK) {
            *syn_ack = true;
        } else {
            *syn = true;
        }
        match me.syn_isn {
            None if me.base_seq.is_none_or(|b| b == t.seq.wrapping_add(1)) => {
                me.syn_isn = Some(t.seq);
                me.base_seq = Some(t.seq.wrapping_add(1));
            }
            Some(isn) if isn == t.seq => {}
            _ => e.event(EventKind::SynChanged, None, 0, Some(at)),
        }
    }
    if me.base_seq.is_none() {
        me.base_seq = Some(t.seq);
    }
    if t.has(TCP_ACK) && other.base_seq.is_none() {
        other.base_seq = Some(t.ack);
    }

    let data_seq = t.seq.wrapping_add(u32::from(is_syn));
    let first = me.abs(data_seq).expect("base set");
    let mut off = first;
    let mut captured = d.payload;
    let mut total = u64::from(d.payload_len);
    let mut pkt_off = d.payload_offset;
    if off < 0 && total > 0 {
        let trim = (off.unsigned_abs()).min(total);
        e.event(EventKind::BeforeStreamStart, None, trim, Some(at));
        let cut = (trim as usize).min(captured.len());
        captured = &captured[cut..];
        pkt_off += cut as u32;
        total -= trim;
        off += trim as i64;
    }
    let off = off.max(0) as u64;
    if total > 0 {
        if me.fin_off.is_some_and(|f| off + total > f) {
            e.event(EventKind::DataAfterFin, Some(off), total, Some(at));
        }
        let cap = captured.len() as u64;
        if cap > 0 {
            me.insert(off, cap, Some(captured), at, ts_ns, pkt_off, &mut e);
        }
        if total > cap {
            me.insert(
                off + cap,
                total - cap,
                None,
                at,
                ts_ns,
                pkt_off + cap as u32,
                &mut e,
            );
        }
    }
    if t.has(TCP_FIN) {
        let fin_at = off + total;
        match me.fin_off {
            None => me.fin_off = Some(fin_at),
            Some(f) if f == fin_at => {}
            Some(_) => e.event(EventKind::FinChanged, Some(fin_at), 0, Some(at)),
        }
        fin[dir.idx()] = true;
    }
    if t.has(TCP_RST) {
        *rst = true;
    }

    // The peer acknowledging bytes we never saw proves the Tap lost them.
    if t.has(TCP_ACK) {
        if let Some(acked) = other.abs(t.ack) {
            let target = match other.fin_off {
                Some(f) => acked.min(f as i64),
                None => acked,
            };
            if target > other.delivered as i64 {
                let mut oe = Emit {
                    sink: &mut *sink,
                    flow: id,
                    dir: dir.other(),
                    stats: other_stats,
                    hash: &mut other_chain.hasher,
                };
                other.gap_until(target as u64, EventKind::GapLost, &mut oe);
            }
        }
    }
    first
}
