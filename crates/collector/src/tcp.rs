//! Reassembly of one direction of a TCP Flow into an ordered byte stream.
//!
//! Offsets are absolute stream offsets (u64), so streams over 4 GiB are fine.
//! Overlapping bytes keep the first copy seen; a later copy that differs is
//! reported as `retransmit_differs`. Bytes the Tap never saw become gaps,
//! never guesses.

use std::collections::{BTreeMap, VecDeque};

use crate::assembler::{DirStats, EventKind, EventRecord, FlowSink, SegmentRecord};
use crate::flow::{Dir, FlowId};
use crate::window::PacketRef;

/// Where reassembly output goes for one direction.
pub(crate) struct Emit<'a> {
    pub sink: &'a mut dyn FlowSink,
    pub flow: &'a FlowId,
    pub dir: Dir,
    pub stats: &'a mut DirStats,
    /// This direction's Slice hash chain; every delivered byte goes in.
    pub hash: &'a mut blake3::Hasher,
}

impl Emit<'_> {
    pub fn event(&mut self, kind: EventKind, stream_off: Option<u64>, len: u64, at: Option<PacketRef>) {
        self.sink.event(&EventRecord {
            flow: self.flow.clone(),
            dir: Some(self.dir),
            kind,
            stream_off,
            len,
            window_start_ns: at.map(|a| a.window_start_ns),
            index: at.map(|a| a.index),
        });
    }

    fn gap(&mut self, kind: EventKind, off: u64, len: u64, at: Option<PacketRef>) {
        self.stats.gap_bytes += len;
        self.event(kind, Some(off), len, at);
    }
}

/// Bytes waiting for the hole before them to fill. `data == None` stands for
/// bytes cut off by the capture's snap length.
struct Pending {
    len: u64,
    data: Option<Vec<u8>>,
    at: PacketRef,
    ts_ns: u64,
    pkt_off: u32,
}

pub(crate) struct TcpDir {
    /// Sequence number of stream offset 0.
    pub base_seq: Option<u32>,
    /// ISN of the SYN seen in this direction, if any.
    pub syn_isn: Option<u32>,
    /// Every stream byte below this offset has been delivered or declared a gap.
    pub delivered: u64,
    /// Stream offset of the FIN, once seen.
    pub fin_off: Option<u64>,
    /// `delivered` when the current Slice began.
    pub slice_start: u64,
    pending: BTreeMap<u64, Pending>,
    pending_bytes: u64,
    max_pending: u64,
    /// The last delivered bytes, kept to compare retransmits against.
    recent: VecDeque<(u64, Vec<u8>)>,
    recent_bytes: u64,
    max_recent: u64,
}

impl TcpDir {
    pub fn new(max_pending: u64, max_recent: u64) -> Self {
        TcpDir {
            base_seq: None,
            syn_isn: None,
            delivered: 0,
            fin_off: None,
            slice_start: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_pending,
            recent: VecDeque::new(),
            recent_bytes: 0,
            max_recent,
        }
    }

    /// The stream offset of `seq`, taken as the nearest one to the delivered
    /// edge (modulo 2^32). Negative when it lies before stream offset 0.
    pub fn abs(&self, seq: u32) -> Option<i64> {
        let base = self.base_seq?;
        let edge = base.wrapping_add(self.delivered as u32);
        Some(self.delivered as i64 + i64::from(seq.wrapping_sub(edge) as i32))
    }

    /// Adds `len` stream bytes starting at `off`, carried by packet `at`
    /// (captured at `ts_ns`) from byte `pkt_off`. `data` is `None` for bytes
    /// cut off by the snap length.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        off: u64,
        len: u64,
        data: Option<&[u8]>,
        at: PacketRef,
        ts_ns: u64,
        pkt_off: u32,
        e: &mut Emit,
    ) {
        let end = off + len;
        let piece = |s: u64, t: u64| data.map(|d| &d[(s - off) as usize..(t - off) as usize]);

        if off < self.delivered {
            let old_end = end.min(self.delivered);
            self.check_delivered(off, piece(off, old_end), old_end - off, at, e);
        }
        let start = off.max(self.delivered);
        if start >= end {
            return;
        }

        // Pending entries overlapping [start, end), in order.
        let mut overlaps: Vec<u64> = Vec::new();
        if let Some((&k, p)) = self.pending.range(..start).next_back() {
            if k + p.len > start {
                overlaps.push(k);
            }
        }
        overlaps.extend(self.pending.range(start..end).map(|(&k, _)| k));

        let mut cursor = start;
        for k in overlaps {
            let (k_end, existing) = {
                let p = &self.pending[&k];
                (k + p.len, p.data.as_deref().map(|d| d.to_vec()))
            };
            if cursor < k {
                let t = k.min(end);
                self.put(
                    cursor,
                    t,
                    piece(cursor, t),
                    at,
                    ts_ns,
                    pkt_off + (cursor - off) as u32,
                );
            }
            let (s, t) = (cursor.max(k), end.min(k_end));
            if s < t {
                let old = existing
                    .as_deref()
                    .map(|d| &d[(s - k) as usize..(t - k) as usize]);
                self.compare(s, piece(s, t), old, t - s, at, e);
            }
            cursor = cursor.max(k_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            self.put(
                cursor,
                end,
                piece(cursor, end),
                at,
                ts_ns,
                pkt_off + (cursor - off) as u32,
            );
        }

        self.drain(e);
        while self.pending_bytes > self.max_pending {
            let Some(&k) = self.pending.keys().next() else {
                break;
            };
            self.gap_until(k, EventKind::GapBufferLimit, e);
        }
    }

    fn put(&mut self, s: u64, t: u64, data: Option<&[u8]>, at: PacketRef, ts_ns: u64, pkt_off: u32) {
        self.pending_bytes += t - s;
        self.pending.insert(
            s,
            Pending {
                len: t - s,
                data: data.map(<[u8]>::to_vec),
                at,
                ts_ns,
                pkt_off,
            },
        );
    }

    /// Bytes at `[off, off + len)` arrived again after being delivered.
    fn check_delivered(&mut self, off: u64, new: Option<&[u8]>, len: u64, at: PacketRef, e: &mut Emit) {
        e.stats.retransmit_bytes += len;
        let Some(new) = new else { return };
        let end = off + len;
        let mut diffs = Vec::new();
        for (k, old) in self.recent.iter().rev() {
            let k_end = k + old.len() as u64;
            if k_end <= off {
                break;
            }
            let (s, t) = (off.max(*k), end.min(k_end));
            if s < t {
                let a = &new[(s - off) as usize..(t - off) as usize];
                let b = &old[(s - k) as usize..(t - k) as usize];
                if let Some(range) = differing(s, a, b) {
                    diffs.push(range);
                }
            }
        }
        diffs.sort_unstable();
        for (s, t) in diffs {
            e.stats.retransmit_diff_bytes += t - s;
            e.event(EventKind::RetransmitDiffers, Some(s), t - s, Some(at));
        }
    }

    /// Bytes at `[off, off + len)` overlap bytes still pending.
    fn compare(
        &mut self,
        off: u64,
        new: Option<&[u8]>,
        old: Option<&[u8]>,
        len: u64,
        at: PacketRef,
        e: &mut Emit,
    ) {
        e.stats.retransmit_bytes += len;
        if let (Some(a), Some(b)) = (new, old) {
            if let Some((s, t)) = differing(off, a, b) {
                e.stats.retransmit_diff_bytes += t - s;
                e.event(EventKind::RetransmitDiffers, Some(s), t - s, Some(at));
            }
        }
    }

    /// Delivers pending bytes that now sit at the delivered edge.
    fn drain(&mut self, e: &mut Emit) {
        while let Some(entry) = self.pending.first_entry() {
            if *entry.key() != self.delivered {
                break;
            }
            let (off, p) = entry.remove_entry();
            self.pending_bytes -= p.len;
            match p.data {
                Some(data) => {
                    e.hash.update(&data);
                    e.sink.segment(
                        &SegmentRecord {
                            flow: e.flow.clone(),
                            dir: e.dir,
                            stream_off: off,
                            len: p.len,
                            window_start_ns: p.at.window_start_ns,
                            index: p.at.index,
                            pkt_off: p.pkt_off,
                            ts_ns: p.ts_ns,
                        },
                        &data,
                    );
                    self.recent_bytes += p.len;
                    self.recent.push_back((off, data));
                    while self.recent_bytes > self.max_recent {
                        let Some((_, old)) = self.recent.pop_front() else {
                            break;
                        };
                        self.recent_bytes -= old.len() as u64;
                    }
                }
                None => e.gap(EventKind::GapTruncated, off, p.len, Some(p.at)),
            }
            self.delivered += p.len;
        }
    }

    /// Declares every missing byte below `target` a gap of `kind`.
    pub fn gap_until(&mut self, target: u64, kind: EventKind, e: &mut Emit) {
        loop {
            self.drain(e);
            if self.delivered >= target {
                return;
            }
            let end = match self.pending.keys().next() {
                Some(&k) => k.min(target),
                None => target,
            };
            let start = self.delivered;
            e.gap(kind, start, end - start, None);
            self.delivered = end;
        }
    }

    /// Declares every remaining hole a gap and delivers everything pending.
    /// Returns whether anything changed.
    pub fn flush(&mut self, e: &mut Emit) -> bool {
        let before = self.delivered;
        while let Some(&k) = self.pending.keys().next() {
            self.gap_until(k, EventKind::GapUnfilled, e);
        }
        self.delivered != before
    }
}

/// The smallest range `[s, t)` (as stream offsets from `off`) where `a` and
/// `b` differ, if any.
fn differing(off: u64, a: &[u8], b: &[u8]) -> Option<(u64, u64)> {
    let first = a.iter().zip(b).position(|(x, y)| x != y)?;
    let last = a.iter().zip(b).rposition(|(x, y)| x != y)?;
    Some((off + first as u64, off + last as u64 + 1))
}
