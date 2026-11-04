//! DNS over UDP and the per-Slice covert-channel features (spec §5, "DNS").
//!
//! Every UDP datagram, on any port, is tried as a DNS message (RFC 1035
//! §4): a datagram is DNS only when its bytes parse as DNS. The parse is
//! strict: a header with a known opcode and at least one question, then
//! every question and resource record the header counts.
//! - Names are checked label by label: at most 63 bytes a label, 255 a
//!   name. A compression pointer must point at the start of a label, or of
//!   a pointer, in an earlier name of the same message, never into the
//!   header, a label's bytes or other data, and at most [`MAX_HOPS`] are
//!   followed per name.
//! - The RDATA of the types whose format is fixed is checked within its
//!   RDLENGTH: A and AAAA by length, TXT as character-strings that fill it,
//!   the name-bearing types (NS, CNAME, PTR, DNAME, MX, SOA, SRV, …) as
//!   their fields and names, OPT as options. Other types stay opaque.
//! - Bytes left after the last record are counted, not rejected: they are
//!   a fact worth seeing on a Link.
//!
//! Each message becomes a [`DnsRecord`] (the `dns` table) and adds to the
//! Slice's [`DnsFeatures`] (the `dns_*` columns of `features`). This
//! module is a pure parse: bytes in, rows out, no I/O. These are facts;
//! Allowlist rules and statuses are the Classifier's.

use serde::Serialize;

use crate::flow::{Dir, FlowId};
use crate::window::PacketRef;

/// Compression pointers followed per name before the name is malformed.
/// A name has at most 127 labels, and real encoders use one pointer.
const MAX_HOPS: usize = 128;
/// Longest name on the wire, length octets and the root included.
const MAX_NAME: usize = 255;
const TYPE_TXT: u16 = 16;
const TYPE_SPF: u16 = 99;

/// One UDP datagram as captured, handed to [`FlowSink::datagram`](crate::FlowSink::datagram).
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    pub flow: &'a FlowId,
    pub dir: Dir,
    pub at: PacketRef,
    pub ts_ns: u64,
    /// The captured payload; shorter than `payload_len` when the capture
    /// cut the packet.
    pub payload: &'a [u8],
    pub payload_len: u32,
}

/// One DNS message (the `dns` table): one row per UDP datagram that parses.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DnsRecord {
    /// The packet that carried it.
    pub window_start_ns: u64,
    pub index: u32,
    pub ts_ns: u64,
    pub flow: FlowId,
    pub dir: Dir,
    pub id: u16,
    /// QR: a response, else a query.
    pub response: bool,
    pub opcode: u8,
    /// The header's RCODE (EDNS extended bits not added).
    pub rcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    /// Section counts, as the header gives them (all parsed).
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
    /// The first question's name in presentation form (RFC 1035 §5.1):
    /// a byte outside `!`..`~` is `\DDD`, `.` and `\` inside a label are
    /// escaped, the root is `.`. Case is kept as sent.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Label bytes plus the dots between labels (0 for the root).
    pub qname_len: u32,
    pub labels: u32,
    pub label_len_max: u32,
    /// Shannon entropy of the name's label bytes, ASCII letters folded to
    /// lower case, in bits per byte, rounded to 3 decimals. `null` for the
    /// root.
    pub qname_entropy: Option<f64>,
    /// TXT records in any section, and the sum and largest of their RDATA
    /// lengths (`null` with none).
    pub txt_records: u32,
    pub txt_bytes: u64,
    pub txt_max: Option<u32>,
    /// The message's bytes: the UDP payload.
    pub size: u32,
    /// Bytes after the last record the header counts.
    pub trailing_bytes: u32,
}

/// Per-Slice DNS features of one Flow (the `dns_*` columns of `features`).
/// Name features are taken over queries only, so a name is counted once per
/// exchange. Content features (names, TXT sizes) belong to the parse; the
/// rate and volume ones (`query_rate`, the byte counts) are to come from the
/// commit layer's per-Flow counters later (TS-57), with the same columns.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DnsFeatures {
    pub messages: u64,
    pub queries: u64,
    pub responses: u64,
    /// Datagrams of the Flow in this Slice that are not DNS: they did not
    /// parse, or the capture cut them.
    pub other_datagrams: u64,
    /// DNS message bytes, queries and responses, and both together.
    pub query_bytes: u64,
    pub response_bytes: u64,
    pub bytes: u64,
    /// Queries per second of the window, rounded to 3 decimals.
    pub query_rate: f64,
    pub qname_entropy_max: Option<f64>,
    pub qname_entropy_mean: Option<f64>,
    pub qname_len_max: Option<u32>,
    pub label_len_max: Option<u32>,
    /// Mean length of every label of every query name.
    pub label_len_mean: Option<f64>,
    pub txt_records: u64,
    pub txt_bytes: u64,
    pub txt_max: Option<u32>,
}

/// What one Flow's datagrams added up to in the current Slice.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    f: DnsFeatures,
    entropy_sum: f64,
    entropy_n: u64,
    label_sum: u64,
    label_n: u64,
}

impl Tally {
    pub fn other(&mut self) {
        self.f.other_datagrams += 1;
    }

    pub fn add(&mut self, r: &DnsRecord) {
        let f = &mut self.f;
        f.messages += 1;
        f.bytes += u64::from(r.size);
        f.txt_records += u64::from(r.txt_records);
        f.txt_bytes += r.txt_bytes;
        f.txt_max = f.txt_max.max(r.txt_max);
        if r.response {
            f.responses += 1;
            f.response_bytes += u64::from(r.size);
            return;
        }
        f.queries += 1;
        f.query_bytes += u64::from(r.size);
        f.qname_len_max = f.qname_len_max.max(Some(r.qname_len));
        if r.labels > 0 {
            f.label_len_max = f.label_len_max.max(Some(r.label_len_max));
            self.label_sum += u64::from(r.qname_len + 1 - r.labels);
            self.label_n += u64::from(r.labels);
        }
        if let Some(e) = r.qname_entropy {
            f.qname_entropy_max = Some(f.qname_entropy_max.map_or(e, |m| m.max(e)));
            self.entropy_sum += e;
            self.entropy_n += 1;
        }
    }

    /// The Slice's features, or `None` when no datagram in it was DNS.
    pub fn finish(self, window_ns: u64) -> Option<DnsFeatures> {
        let mut f = self.f;
        if f.messages == 0 {
            return None;
        }
        f.query_rate = round3(f.queries as f64 * 1e9 / window_ns.max(1) as f64);
        f.qname_entropy_mean = (self.entropy_n > 0).then(|| round3(self.entropy_sum / self.entropy_n as f64));
        f.label_len_mean = (self.label_n > 0).then(|| round3(self.label_sum as f64 / self.label_n as f64));
        Some(f)
    }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The DNS row for a datagram, or `None` when it is not a whole DNS message.
pub fn decode(d: &Datagram<'_>) -> Option<DnsRecord> {
    if d.payload.len() as u64 != u64::from(d.payload_len) {
        return None;
    }
    let m = d.payload;
    let h = Header::parse(m)?;
    let mut p = Msg::new(m);
    let q = p.name()?;
    let qtype = p.u16()?;
    let qclass = p.u16()?;
    for _ in 1..h.questions {
        p.name()?;
        p.take(4)?;
    }
    let (mut txt_records, mut txt_bytes, mut txt_max) = (0u32, 0u64, None);
    let records = u32::from(h.answers) + u32::from(h.authority) + u32::from(h.additional);
    for _ in 0..records {
        p.name()?;
        let rtype = p.u16()?;
        p.take(6)?; // class, TTL
        let rdlen = usize::from(p.u16()?);
        let end = p.pos.checked_add(rdlen).filter(|&e| e <= m.len())?;
        p.rdata(rtype, end)?;
        if rtype == TYPE_TXT {
            txt_records += 1;
            txt_bytes += rdlen as u64;
            txt_max = txt_max.max(Some(rdlen as u32));
        }
    }
    let pos = p.pos;
    Some(DnsRecord {
        window_start_ns: d.at.window_start_ns,
        index: d.at.index,
        ts_ns: d.ts_ns,
        flow: d.flow.clone(),
        dir: d.dir,
        id: h.id,
        response: h.flags & 0x8000 != 0,
        opcode: h.opcode(),
        rcode: (h.flags & 0x000f) as u8,
        aa: h.flags & 0x0400 != 0,
        tc: h.flags & 0x0200 != 0,
        rd: h.flags & 0x0100 != 0,
        ra: h.flags & 0x0080 != 0,
        questions: h.questions,
        answers: h.answers,
        authority: h.authority,
        additional: h.additional,
        qname: q.presentation(),
        qtype,
        qclass,
        qname_len: q.len(),
        labels: q.labels.len() as u32,
        label_len_max: q.labels.iter().map(|l| l.len() as u32).max().unwrap_or(0),
        qname_entropy: q.entropy(),
        txt_records,
        txt_bytes,
        txt_max,
        size: m.len() as u32,
        trailing_bytes: (m.len() - pos) as u32,
    })
}

struct Header {
    id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
}

impl Header {
    fn parse(m: &[u8]) -> Option<Header> {
        let h = Header {
            id: u16_at(m, 0)?,
            flags: u16_at(m, 2)?,
            questions: u16_at(m, 4)?,
            answers: u16_at(m, 6)?,
            authority: u16_at(m, 8)?,
            additional: u16_at(m, 10)?,
        };
        // QUERY, IQUERY, STATUS, NOTIFY, UPDATE, DSO; 3 and 7–15 are unassigned.
        let known = matches!(h.opcode(), 0 | 1 | 2 | 4 | 5 | 6);
        (known && h.questions > 0).then_some(h)
    }

    fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }
}

fn u16_at(m: &[u8], at: usize) -> Option<u16> {
    let b = m.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// A domain name's labels, borrowed from the message.
struct Name<'a> {
    labels: Vec<&'a [u8]>,
}

impl Name<'_> {
    fn len(&self) -> u32 {
        let bytes: usize = self.labels.iter().map(|l| l.len()).sum();
        (bytes + self.labels.len().saturating_sub(1)) as u32
    }

    fn presentation(&self) -> String {
        if self.labels.is_empty() {
            return ".".into();
        }
        let mut s = String::new();
        for (i, l) in self.labels.iter().enumerate() {
            if i > 0 {
                s.push('.');
            }
            for &b in *l {
                match b {
                    b'.' | b'\\' => {
                        s.push('\\');
                        s.push(b as char);
                    }
                    0x21..=0x7e => s.push(b as char),
                    _ => s.push_str(&format!("\\{b:03}")),
                }
            }
        }
        s
    }

    fn entropy(&self) -> Option<f64> {
        let mut counts = [0u32; 256];
        let mut n = 0u32;
        for &b in self.labels.iter().flat_map(|l| l.iter()) {
            counts[usize::from(b.to_ascii_lowercase())] += 1;
            n += 1;
        }
        if n == 0 {
            return None;
        }
        let n = f64::from(n);
        let h: f64 = counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        // A single repeated byte sums to `-0.0`; written as `0.0`.
        Some(round3(h) + 0.0)
    }
}

/// A message being read front to back.
struct Msg<'a> {
    m: &'a [u8],
    pos: usize,
    /// Where each label and pointer of the names read so far begins, in
    /// increasing order: the only places a compression pointer may target.
    starts: Vec<usize>,
}

impl<'a> Msg<'a> {
    fn new(m: &'a [u8]) -> Self {
        Msg {
            m,
            pos: 12,
            starts: Vec::new(),
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.m.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads the name at the cursor and moves past it.
    fn name(&mut self) -> Option<Name<'a>> {
        let first = self.starts.len();
        let mut labels = Vec::new();
        let mut at = self.pos;
        let mut resume = None;
        let mut hops = 0;
        let mut wire = 1; // the root's length octet
        loop {
            let len = *self.m.get(at)?;
            if resume.is_none() && len != 0 {
                self.starts.push(at);
            }
            match len >> 6 {
                0 if len == 0 => break,
                0 => {
                    let len = usize::from(len);
                    labels.push(self.m.get(at + 1..at + 1 + len)?);
                    wire += 1 + len;
                    if wire > MAX_NAME {
                        return None;
                    }
                    at += 1 + len;
                }
                3 => {
                    let target = usize::from(u16_at(self.m, at)? & 0x3fff);
                    hops += 1;
                    // Earlier names only: one that points into itself loops.
                    let earlier = &self.starts[..first];
                    if hops > MAX_HOPS || earlier.binary_search(&target).is_err() {
                        return None;
                    }
                    resume.get_or_insert(at + 2);
                    at = target;
                }
                // 0b01 (extended label types) and 0b10 are not in use.
                _ => return None,
            }
        }
        self.pos = resume.unwrap_or(at + 1);
        Some(Name { labels })
    }

    /// Checks the RDATA of `rtype` that ends at `end`, and moves past it.
    fn rdata(&mut self, rtype: u16, end: usize) -> Option<()> {
        let len = end - self.pos;
        let names = |p: &mut Self, fixed_before: usize, names: usize, fixed_after: usize| {
            p.take(fixed_before)?;
            for _ in 0..names {
                p.name()?;
            }
            p.take(fixed_after)?;
            (p.pos == end).then_some(())
        };
        match rtype {
            // A, AAAA
            1 | 28 if len == if rtype == 1 { 4 } else { 16 } => self.pos = end,
            1 | 28 => return None,
            // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME: one name.
            2..=5 | 7..=9 | 12 | 39 => names(self, 0, 1, 0)?,
            // SOA: two names, then serial, refresh, retry, expire, minimum.
            6 => names(self, 0, 2, 20)?,
            // MINFO: two names.
            14 => names(self, 0, 2, 0)?,
            // MX, AFSDB, RT, KX: a 16-bit preference, then a name.
            15 | 18 | 21 | 36 => names(self, 2, 1, 0)?,
            // SRV: priority, weight, port, then a name.
            33 => names(self, 6, 1, 0)?,
            // TXT, SPF: one or more character-strings, filling the RDATA.
            TYPE_TXT | TYPE_SPF => {
                if len == 0 {
                    return None;
                }
                while self.pos < end {
                    let n = usize::from(*self.m.get(self.pos)?);
                    self.take(1 + n)?;
                }
                (self.pos == end).then_some(())?
            }
            // OPT: options of (code, length, data), filling the RDATA.
            41 => {
                while self.pos < end {
                    self.take(2)?;
                    let n = usize::from(self.u16()?);
                    self.take(n)?;
                }
                (self.pos == end).then_some(())?
            }
            _ => self.pos = end,
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::flow::{Endpoint, FlowKind, Tuple};
    use crate::source::LinkId;

    fn flow() -> FlowId {
        let end = |port| Endpoint {
            ip: IpAddr::from([10, 0, 0, 1]),
            port,
        };
        FlowId::new(
            &Tuple::new(LinkId::new("tap0"), FlowKind::Udp, end(5353), end(53)),
            0,
        )
    }

    fn dg<'a>(flow: &'a FlowId, payload: &'a [u8]) -> Datagram<'a> {
        Datagram {
            flow,
            dir: Dir::Orig,
            at: PacketRef {
                window_start_ns: 0,
                index: 0,
            },
            ts_ns: 1,
            payload,
            payload_len: payload.len() as u32,
        }
    }

    fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&qd.to_be_bytes());
        m.extend_from_slice(&an.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m
    }

    fn qname(m: &mut Vec<u8>, labels: &[&[u8]]) {
        for l in labels {
            m.push(l.len() as u8);
            m.extend_from_slice(l);
        }
        m.push(0);
    }

    const A: u16 = 1;

    fn query(labels: &[&[u8]], qtype: u16) -> Vec<u8> {
        let mut m = header(0x0100, 1, 0);
        qname(&mut m, labels);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn a_query_and_its_answer() {
        let f = flow();
        let q = query(&[b"api", b"example"], A);
        let r = decode(&dg(&f, &q)).expect("query");
        assert!(!r.response && r.rd && !r.ra);
        assert_eq!((r.qname.as_str(), r.qtype, r.qclass), ("api.example", 1, 1));
        assert_eq!((r.qname_len, r.labels, r.label_len_max), (11, 2, 7));
        assert_eq!(r.size as usize, q.len());
        assert_eq!(r.trailing_bytes, 0);

        let mut a = header(0x8180, 1, 1);
        a.extend_from_slice(&q[12..]);
        a.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 2]);
        let r = decode(&dg(&f, &a)).expect("answer");
        assert!(r.response && r.ra);
        assert_eq!(r.answers, 1);
        assert_eq!((r.txt_records, r.txt_max), (0, None));
    }

    #[test]
    fn txt_records_are_counted_in_every_section() {
        let f = flow();
        let mut m = header(0x8180, 1, 1);
        m[11] = 1; // one additional record
        qname(&mut m, &[b"t", b"example"]);
        m.extend_from_slice(&[0, 16, 0, 1]);
        for len in [200u8, 40] {
            m.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, len + 1, len]);
            m.extend(std::iter::repeat_n(b'x', usize::from(len)));
        }
        let r = decode(&dg(&f, &m)).expect("dns");
        assert_eq!((r.txt_records, r.txt_bytes, r.txt_max), (2, 242, Some(201)));
    }

    #[test]
    fn names_are_escaped_and_entropy_folds_case() {
        let f = flow();
        let r = decode(&dg(&f, &query(&[b"a.b\\", b"\x00\xff ", b"Zz"], A))).unwrap();
        assert_eq!(r.qname, "a\\.b\\\\.\\000\\255\\032.Zz");
        // "aaaa" has no entropy; "ab" one bit; "AaBb" folds to "aabb".
        let e = |l: &[u8]| decode(&dg(&f, &query(&[l], A))).unwrap().qname_entropy;
        assert_eq!(e(b"aaaa"), Some(0.0));
        assert_eq!(e(b"ab"), Some(1.0));
        assert_eq!(e(b"AaBb"), Some(1.0));
        assert_eq!(e(b"abcd"), Some(2.0));
        let root = decode(&dg(&f, &query(&[], 2))).unwrap();
        assert_eq!((root.qname.as_str(), root.qname_len, root.labels), (".", 0, 0));
        assert_eq!(root.qname_entropy, None);
    }

    #[test]
    fn trailing_bytes_are_counted() {
        let f = flow();
        let mut q = query(&[b"x"], A);
        q.extend_from_slice(b"hidden");
        assert_eq!(decode(&dg(&f, &q)).unwrap().trailing_bytes, 6);
    }

    #[test]
    fn what_is_not_dns() {
        let f = flow();
        let q = query(&[b"api", b"example"], A);
        // Cut by the capture.
        let mut cut = dg(&f, &q[..20]);
        cut.payload_len = q.len() as u32;
        assert!(decode(&cut).is_none());
        // Too short, no question, an unassigned opcode.
        assert!(decode(&dg(&f, &q[..11])).is_none());
        assert!(decode(&dg(&f, &header(0x0100, 0, 0))).is_none());
        let mut op3 = q.clone();
        op3[2] = 0x18;
        assert!(decode(&dg(&f, &op3)).is_none());
        // A record the header counts is missing.
        let mut more = q.clone();
        more[7] = 1;
        assert!(decode(&dg(&f, &more)).is_none());
        // RDATA runs past the end.
        let mut a = header(0x8180, 1, 1);
        a.extend_from_slice(&q[12..]);
        a.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 9, 10]);
        assert!(decode(&dg(&f, &a)).is_none());
        // A label type that is not in use, and a label past the end.
        let mut ext = q.clone();
        ext[12] = 0x41;
        assert!(decode(&dg(&f, &ext)).is_none());
        let mut long = q.clone();
        long[12] = 60;
        assert!(decode(&dg(&f, &long)).is_none());
        // NTP: 48 bytes with zero counts.
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x23;
        assert!(decode(&dg(&f, &ntp)).is_none());
    }

    #[test]
    fn compression_pointers_go_backwards_only() {
        let f = flow();
        // The question's name is a pointer to itself, then one forwards.
        let mut m = header(0x0100, 1, 0);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(decode(&dg(&f, &m)).is_none());
        let mut m = header(0x0100, 1, 0);
        m.extend_from_slice(&[0xc0, 14, 0, 0, 1, 0, 1]);
        assert!(decode(&dg(&f, &m)).is_none());
        // An answer's name: one more label in front of the question's 193
        // bytes, through a pointer. 254 bytes parse; 256 do not.
        let named = |extra: usize| {
            let mut m = header(0x8180, 1, 1);
            qname(&mut m, &[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63]]);
            m.extend_from_slice(&[0, 1, 0, 1]);
            m.push(extra as u8);
            m.extend(std::iter::repeat_n(b'd', extra));
            // HINFO with empty RDATA: a type this parser leaves opaque.
            m.extend_from_slice(&[0xc0, 12, 0, 13, 0, 1, 0, 0, 0, 0, 0, 0]);
            m
        };
        assert!(decode(&dg(&f, &named(60))).is_some());
        assert!(decode(&dg(&f, &named(62))).is_none());
    }

    #[test]
    fn a_pointer_chain_is_bounded() {
        let f = flow();
        // Questions 2.. each point at the one before: MAX_HOPS + 2 hops for
        // the last name.
        let n = MAX_HOPS + 2;
        let mut m = header(0x0100, n as u16, 0);
        qname(&mut m, &[b"x"]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let mut prev = 12u16;
        for _ in 1..n {
            let at = m.len() as u16;
            m.extend_from_slice(&(0xc000 | prev).to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 1]);
            prev = at;
        }
        assert!(decode(&dg(&f, &m)).is_none());
        let ok = n - 2;
        let mut m2 = m.clone();
        m2[4..6].copy_from_slice(&(ok as u16).to_be_bytes());
        let cut = 12 + 7 + (ok - 1) * 6;
        assert!(decode(&dg(&f, &m2[..cut])).is_some());
    }

    /// An answer to `api.example A` whose record is `rtype` with `rdata`.
    fn answer(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut m = header(0x8180, 1, 1);
        qname(&mut m, &[b"api", b"example"]);
        m.extend_from_slice(&[0, 1, 0, 1, 0xc0, 0x0c]);
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(rdata);
        m
    }

    #[test]
    fn pointers_must_target_an_earlier_name() {
        let f = flow();
        // Review round 1: a question pointing at the transaction ID.
        let header_target = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x01\x00\x01";
        assert!(decode(&dg(&f, header_target)).is_none());
        // Into the middle of a label (offset 13 is "pi" of "api").
        let mut m = header(0x0100, 2, 0);
        qname(&mut m, &[b"api", b"example"]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let ok = m.len();
        m.extend_from_slice(&[0xc0, 13, 0, 1, 0, 1]);
        assert!(decode(&dg(&f, &m)).is_none());
        // To each label start of the first name: fine.
        for target in [12u8, 16] {
            m[ok + 1] = target;
            assert!(decode(&dg(&f, &m)).is_some(), "{target}");
        }
        // At the first name's root octet, or past it into its type.
        for target in [24u8, 25] {
            m[ok + 1] = target;
            assert!(decode(&dg(&f, &m)).is_none(), "{target}");
        }
        // A label, then a pointer back into the same name: a loop.
        let mut m = header(0x0100, 1, 0);
        m.extend_from_slice(&[1, b'a', 0xc0, 12, 0, 1, 0, 1]);
        assert!(decode(&dg(&f, &m)).is_none());
        // A pointer to a pointer of an earlier name is a valid chain.
        let mut m = header(0x0100, 3, 0);
        qname(&mut m, &[b"x"]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let second = m.len() as u8;
        m.extend_from_slice(&[1, b'y', 0xc0, 12, 0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, second + 2, 0, 1, 0, 1]);
        assert!(decode(&dg(&f, &m)).is_some());
    }

    #[test]
    fn rdata_of_known_types_is_checked() {
        let f = flow();
        let ok = |rtype: u16, rdata: &[u8]| decode(&dg(&f, &answer(rtype, rdata))).is_some();
        // TXT: strings must fill RDLENGTH exactly (review round 1: `ff`
        // alone claims 255 bytes that are not there).
        assert!(!ok(16, b"\xff"));
        assert!(!ok(16, b""));
        assert!(!ok(16, b"\x03ab"));
        assert!(!ok(16, b"\x01ab"));
        assert!(ok(16, b"\x02ab\x00\x01c"));
        assert!(!ok(99, b"\x05abc"));
        // A and AAAA by length.
        assert!(ok(1, &[10, 0, 0, 2]));
        let a = decode(&dg(&f, &answer(1, &[10, 0, 0, 2]))).unwrap();
        assert_eq!(a.trailing_bytes, 0, "RDATA is consumed");
        assert!(!ok(1, &[10, 0, 0]));
        assert!(ok(28, &[0; 16]));
        assert!(!ok(28, &[0; 4]));
        // Name-bearing RDATA: the name must parse, compress validly and end
        // at RDLENGTH.
        assert!(ok(5, &[0xc0, 0x0c]));
        assert!(ok(5, &[3, b'w', b'w', b'w', 0xc0, 0x0c]));
        assert!(!ok(5, &[0xc0, 0x00]), "CNAME into the header");
        assert!(!ok(5, &[0xc0, 0x0d]), "CNAME into a label");
        assert!(!ok(5, &[0xc0, 0x0c, 0]), "a byte after the name");
        assert!(!ok(5, &[3, b'w', b'w']), "a name cut by RDLENGTH");
        assert!(ok(15, &[0, 10, 0xc0, 0x0c]));
        assert!(!ok(15, &[0, 10]));
        assert!(ok(33, &[0, 1, 0, 1, 0, 53, 0xc0, 0x0c]));
        let mut soa = vec![0xc0, 0x0c, 0xc0, 0x0c];
        soa.extend_from_slice(&[0; 20]);
        assert!(ok(6, &soa));
        assert!(!ok(6, &soa[..23]));
        // OPT options must fill the RDATA.
        assert!(ok(41, &[0, 10, 0, 2, 1, 2]));
        assert!(!ok(41, &[0, 10, 0, 3, 1, 2]));
        // Unknown types stay opaque.
        assert!(ok(65280, &[0xff; 7]));
        // A name in RDATA is a valid compression target for later records.
        let mut m = answer(5, &[3, b'w', b'w', b'w', 0xc0, 0x0c]);
        m[7] = 2;
        let www = (m.len() - 6) as u8;
        m.extend_from_slice(&[0xc0, www, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 2]);
        assert!(decode(&dg(&f, &m)).is_some());
    }

    /// Valid messages to mutate: a query, A and AAAA answers, an answer with
    /// compression in RDATA, TXT, SOA, OPT and SRV records.
    fn corpus() -> Vec<Vec<u8>> {
        let mut soa = vec![0xc0, 0x0c, 2, b'n', b's', 0xc0, 0x10];
        soa.extend_from_slice(&[0; 20]);
        vec![
            query(&[b"api", b"example"], A),
            answer(1, &[10, 0, 0, 2]),
            answer(28, &[0; 16]),
            answer(5, &[3, b'w', b'w', b'w', 0xc0, 0x0c]),
            answer(16, b"\x05hello\x00\x03abc"),
            answer(6, &soa),
            answer(41, &[0, 10, 0, 2, 1, 2]),
            answer(33, &[0, 1, 0, 1, 0, 53, 0xc0, 0x10]),
        ]
    }

    /// What every accepted message satisfies.
    fn sane(m: &[u8], r: &DnsRecord) {
        assert_eq!(r.size as usize, m.len());
        assert!((r.trailing_bytes as usize) < m.len() - 12);
        assert!(r.qname_len <= 253 && r.label_len_max <= 63 && r.labels <= 127);
        assert!(u64::from(r.txt_max.unwrap_or(0)) <= r.txt_bytes);
        assert!(r.txt_bytes as usize <= m.len());
    }

    #[test]
    fn every_strict_prefix_is_rejected() {
        let f = flow();
        for m in corpus() {
            let whole = decode(&dg(&f, &m)).unwrap_or_else(|| panic!("{m:?}"));
            assert_eq!(whole.trailing_bytes, 0, "{m:?}");
            for n in 0..m.len() {
                assert!(decode(&dg(&f, &m[..n])).is_none(), "{n} of {m:?}");
            }
        }
    }

    #[test]
    fn mutations_never_panic_and_accepted_ones_are_sane() {
        let f = flow();
        for m in corpus() {
            for i in 0..m.len() {
                for v in [
                    0u8,
                    1,
                    0x3f,
                    0x40,
                    0x80,
                    0xc0,
                    0xff,
                    m[i] ^ 1,
                    m[i].wrapping_add(1),
                ] {
                    let mut x = m.clone();
                    x[i] = v;
                    if let Some(r) = decode(&dg(&f, &x)) {
                        sane(&x, &r);
                    }
                }
            }
        }
    }

    #[test]
    fn random_datagrams_are_not_dns() {
        let f = flow();
        // xorshift64, fixed seed: deterministic.
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let (mut plain, mut shaped) = (0, 0);
        for _ in 0..200_000 {
            let len = 12 + (next() % 512) as usize;
            let mut m: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if let Some(r) = decode(&dg(&f, &m)) {
                sane(&m, &r);
                plain += 1;
            }
            // A plausible header (one question, no records) over random
            // bytes, to drive the name parser.
            m[2..12].copy_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            if let Some(r) = decode(&dg(&f, &m)) {
                sane(&m, &r);
                shaped += 1;
            }
        }
        assert_eq!(plain, 0);
        // Random names do sometimes parse (a short label run ending in 0);
        // those are well-formed queries, so they are counted, not refused.
        assert!(shaped < 2_000, "{shaped}");
    }

    #[test]
    fn tally_takes_name_features_from_queries() {
        let f = flow();
        let mut t = Tally::default();
        let q1 = decode(&dg(&f, &query(&[b"ab", b"example"], A))).unwrap();
        let q2 = decode(&dg(&f, &query(&[b"abcd"], 16))).unwrap();
        let mut resp = q2.clone();
        resp.response = true;
        resp.txt_records = 1;
        resp.txt_bytes = 300;
        resp.txt_max = Some(300);
        resp.qname_len = 999;
        for r in [&q1, &q2, &resp] {
            t.add(r);
        }
        t.other();
        let d = t.finish(2_000_000_000).unwrap();
        assert_eq!(
            (d.messages, d.queries, d.responses, d.other_datagrams),
            (3, 2, 1, 1)
        );
        assert_eq!(d.query_rate, 1.0);
        assert_eq!(d.qname_len_max, Some(10));
        assert_eq!(d.label_len_max, Some(7));
        // Labels 2, 7 and 4.
        assert_eq!(d.label_len_mean, Some(4.333));
        // "abexample" has more entropy than "abcd" (2 bits).
        assert_eq!(d.qname_entropy_max, q1.qname_entropy);
        assert!(q1.qname_entropy > Some(2.0));
        let mean = (q1.qname_entropy.unwrap() + 2.0) / 2.0;
        assert_eq!(d.qname_entropy_mean, Some(round3(mean)));
        assert_eq!((d.txt_records, d.txt_bytes, d.txt_max), (1, 300, Some(300)));
        assert_eq!(d.bytes, d.query_bytes + d.response_bytes);
        let mut none = Tally::default();
        none.other();
        assert!(none.finish(1).is_none());
    }
}
