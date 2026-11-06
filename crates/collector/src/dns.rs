//! DNS over UDP and the per-Slice covert-channel features (spec §5, "DNS").
//!
//! Every UDP datagram, on any port, is tried as a DNS message. The parse
//! reads what a rule like "DNS to resolver X, zones in Y, at most N B/s"
//! needs, plus the content features, and no more: the header and first
//! question strictly, everything after by bounds only (spec §5 has the
//! rules). A pure parse: bytes in, rows out, no I/O. These are facts;
//! Allowlist rules and statuses are the Classifier's.

use serde::Serialize;

use crate::flow::{Dir, FlowId};
use crate::packet::PacketRef;

/// Longest name on the wire, length octets and the root included.
const MAX_NAME: usize = 255;
const TYPE_TXT: u16 = 16;

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
    /// QR: a response, else a query.
    pub response: bool,
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
/// Name features are taken over queries only. The rate and volume ones are
/// to come from the commit layer's per-Flow counters (TS-57).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DnsFeatures {
    pub messages: u64,
    pub queries: u64,
    pub responses: u64,
    /// Datagrams of the Flow in this Slice that are not DNS.
    pub other_datagrams: u64,
    pub query_bytes: u64,
    pub response_bytes: u64,
    pub bytes: u64,
    pub query_rate: f64,
    pub qname_entropy_max: Option<f64>,
    pub qname_entropy_mean: Option<f64>,
    pub qname_len_max: Option<u32>,
    pub label_len_max: Option<u32>,
    pub label_len_mean: Option<f64>,
    pub txt_records: u64,
    pub txt_bytes: u64,
    pub txt_max: Option<u32>,
}

/// What one Flow's datagrams added up to in the current Slice.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    /// Bytes of DNS messages per direction: the `fact` bucket.
    pub fact: [u64; 2],
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
        self.fact[r.dir.idx()] += u64::from(r.size);
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
    let mut p = Msg { m, pos: 2 };
    let flags = p.u16()?;
    let questions = p.u16()?;
    let records = u32::from(p.u16()?) + u32::from(p.u16()?) + u32::from(p.u16()?);
    // Only QUERY: other opcodes give their sections other meanings.
    if flags & 0x7800 != 0 || questions == 0 {
        return None;
    }
    let q = p.qname()?;
    let qtype = p.u16()?;
    let qclass = p.u16()?;
    for _ in 1..questions {
        p.skip_name()?;
        p.take(4)?;
    }
    let (mut txt_records, mut txt_bytes, mut txt_max) = (0u32, 0u64, None);
    for _ in 0..records {
        p.skip_name()?;
        let rtype = p.u16()?;
        p.take(6)?; // class, TTL
        let rdlen = usize::from(p.u16()?);
        let rdata = p.take(rdlen)?;
        if rtype == TYPE_TXT && txt_is_well_formed(rdata) {
            txt_records += 1;
            txt_bytes += rdlen as u64;
            txt_max = txt_max.max(Some(rdlen as u32));
        }
    }
    Some(DnsRecord {
        window_start_ns: d.at.window_start_ns,
        index: d.at.index,
        ts_ns: d.ts_ns,
        flow: d.flow.clone(),
        dir: d.dir,
        response: flags & 0x8000 != 0,
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
        trailing_bytes: (m.len() - p.pos) as u32,
    })
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

/// One or more character-strings that fill `rdata` exactly.
fn txt_is_well_formed(rdata: &[u8]) -> bool {
    let mut at = 0;
    while at < rdata.len() {
        at += 1 + usize::from(rdata[at]);
    }
    at == rdata.len() && !rdata.is_empty()
}

/// A message being read front to back.
struct Msg<'a> {
    m: &'a [u8],
    pos: usize,
}

impl<'a> Msg<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.m.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads the first question's name. Only the header comes before it, so
    /// a compression pointer here could only reach the header or the name's
    /// own labels: malformed.
    fn qname(&mut self) -> Option<Name<'a>> {
        let mut labels = Vec::new();
        let mut wire = 1; // the root's length octet
        loop {
            let len = *self.m.get(self.pos)?;
            if len == 0 {
                self.pos += 1;
                return Some(Name { labels });
            }
            if len >> 6 != 0 {
                return None;
            }
            let len = usize::from(len);
            wire += 1 + len;
            if wire > MAX_NAME {
                return None;
            }
            self.pos += 1;
            labels.push(self.take(len)?);
        }
    }

    /// Moves past a name without reading it: its labels up to the root, or
    /// up to a pointer, which ends it and is not followed.
    fn skip_name(&mut self) -> Option<()> {
        loop {
            let len = *self.m.get(self.pos)?;
            match len >> 6 {
                0 if len == 0 => {
                    self.pos += 1;
                    return Some(());
                }
                0 => {
                    self.take(1 + usize::from(len))?;
                }
                3 => {
                    self.take(2)?;
                    return Some(());
                }
                // 0b01 and 0b10 have no length to walk.
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::flow::{Endpoint, FlowKind, Tuple};
    use crate::packet::LinkId;

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
        assert!(!r.response);
        assert_eq!((r.qname.as_str(), r.qtype, r.qclass), ("api.example", 1, 1));
        assert_eq!((r.qname_len, r.labels, r.label_len_max), (11, 2, 7));
        assert_eq!(r.size as usize, q.len());
        assert_eq!(r.trailing_bytes, 0);

        let mut a = header(0x8180, 1, 1);
        a.extend_from_slice(&q[12..]);
        a.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 2]);
        let r = decode(&dg(&f, &a)).expect("answer");
        assert!(r.response);
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
    fn a_pointer_in_the_qname_is_malformed() {
        let f = flow();
        // Review round 1: a question pointing at the transaction ID.
        let header_target = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x01\x00\x01";
        assert!(decode(&dg(&f, header_target)).is_none());
        // At itself, forwards, and after a label: at its own start, and into
        // the label's bytes.
        for name in [
            &[0xc0, 12][..],
            &[0xc0, 14, 0],
            &[1, b'a', 0xc0, 12],
            &[3, b'a', b'b', b'c', 0xc0, 13],
        ] {
            let mut m = header(0x0100, 1, 0);
            m.extend_from_slice(name);
            m.extend_from_slice(&[0, 1, 0, 1]);
            assert!(decode(&dg(&f, &m)).is_none(), "{name:?}");
        }
    }

    #[test]
    fn the_qname_is_limited_to_255_bytes() {
        let f = flow();
        // Three labels of 63 and one of `last`: 193 + 1 + last on the wire
        // with the root, so 61 makes 255 and 62 makes 256.
        let named = |last: usize| query(&[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &vec![b'd'; last]], A);
        assert_eq!(decode(&dg(&f, &named(61))).unwrap().qname_len, 253);
        assert!(decode(&dg(&f, &named(62))).is_none());
        // A label of 64 is a label type not in use.
        assert!(decode(&dg(&f, &query(&[&[b'a'; 64]], A))).is_none());
    }

    #[test]
    fn names_after_the_qname_are_skipped_not_followed() {
        let f = flow();
        // Review round 2: a TXT owner that points into an RP record's RDATA.
        // The RP's mailbox `txt.x` is at the offset noted below.
        let mut m = header(0x8180, 1, 2);
        qname(&mut m, &[b"x"]);
        m.extend_from_slice(&[0, 16, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 17, 0, 1, 0, 0, 0, 60, 0, 7]);
        let mailbox = m.len() as u8;
        m.extend_from_slice(&[3, b't', b'x', b't', 0xc0, 12, 0]);
        m.extend_from_slice(&[0xc0, mailbox, 0, 16, 0, 1, 0, 0, 0, 60, 0, 3, 2, b'o', b'k']);
        let r = decode(&dg(&f, &m)).expect("RP owner");
        assert_eq!((r.txt_records, r.txt_bytes, r.trailing_bytes), (1, 3, 0));
        // Review round 2: an owner that points at the question's root octet.
        let mut m = answer(1, &[10, 0, 0, 2]);
        let at = m.len() - 16;
        m[at + 1] = 24;
        assert!(decode(&dg(&f, &m)).is_some());
        // A second question may point at the first, as mDNS does; its target
        // is not checked.
        let mut m = header(0x0100, 2, 0);
        qname(&mut m, &[b"api", b"example"]);
        m.extend_from_slice(&[0, 1, 0, 1, 0xc0, 16, 0, 1, 0, 1]);
        let r = decode(&dg(&f, &m)).expect("two questions");
        assert_eq!(r.qname, "api.example");
        // Owner names are walked, so they must still fit: cut by the end of
        // the message, or a label type with no length to walk.
        let mut m = header(0x8180, 1, 1);
        qname(&mut m, &[b"x"]);
        m.extend_from_slice(&[0, 1, 0, 1, 9, b'a']);
        assert!(decode(&dg(&f, &m)).is_none());
        let at = m.len() - 2;
        m[at] = 0x41;
        m.extend_from_slice(&[0; 12]);
        assert!(decode(&dg(&f, &m)).is_none());
    }

    #[test]
    fn rdata_is_walked_by_its_length_only() {
        let f = flow();
        let ok = |rtype: u16, rdata: &[u8]| decode(&dg(&f, &answer(rtype, rdata))).is_some();
        // Any bytes fit: the type does not say how they must look.
        assert!(ok(1, &[10, 0, 0, 2]));
        assert!(ok(1, &[10, 0, 0]));
        assert!(ok(1, &[]));
        assert!(ok(28, &[0; 4]));
        assert!(ok(5, &[0xc0, 0x00]), "a CNAME into the header");
        assert!(ok(41, &[0, 10, 0, 3, 1, 2]));
        assert!(ok(65280, &[0xff; 7]));
        let a = decode(&dg(&f, &answer(1, &[10, 0, 0, 2]))).unwrap();
        assert_eq!(a.trailing_bytes, 0, "RDATA is consumed");
        // RDLENGTH must fit in the message.
        let mut m = answer(1, &[10, 0, 0, 2]);
        let n = m.len();
        m[n - 5] = 5;
        assert!(decode(&dg(&f, &m)).is_none());
    }

    #[test]
    fn a_malformed_txt_adds_no_txt_facts() {
        let f = flow();
        let txt = |rdata: &[u8]| {
            let r = decode(&dg(&f, &answer(16, rdata))).expect("still DNS");
            assert_eq!(r.trailing_bytes, 0);
            (r.txt_records, r.txt_bytes, r.txt_max)
        };
        // Review round 1: `ff` alone claims 255 bytes that are not there.
        assert_eq!(txt(b"\xff"), (0, 0, None));
        assert_eq!(txt(b""), (0, 0, None));
        assert_eq!(txt(b"\x03ab"), (0, 0, None));
        assert_eq!(txt(b"\x01ab"), (0, 0, None));
        assert_eq!(txt(b"\x02ab\x00\x01c"), (1, 6, Some(6)));
        // A good record beside a bad one: only the good one counts.
        let mut m = answer(16, b"\xff");
        m[7] = 2;
        m.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 3, 2, b'o', b'k']);
        let r = decode(&dg(&f, &m)).unwrap();
        assert_eq!((r.txt_records, r.txt_bytes, r.txt_max), (1, 3, Some(3)));
    }

    #[test]
    fn only_query_is_parsed() {
        let f = flow();
        // Review round 2: an UPDATE deleting an A RRset. Zone `example`, then
        // in the update section: CLASS ANY, TTL 0, RDLENGTH 0.
        let mut m = header(0x2800, 1, 0);
        m[9] = 1;
        qname(&mut m, &[b"example"]);
        m.extend_from_slice(&[0, 6, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0]);
        assert!(decode(&dg(&f, &m)).is_none());
        // The same bytes as a QUERY walk fine: only the opcode decides.
        m[2] = 0x00;
        assert!(decode(&dg(&f, &m)).is_some());
        let q = query(&[b"x"], A);
        for opcode in 1..16u8 {
            let mut x = q.clone();
            x[2] = (x[2] & 0x87) | (opcode << 3);
            assert!(decode(&dg(&f, &x)).is_none(), "{opcode}");
        }
    }

    /// Messages to mutate: a query, and answers of several types.
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
        // Random names do sometimes parse (a short label run ending in 0),
        // with the rest as trailing bytes: facts, not protocol certainty.
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
