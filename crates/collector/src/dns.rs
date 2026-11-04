//! DNS over UDP and the per-Slice covert-channel features (spec §5, "DNS").
//!
//! Every UDP datagram, on any port, is tried as a DNS message (RFC 1035
//! §4): a datagram is DNS only when its bytes parse as DNS. The parse is
//! strict: a header with a known opcode and at least one question, then
//! every question and resource record the header counts, names checked
//! label by label (at most 63 bytes a label, 255 a name, compression
//! pointers only backwards and at most [`MAX_HOPS`] per name). Bytes left
//! after the last record are counted, not rejected: they are a fact worth
//! seeing on a Link.
//!
//! Each message becomes a [`DnsRecord`] (the `dns` table), and each Slice
//! of a Flow that carried one gets a [`FeaturesRecord`] (the `features`
//! table). These are facts; Allowlist rules and statuses are the
//! Classifier's.

use serde::Serialize;

use crate::flow::{Dir, FlowId};
use crate::source::LinkId;
use crate::window::PacketRef;

/// Compression pointers followed per name before the name is malformed.
/// A name has at most 127 labels, and real encoders use one pointer.
const MAX_HOPS: usize = 128;
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
/// exchange.
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

/// Covert-channel features of one Flow during one Slice (the `features`
/// table). One family of columns per decoder, each `null` when that decoder
/// saw nothing in the Slice; a row is written when any family has facts.
/// Later decoders (TLS ClientHello, NTP) add their own family.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FeaturesRecord {
    pub window_start_ns: u64,
    pub flow: FlowId,
    pub link: LinkId,
    pub dns: Option<DnsFeatures>,
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
    let mut pos = 12;
    let (q, end) = name(m, pos)?;
    pos = end;
    let qtype = u16_at(m, pos)?;
    let qclass = u16_at(m, pos + 2)?;
    pos += 4;
    for _ in 1..h.questions {
        pos = name(m, pos)?.1 + 4;
        if pos > m.len() {
            return None;
        }
    }
    let (mut txt_records, mut txt_bytes, mut txt_max) = (0u32, 0u64, None);
    let records = u32::from(h.answers) + u32::from(h.authority) + u32::from(h.additional);
    for _ in 0..records {
        pos = name(m, pos)?.1;
        let rtype = u16_at(m, pos)?;
        let rdlen = u16_at(m, pos + 8)?;
        pos += 10 + usize::from(rdlen);
        if pos > m.len() {
            return None;
        }
        if rtype == TYPE_TXT {
            txt_records += 1;
            txt_bytes += u64::from(rdlen);
            txt_max = txt_max.max(Some(u32::from(rdlen)));
        }
    }
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

/// Reads the name at `start`; returns it and where the bytes after it begin.
fn name(m: &[u8], start: usize) -> Option<(Name<'_>, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    let mut wire = 1; // the root's length octet
    loop {
        let len = *m.get(pos)?;
        match len >> 6 {
            0 if len == 0 => break,
            0 => {
                let len = usize::from(len);
                let label = m.get(pos + 1..pos + 1 + len)?;
                wire += 1 + len;
                if wire > MAX_NAME {
                    return None;
                }
                labels.push(label);
                pos += 1 + len;
            }
            3 => {
                let target = usize::from(u16_at(m, pos)? & 0x3fff);
                hops += 1;
                if target >= pos || hops > MAX_HOPS {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            // 0b01 (extended label types) and 0b10 are not in use.
            _ => return None,
        }
    }
    Some((Name { labels }, end.unwrap_or(pos + 1)))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::flow::{Endpoint, FlowKind, Tuple};

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
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
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
