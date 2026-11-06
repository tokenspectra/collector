//! TLS ClientHello: SNI and ALPN (spec §5, "TLS ClientHello").
//!
//! The first bytes of a `tls` Flow's client direction are read as one
//! ClientHello. The parse reads what a rule like "TLS to these names" needs
//! and no more: the records up to the end of the message and the SNI and
//! ALPN extensions strictly, everything else by bounds only (spec §5 has
//! the rules). A pure parse: bytes in, rows out, no I/O. These are facts;
//! Allowlist rules and statuses are the Classifier's.

use serde::Serialize;

use crate::dns::Msg;
use crate::flow::{Dir, FlowId};
use crate::http::{Lab, Out};
use crate::packet::PacketRef;

/// Most bytes held while a ClientHello is incomplete; a longer one is not read.
const MAX_HELLO: usize = 16 << 10;
const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const NAME_HOST: u8 = 0;

/// One ClientHello (the `tls` table): at most one row per Flow.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TlsRecord {
    /// The packet that carried its first byte.
    pub window_start_ns: u64,
    pub index: u32,
    pub ts_ns: u64,
    pub flow: FlowId,
    pub dir: Dir,
    /// The `host_name`, a byte outside `!`..`~` as `\DDD` and `\` escaped;
    /// `null` without the extension. Case is kept as sent.
    pub sni: Option<String>,
    /// Its bytes on the wire.
    pub sni_len: Option<u32>,
    /// The offered protocols in order, escaped like `sni`.
    pub alpn: Vec<String>,
    /// The bytes it took on the stream, record headers included.
    pub size: u32,
    /// Bytes of the message after its extensions.
    pub trailing_bytes: u32,
}

/// Per-Slice TLS features of one Flow (the `tls_*` columns of `features`),
/// in the Slice of the ClientHello's first byte.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct TlsFeatures {
    pub client_hellos: u64,
    pub bytes: u64,
    pub sni_len: Option<u32>,
}

impl TlsRecord {
    pub(crate) fn features(&self) -> TlsFeatures {
        TlsFeatures {
            client_hellos: 1,
            bytes: u64::from(self.size),
            sni_len: self.sni_len,
        }
    }
}

/// The fields a ClientHello's message gives.
#[derive(Debug, Default, PartialEq)]
struct Hello {
    sni: Option<(String, u32)>,
    alpn: Vec<String>,
    trailing_bytes: u32,
}

/// What the bytes at the start of a stream are so far.
#[derive(Debug, PartialEq)]
enum Scan {
    /// Nothing to say before this many bytes.
    Need(usize),
    /// A ClientHello that ends this many bytes in.
    Hello(Hello, usize),
    NotHello,
}

/// Reads the client direction of a `tls` Flow. Holds its first bytes until
/// they are a whole ClientHello or can't be one; then labels them, and all
/// that follows is unexplained.
pub(crate) struct ClientHello {
    flow: FlowId,
    dir: Dir,
    held: Vec<u8>,
    need: usize,
    first: Option<(u64, PacketRef)>,
    done: bool,
}

impl ClientHello {
    pub fn new(flow: FlowId, dir: Dir) -> Self {
        ClientHello {
            flow,
            dir,
            held: Vec::new(),
            need: 0,
            first: None,
            done: false,
        }
    }

    pub fn data(&mut self, d: &[u8], ts_ns: u64, at: PacketRef, out: &mut dyn Out) {
        if self.done {
            return out.span(d.len() as u64, Lab::Unexplained);
        }
        self.first.get_or_insert((ts_ns, at));
        self.held.extend_from_slice(d);
        if self.held.len() < self.need {
            return;
        }
        match scan(&self.held) {
            Scan::Need(n) if n <= MAX_HELLO => self.need = n,
            Scan::Hello(h, size) => {
                self.report(h, size, out);
                out.span(size as u64, Lab::Fact);
                self.held.drain(..size);
                self.stop(out);
            }
            _ => self.stop(out),
        }
    }

    /// No ClientHello will complete: what is held stays unexplained.
    pub fn stop(&mut self, out: &mut dyn Out) {
        if !self.done {
            out.span(self.held.len() as u64, Lab::Unexplained);
        }
        self.held = Vec::new();
        self.done = true;
    }

    fn report(&self, h: Hello, size: usize, out: &mut dyn Out) {
        let (ts_ns, at) = self.first.expect("bytes were held");
        let (sni, sni_len) = h.sni.unzip();
        out.client_hello(&TlsRecord {
            window_start_ns: at.window_start_ns,
            index: at.index,
            ts_ns,
            flow: self.flow.clone(),
            dir: self.dir,
            sni,
            sni_len,
            alpn: h.alpn,
            size: size as u32,
            trailing_bytes: h.trailing_bytes,
        });
    }
}

/// Walks handshake records from the start of `s`, joining their fragments
/// until the first message is whole.
fn scan(s: &[u8]) -> Scan {
    let mut msg = Vec::new();
    let mut at = 0;
    loop {
        let Some(header) = s.get(at..at + RECORD_HEADER) else {
            return Scan::Need(at + RECORD_HEADER);
        };
        if header[0] != CONTENT_HANDSHAKE {
            return Scan::NotHello;
        }
        let start = at + RECORD_HEADER;
        at = start + usize::from(u16::from_be_bytes([header[3], header[4]]));
        let Some(fragment) = s.get(start..at) else {
            return Scan::Need(at);
        };
        msg.extend_from_slice(fragment);
        let [kind, a, b, c, ..] = msg[..] else { continue };
        if kind != HANDSHAKE_CLIENT_HELLO {
            return Scan::NotHello;
        }
        let end = 4 + u32::from_be_bytes([0, a, b, c]) as usize;
        if msg.len() >= end {
            return match read(&msg[4..end]) {
                Some(h) => Scan::Hello(h, at - (msg.len() - end)),
                None => Scan::NotHello,
            };
        }
    }
}

/// The body of a ClientHello (RFC 8446 §4.1.2): `None` when a field runs
/// past its bounds or SNI or ALPN is malformed.
fn read(m: &[u8]) -> Option<Hello> {
    let mut p = Msg { m, pos: 0 };
    p.take(34)?; // legacy_version, random
    vec8(&mut p)?; // legacy_session_id
    vec16(&mut p)?; // cipher_suites
    vec8(&mut p)?; // legacy_compression_methods
    let mut h = Hello::default();
    // Before TLS 1.3 the extensions may be left out.
    if p.pos == m.len() {
        return Some(h);
    }
    let mut e = Msg {
        m: vec16(&mut p)?,
        pos: 0,
    };
    while e.pos < e.m.len() {
        let kind = e.u16()?;
        let data = vec16(&mut e)?;
        match kind {
            // A second copy could name something else: neither is the fact.
            EXT_SERVER_NAME if h.sni.is_some() => return None,
            EXT_ALPN if !h.alpn.is_empty() => return None,
            EXT_SERVER_NAME => h.sni = Some(host_name(data)?),
            EXT_ALPN => h.alpn = protocols(data)?,
            _ => {}
        }
    }
    h.trailing_bytes = (m.len() - p.pos) as u32;
    Some(h)
}

/// `server_name` (RFC 6066 §3): exactly one `host_name`.
fn host_name(data: &[u8]) -> Option<(String, u32)> {
    let (&kind, name) = filled(data)?.split_first()?;
    let name = filled(name)?;
    (kind == NAME_HOST).then(|| (escaped(name), name.len() as u32))
}

/// `application_layer_protocol_negotiation` (RFC 7301 §3.1): a list of one
/// or more non-empty names.
fn protocols(data: &[u8]) -> Option<Vec<String>> {
    let mut p = Msg {
        m: filled(data)?,
        pos: 0,
    };
    let mut names = Vec::new();
    while p.pos < p.m.len() {
        let name = vec8(&mut p).filter(|n| !n.is_empty())?;
        names.push(escaped(name));
    }
    Some(names)
}

fn vec8<'a>(p: &mut Msg<'a>) -> Option<&'a [u8]> {
    let len = p.take(1)?[0];
    p.take(usize::from(len))
}

fn vec16<'a>(p: &mut Msg<'a>) -> Option<&'a [u8]> {
    let len = p.u16()?;
    p.take(usize::from(len))
}

/// The non-empty vector with a 16-bit length that fills `b` exactly.
fn filled(b: &[u8]) -> Option<&[u8]> {
    let mut p = Msg { m: b, pos: 0 };
    vec16(&mut p).filter(|v| !v.is_empty() && p.pos == b.len())
}

fn escaped(name: &[u8]) -> String {
    let mut s = String::new();
    for &b in name {
        match b {
            b'\\' => s.push_str("\\\\"),
            0x21..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03}")),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut e = kind.to_be_bytes().to_vec();
        e.extend_from_slice(&(data.len() as u16).to_be_bytes());
        e.extend_from_slice(data);
        e
    }

    fn sni(name: &[u8]) -> Vec<u8> {
        let mut d = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        d.push(NAME_HOST);
        d.extend_from_slice(&(name.len() as u16).to_be_bytes());
        d.extend_from_slice(name);
        ext(EXT_SERVER_NAME, &d)
    }

    fn alpn(names: &[&[u8]]) -> Vec<u8> {
        let list: Vec<u8> = names
            .iter()
            .flat_map(|n| [&[n.len() as u8], *n].concat())
            .collect();
        ext(
            EXT_ALPN,
            &[&(list.len() as u16).to_be_bytes(), &list[..]].concat(),
        )
    }

    /// A ClientHello's handshake message with these extensions.
    fn message(exts: &[Vec<u8>]) -> Vec<u8> {
        let exts = exts.concat();
        let mut b = vec![3, 3];
        b.extend_from_slice(&[7; 32]);
        b.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend_from_slice(&exts);
        let mut m = vec![HANDSHAKE_CLIENT_HELLO];
        m.extend_from_slice(&(b.len() as u32).to_be_bytes()[1..]);
        m.extend_from_slice(&b);
        m
    }

    fn record(fragment: &[u8]) -> Vec<u8> {
        let mut r = vec![CONTENT_HANDSHAKE, 3, 1];
        r.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        r.extend_from_slice(fragment);
        r
    }

    fn hello(s: &[u8]) -> Hello {
        match scan(s) {
            Scan::Hello(h, _) => h,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reads_sni_and_alpn_past_other_extensions() {
        let m = message(&[
            ext(10, &[0, 2, 0, 29]),
            sni(b"api.Example"),
            alpn(&[b"h2", b"http/1.1"]),
        ]);
        let r = record(&m);
        let Scan::Hello(h, size) = scan(&r) else {
            panic!("no hello")
        };
        assert_eq!(size, r.len());
        assert_eq!(h.sni, Some(("api.Example".to_string(), 11)));
        assert_eq!(h.alpn, ["h2", "http/1.1"]);
        assert_eq!(h.trailing_bytes, 0);
    }

    #[test]
    fn extensions_are_optional() {
        let mut m = message(&[]);
        m.truncate(m.len() - 2);
        m[3] -= 2;
        assert_eq!(hello(&record(&m)), Hello::default());
        assert_eq!(hello(&record(&message(&[ext(10, &[])]))), Hello::default());
    }

    #[test]
    fn names_are_escaped() {
        let m = message(&[sni(b"a\\b \xff"), alpn(&[b"x\x00"])]);
        let h = hello(&record(&m));
        assert_eq!(h.sni, Some(("a\\\\b\\032\\255".to_string(), 5)));
        assert_eq!(h.alpn, ["x\\000"]);
    }

    #[test]
    fn a_message_can_span_records() {
        let m = message(&[sni(b"a.example")]);
        // Even its four-byte header can be split.
        let r = [record(&m[..2]), record(&m[2..50]), record(&m[50..])].concat();
        let Scan::Hello(h, size) = scan(&r) else {
            panic!("no hello")
        };
        assert_eq!(size, r.len());
        assert_eq!(h.sni.unwrap().0, "a.example");
    }

    #[test]
    fn what_follows_the_message_is_not_in_it() {
        let m = message(&[sni(b"a.example")]);
        let r = record(&[&m[..], b"more"].concat());
        assert_eq!(scan(&r), Scan::Hello(hello(&r), r.len() - 4));
    }

    #[test]
    fn bytes_after_the_extensions_are_counted() {
        let mut m = message(&[sni(b"a.example")]);
        m.extend_from_slice(b"hidden");
        m[3] += 6;
        assert_eq!(hello(&record(&m)).trailing_bytes, 6);
    }

    #[test]
    fn asks_for_what_it_needs() {
        let r = record(&message(&[sni(b"a.example")]));
        assert_eq!(scan(&r[..3]), Scan::Need(5));
        assert_eq!(scan(&r[..5]), Scan::Need(r.len()));
        let m = message(&[]);
        let first = record(&m[..10]);
        assert_eq!(scan(&first), Scan::Need(first.len() + 5));
    }

    #[test]
    fn what_is_not_a_client_hello() {
        let not = |s: &[u8]| assert_eq!(scan(s), Scan::NotHello, "{s:?}");
        // A ServerHello; application data; a bad record after the first.
        not(&record(&[2, 0, 0, 0]));
        not(b"\x17\x03\x03\x00\x01\x00");
        let m = message(&[]);
        not(&[record(&m[..10]), b"\x17\x03\x03\x00\x00".to_vec()].concat());
        // A body that stops inside the random, or a vector past its bounds.
        not(&record(&[1, 0, 0, 3, 3, 3, 0]));
        let mut long = message(&[sni(b"a.example")]);
        long[40] = 0xff;
        not(&record(&long));
    }

    #[test]
    fn malformed_sni_or_alpn_is_not_read() {
        let not = |e: Vec<u8>| {
            assert_eq!(
                scan(&record(&message(std::slice::from_ref(&e)))),
                Scan::NotHello,
                "{e:?}"
            )
        };
        not(ext(EXT_SERVER_NAME, &[]));
        not(ext(EXT_SERVER_NAME, &[0, 0]));
        // Another name type; a list longer than the extension; two names.
        not(ext(EXT_SERVER_NAME, &[0, 4, 1, 0, 1, b'a']));
        not(ext(EXT_SERVER_NAME, &[0, 9, 0, 0, 1, b'a']));
        not(ext(EXT_SERVER_NAME, &[0, 8, 0, 0, 1, b'a', 0, 0, 1, b'b']));
        not(ext(EXT_ALPN, &[0, 0]));
        not(ext(EXT_ALPN, &[0, 1, 0]));
        not(ext(EXT_ALPN, &[0, 3, 5, b'a', b'b']));
        for twice in [[sni(b"a"), sni(b"b")], [alpn(&[b"a"]), alpn(&[b"b"])]] {
            assert_eq!(scan(&record(&message(&twice))), Scan::NotHello);
        }
    }
}
