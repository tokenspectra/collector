//! What the HTTP parsers ([`crate::http1`], [`crate::http2`]) report about
//! one direction of a Flow (L2, spec §2 and §5).
//!
//! A parser consumes the direction's stream bytes in order and labels every
//! byte exactly once, in order, through [`Out::span`]. Messages are reported
//! as a head, body bytes and an end; the decoder ([`crate::decode`]) pairs
//! requests with responses and turns labels into byte-accounting buckets.

use crate::tls::TlsRecord;

/// What a run of stream bytes is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lab {
    /// Protocol overhead around messages.
    Framing,
    /// Part of the message on this stream (HTTP/1: the current message).
    Msg(u32),
    /// Part of a parsed HTTP message that can never be a Workunit (HTTP/2
    /// server push).
    Other,
    /// Bytes the parser does not understand.
    Unexplained,
    /// Bytes never captured.
    Gap,
    /// Inside a protocol fact.
    Fact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StartLine {
    Request {
        method: String,
        target: String,
    },
    Response {
        status: u16,
    },
    /// HTTP/2 trailers: a header block without pseudo-headers.
    Trailers,
}

/// Header fields as (name, value) bytes.
pub(crate) type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// A parsed message head. Header names are lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub start: StartLine,
    pub headers: Fields,
}

impl Head {
    /// The first value of header `name` (lowercase).
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n == name.as_bytes())
            .map(|(_, v)| v.as_slice())
    }

    /// Every value of header `name`.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name.as_bytes())
            .map(|(_, v)| v.as_slice())
    }

    /// The media type of `content-type`, lowercase, without parameters.
    pub fn media_type(&self) -> Option<String> {
        let v = self.get("content-type")?;
        let v = String::from_utf8_lossy(v);
        let t = v.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        Some(t)
    }

    pub fn header_str(&self, name: &str) -> Option<String> {
        self.get(name)
            .map(|v| String::from_utf8_lossy(v).trim().to_string())
    }
}

/// How the decoder tells an HTTP/1 response parser to read the body that
/// follows a head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HeadReply {
    /// The request was HEAD: no body whatever the headers say.
    pub no_body: bool,
    /// The connection stops being HTTP after this head (a CONNECT 2xx).
    pub tunnel: bool,
}

/// Where a parser reports what it found.
pub(crate) trait Out {
    /// A ClientHello read at the start of the direction.
    fn client_hello(&mut self, _rec: &TlsRecord) {}
    /// The next `len` bytes of the direction are `lab`.
    fn span(&mut self, len: u64, lab: Lab);
    /// A message head starting at stream offset `start`, whose first byte
    /// was captured at `ts_ns`.
    fn head(&mut self, stream: u32, start: u64, ts_ns: u64, head: Head) -> HeadReply;
    /// Body bytes as on the wire, after removing chunked encoding.
    fn body(&mut self, stream: u32, data: &[u8], ts_ns: u64);
    /// Body bytes that were never captured.
    fn body_gap(&mut self, stream: u32, len: u64);
    /// The message on `stream` ended at stream offset `end`. `complete` is
    /// false when the stream stopped before the message's declared end.
    fn end(&mut self, stream: u32, end: u64, ts_ns: u64, complete: bool);
    /// An HTTP/2 stream was reset.
    fn reset(&mut self, stream: u32);
    /// The parser lost track of the protocol; the rest of the direction is
    /// unexplained.
    fn desync(&mut self, reason: &'static str);
}

/// `tchar` from RFC 9110 §5.6.2.
pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Finds `needle` in `hay`.
pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
