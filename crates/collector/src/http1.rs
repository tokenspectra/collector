//! HTTP/1.x parsing of one direction of a Flow (RFC 9112), including chunked
//! transfer coding.
//!
//! Incremental: bytes arrive as the reassembler delivers them, possibly with
//! gaps. A gap inside a body of known length is skipped and counted; a gap
//! anywhere else loses the message boundaries, so the rest of the direction
//! becomes unexplained. There is no resynchronisation in v1.
//!
//! Chunk-size lines, the CRLF after each chunk and the blank lines allowed
//! between messages are framing; heads, bodies and trailers belong to their
//! message.

use crate::http::{find, is_tchar, Fields, Head, Lab, Out, StartLine};

/// Largest message head (start line and header fields).
const MAX_HEAD: usize = 64 << 10;
/// Largest start line before its CRLF.
const MAX_START_LINE: usize = 16 << 10;
/// Largest chunk-size line, extensions included.
const MAX_CHUNK_LINE: usize = 4 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    /// Between messages.
    Idle,
    /// Reading a head into `buf`.
    Head,
    /// Body with this many bytes left.
    Body(u64),
    /// Reading a chunk-size line into `buf`.
    ChunkSize,
    /// Chunk data with this many bytes left.
    ChunkData(u64),
    /// The CRLF after chunk data; this many bytes of it seen.
    ChunkCrlf(u8),
    /// Reading the trailer section into `buf`.
    Trailers,
    /// A response body delimited by the end of the stream.
    UntilClose,
    /// No longer HTTP (after 101 or CONNECT).
    Tunnel,
    /// Lost sync.
    Dead,
}

/// How a message's body is delimited.
enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

pub(crate) struct H1 {
    /// Parses requests (client side) or responses.
    requests: bool,
    /// Stream offset of the next byte to label.
    off: u64,
    st: St,
    /// Bytes read but not labeled yet, starting at `off`.
    buf: Vec<u8>,
    /// Capture time of the first byte in `buf`.
    buf_ts: u64,
    last_ts: u64,
}

impl H1 {
    pub fn new(requests: bool) -> Self {
        H1 {
            requests,
            off: 0,
            st: St::Idle,
            buf: Vec::new(),
            buf_ts: 0,
            last_ts: 0,
        }
    }

    pub fn data(&mut self, mut data: &[u8], ts_ns: u64, out: &mut dyn Out) {
        self.last_ts = ts_ns;
        while !data.is_empty() {
            let n = self.step(data, ts_ns, out);
            data = &data[n..];
        }
    }

    pub fn gap(&mut self, len: u64, out: &mut dyn Out) {
        let mut len = len;
        match self.st {
            St::Body(left) | St::ChunkData(left) => {
                let n = len.min(left);
                out.body_gap(0, n);
                self.label(out, n, Lab::Gap);
                len -= n;
                self.st = match self.st {
                    St::Body(_) if n == left => {
                        out.end(0, self.off, self.last_ts, true);
                        St::Idle
                    }
                    St::Body(_) => St::Body(left - n),
                    _ if n == left => St::ChunkCrlf(0),
                    _ => St::ChunkData(left - n),
                };
                if len > 0 {
                    self.desync(out, "gap");
                }
            }
            St::UntilClose => {
                out.body_gap(0, len);
            }
            St::Tunnel | St::Dead => {}
            St::Idle | St::Head | St::ChunkSize | St::ChunkCrlf(_) | St::Trailers => {
                self.abort(out, "gap");
            }
        }
        if len > 0 {
            self.label(out, len, Lab::Gap);
        }
    }

    /// End of the stream.
    pub fn finish(&mut self, out: &mut dyn Out) {
        let pending = std::mem::take(&mut self.buf);
        self.label(out, pending.len() as u64, Lab::Unexplained);
        match self.st {
            St::UntilClose => out.end(0, self.off, self.last_ts, true),
            _ if self.in_message() => out.end(0, self.off, self.last_ts, false),
            _ => {}
        }
        self.st = St::Dead;
    }

    /// Whether a message with a reported head is in progress.
    fn in_message(&self) -> bool {
        matches!(
            self.st,
            St::Body(_) | St::ChunkSize | St::ChunkData(_) | St::ChunkCrlf(_) | St::Trailers | St::UntilClose
        )
    }

    fn label(&mut self, out: &mut dyn Out, len: u64, lab: Lab) {
        if len > 0 {
            out.span(len, lab);
            self.off += len;
        }
    }

    /// Gives up, ending the message in progress (if any) as incomplete.
    fn abort(&mut self, out: &mut dyn Out, reason: &'static str) {
        if self.in_message() {
            out.end(0, self.off, self.last_ts, false);
        }
        self.desync(out, reason);
    }

    /// Gives up: whatever is buffered and everything after is unexplained.
    fn desync(&mut self, out: &mut dyn Out, reason: &'static str) {
        out.desync(reason);
        let pending = std::mem::take(&mut self.buf);
        self.label(out, pending.len() as u64, Lab::Unexplained);
        self.st = St::Dead;
    }

    /// Consumes a prefix of `data`; returns how many bytes.
    fn step(&mut self, data: &[u8], ts: u64, out: &mut dyn Out) -> usize {
        match self.st {
            St::Idle => {
                let n = data.iter().take_while(|&&b| b == b'\r' || b == b'\n').count();
                if n > 0 {
                    self.label(out, n as u64, Lab::Framing);
                    return n;
                }
                let ok = if self.requests {
                    is_tchar(data[0])
                } else {
                    data[0] == b'H'
                };
                if !ok {
                    self.desync(out, "bad_start_line");
                    return 0;
                }
                self.st = St::Head;
                self.buf.clear();
                self.buf_ts = ts;
                0
            }
            St::Head => {
                let old = self.buf.len();
                let take = data.len().min(MAX_HEAD - old);
                self.buf.extend_from_slice(&data[..take]);
                let from = old.saturating_sub(3);
                if let Some(p) = find(&self.buf[from..], b"\r\n\r\n") {
                    let end = from + p + 4;
                    self.buf.truncate(end);
                    self.end_head(out);
                    return end - old;
                }
                if find(&self.buf, b"\r\n").is_none() && self.buf.len() > MAX_START_LINE {
                    self.desync(out, "start_line_too_long");
                } else if self.buf.len() >= MAX_HEAD {
                    self.desync(out, "head_too_long");
                }
                take
            }
            St::Body(left) => {
                let n = (data.len() as u64).min(left) as usize;
                out.body(0, &data[..n], ts);
                self.label(out, n as u64, Lab::Msg(0));
                if n as u64 == left {
                    out.end(0, self.off, ts, true);
                    self.st = St::Idle;
                } else {
                    self.st = St::Body(left - n as u64);
                }
                n
            }
            St::ChunkSize => {
                let nl = data.iter().position(|&b| b == b'\n');
                let take = nl.map_or(data.len(), |p| p + 1);
                self.buf.extend_from_slice(&data[..take]);
                if nl.is_none() {
                    if self.buf.len() > MAX_CHUNK_LINE {
                        self.abort(out, "chunk_line_too_long");
                    }
                    return take;
                }
                let line = std::mem::take(&mut self.buf);
                match chunk_size(&line) {
                    Some(size) => {
                        self.label(out, line.len() as u64, Lab::Framing);
                        self.st = if size == 0 {
                            St::Trailers
                        } else {
                            St::ChunkData(size)
                        };
                    }
                    None => {
                        self.buf = line;
                        self.abort(out, "bad_chunk_size");
                    }
                }
                take
            }
            St::ChunkData(left) => {
                let n = (data.len() as u64).min(left) as usize;
                out.body(0, &data[..n], ts);
                self.label(out, n as u64, Lab::Msg(0));
                self.st = if n as u64 == left {
                    St::ChunkCrlf(0)
                } else {
                    St::ChunkData(left - n as u64)
                };
                n
            }
            St::ChunkCrlf(got) => {
                let want = if got == 0 { b'\r' } else { b'\n' };
                if data[0] != want {
                    self.abort(out, "bad_chunk_end");
                    return 0;
                }
                if got == 1 {
                    self.buf.clear();
                    self.label(out, 2, Lab::Framing);
                    self.st = St::ChunkSize;
                } else {
                    self.buf.push(b'\r');
                    self.st = St::ChunkCrlf(1);
                }
                1
            }
            St::Trailers => {
                let old = self.buf.len();
                let take = data.len().min(MAX_HEAD - old);
                self.buf.extend_from_slice(&data[..take]);
                if self.buf.len() >= 2 && self.buf.starts_with(b"\r\n") {
                    let used = 2 - old;
                    self.buf.clear();
                    self.label(out, 2, Lab::Framing);
                    out.end(0, self.off, ts, true);
                    self.st = St::Idle;
                    return used;
                }
                let from = old.saturating_sub(3);
                if let Some(p) = find(&self.buf[from..], b"\r\n\r\n") {
                    let end = from + p + 4;
                    self.buf.truncate(end);
                    let fields = &self.buf[..end - 2];
                    if parse_fields(fields).is_err() {
                        self.abort(out, "bad_trailers");
                        return end - old;
                    }
                    self.buf.clear();
                    self.label(out, (end - 2) as u64, Lab::Msg(0));
                    self.label(out, 2, Lab::Framing);
                    out.end(0, self.off, ts, true);
                    self.st = St::Idle;
                    return end - old;
                }
                if self.buf.len() >= MAX_HEAD {
                    self.abort(out, "trailers_too_long");
                }
                take
            }
            St::UntilClose => {
                out.body(0, data, ts);
                self.label(out, data.len() as u64, Lab::Msg(0));
                data.len()
            }
            St::Tunnel | St::Dead => {
                self.label(out, data.len() as u64, Lab::Unexplained);
                data.len()
            }
        }
    }

    /// `buf` holds a complete head, CRLF CRLF included.
    fn end_head(&mut self, out: &mut dyn Out) {
        let parsed = parse_head(&self.buf, self.requests).and_then(|h| Ok((framing(&h, self.requests)?, h)));
        let (framing, head) = match parsed {
            Ok(v) => v,
            Err(reason) => return self.desync(out, reason),
        };
        let status = match head.start {
            StartLine::Response { status } => Some(status),
            _ => None,
        };
        let start = self.off;
        let len = self.buf.len() as u64;
        let ts = self.buf_ts;
        self.buf.clear();
        let reply = out.head(0, start, ts, head);
        self.label(out, len, Lab::Msg(0));
        let end_now = |me: &mut Self, out: &mut dyn Out, next: St| {
            out.end(0, me.off, me.last_ts, true);
            me.st = next;
        };
        match status {
            Some(101) => return end_now(self, out, St::Tunnel),
            // Interim responses have no body and no end of their own.
            Some(100..=199) => {
                self.st = St::Idle;
                return;
            }
            Some(s) if reply.tunnel && (200..300).contains(&s) => return end_now(self, out, St::Tunnel),
            Some(204) | Some(304) => return end_now(self, out, St::Idle),
            Some(_) if reply.no_body => return end_now(self, out, St::Idle),
            _ => {}
        }
        match framing {
            Framing::None | Framing::Length(0) => end_now(self, out, St::Idle),
            Framing::Length(n) => self.st = St::Body(n),
            Framing::Chunked => self.st = St::ChunkSize,
            Framing::UntilClose => self.st = St::UntilClose,
        }
    }
}

/// Parses a head ending in CRLF CRLF.
fn parse_head(buf: &[u8], request: bool) -> Result<Head, &'static str> {
    let text = &buf[..buf.len() - 2];
    let line_end = find(text, b"\r\n").ok_or("bad_head")?;
    let line = &text[..line_end];
    let start = if request {
        parse_request_line(line).ok_or("bad_request_line")?
    } else {
        parse_status_line(line).ok_or("bad_status_line")?
    };
    let headers = parse_fields(&text[line_end + 2..])?;
    Ok(Head { start, headers })
}

/// `method SP request-target SP HTTP/1.x`.
pub(crate) fn parse_request_line(line: &[u8]) -> Option<StartLine> {
    let mut parts = line.split(|&b| b == b' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || method.is_empty()
        || method.len() > 32
        || !method.iter().all(|&b| is_tchar(b))
        || target.is_empty()
        || !target.iter().all(|&b| (0x21..=0x7e).contains(&b))
        || !is_version(version)
    {
        return None;
    }
    Some(StartLine::Request {
        method: String::from_utf8_lossy(method).into_owned(),
        target: String::from_utf8_lossy(target).into_owned(),
    })
}

/// `HTTP/1.x SP 3DIGIT [SP reason-phrase]`.
pub(crate) fn parse_status_line(line: &[u8]) -> Option<StartLine> {
    if line.len() < 12 || !is_version(&line[..8]) || line[8] != b' ' {
        return None;
    }
    let code = &line[9..12];
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let rest = &line[12..];
    if !rest.is_empty() && (rest[0] != b' ' || rest[1..].iter().any(|&b| is_ctl(b) && b != b'\t')) {
        return None;
    }
    let status = code.iter().fold(0u16, |a, &d| a * 10 + u16::from(d - b'0'));
    Some(StartLine::Response { status })
}

fn is_version(v: &[u8]) -> bool {
    v.len() == 8 && v.starts_with(b"HTTP/1.") && v[7].is_ascii_digit()
}

fn is_ctl(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

/// Header field lines, each ending in CRLF. Names are lowercased; obsolete
/// line folding is rejected.
fn parse_fields(mut text: &[u8]) -> Result<Fields, &'static str> {
    let mut fields = Vec::new();
    while !text.is_empty() {
        let end = find(text, b"\r\n").ok_or("bad_header")?;
        let line = &text[..end];
        text = &text[end + 2..];
        let colon = line.iter().position(|&b| b == b':').ok_or("bad_header")?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err("bad_header");
        }
        let value = line[colon + 1..].trim_ascii();
        if value.iter().any(|&b| is_ctl(b) && b != b'\t') {
            return Err("bad_header");
        }
        fields.push((name.to_ascii_lowercase(), value.to_vec()));
    }
    Ok(fields)
}

fn framing(head: &Head, request: bool) -> Result<Framing, &'static str> {
    let codings: Vec<String> = head
        .all("transfer-encoding")
        .flat_map(|v| v.split(|&b| b == b','))
        .map(|c| String::from_utf8_lossy(c).trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    if !codings.is_empty() {
        return match (codings.last().map(String::as_str), request) {
            (Some("chunked"), _) => Ok(Framing::Chunked),
            (_, true) => Err("bad_transfer_encoding"),
            (_, false) => Ok(Framing::UntilClose),
        };
    }
    let mut length: Option<u64> = None;
    for v in head.all("content-length") {
        for part in v.split(|&b| b == b',') {
            let part = part.trim_ascii();
            if part.is_empty() || part.len() > 18 || !part.iter().all(u8::is_ascii_digit) {
                return Err("bad_content_length");
            }
            let n = part.iter().fold(0u64, |a, &d| a * 10 + u64::from(d - b'0'));
            if length.is_some_and(|l| l != n) {
                return Err("bad_content_length");
            }
            length = Some(n);
        }
    }
    Ok(match (length, request) {
        (Some(n), _) => Framing::Length(n),
        (None, true) => Framing::None,
        (None, false) => Framing::UntilClose,
    })
}

/// The size from a chunk-size line (`hex [; ext] CRLF`).
fn chunk_size(line: &[u8]) -> Option<u64> {
    let line = line.strip_suffix(b"\r\n")?;
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 15 {
        return None;
    }
    let rest = &line[digits..];
    if !rest.is_empty() && !matches!(rest[0], b';' | b' ' | b'\t') {
        return None;
    }
    if rest.iter().any(|&b| is_ctl(b) && b != b'\t') {
        return None;
    }
    let s = std::str::from_utf8(&line[..digits]).ok()?;
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http::HeadReply;

    /// Records what a parser reports, as text.
    #[derive(Default)]
    pub(crate) struct Log {
        pub spans: Vec<(u64, Lab)>,
        pub events: Vec<String>,
        pub body: Vec<u8>,
        pub reply: HeadReply,
    }

    impl Log {
        /// Spans with neighbours of the same label merged.
        pub fn merged(&self) -> Vec<(u64, Lab)> {
            let mut out: Vec<(u64, Lab)> = Vec::new();
            for &(n, l) in &self.spans {
                match out.last_mut() {
                    Some((m, last)) if *last == l => *m += n,
                    _ => out.push((n, l)),
                }
            }
            out
        }
    }

    impl Out for Log {
        fn span(&mut self, len: u64, lab: Lab) {
            assert!(len > 0);
            self.spans.push((len, lab));
        }
        fn head(&mut self, stream: u32, start: u64, _ts: u64, head: Head) -> HeadReply {
            let s = match head.start {
                StartLine::Request { method, target } => format!("{method} {target}"),
                StartLine::Response { status } => status.to_string(),
                StartLine::Trailers => "trailers".into(),
            };
            self.events.push(format!("head {stream} @{start} {s}"));
            self.reply
        }
        fn body(&mut self, _stream: u32, data: &[u8], _ts: u64) {
            self.body.extend_from_slice(data);
        }
        fn body_gap(&mut self, stream: u32, len: u64) {
            self.events.push(format!("body_gap {stream} {len}"));
        }
        fn end(&mut self, stream: u32, end: u64, _ts: u64, complete: bool) {
            self.events.push(format!("end {stream} @{end} {complete}"));
        }
        fn reset(&mut self, stream: u32) {
            self.events.push(format!("reset {stream}"));
        }
        fn desync(&mut self, reason: &'static str) {
            self.events.push(format!("desync {reason}"));
        }
    }

    /// Feeds `input` one byte at a time and in one piece; both must agree.
    fn run(requests: bool, input: &[u8]) -> Log {
        let mut whole = Log::default();
        let mut p = H1::new(requests);
        p.data(input, 1, &mut whole);
        p.finish(&mut whole);
        let mut bytes = Log::default();
        let mut p = H1::new(requests);
        for b in input {
            p.data(std::slice::from_ref(b), 1, &mut bytes);
        }
        p.finish(&mut bytes);
        assert_eq!(whole.merged(), bytes.merged());
        assert_eq!(whole.events, bytes.events);
        assert_eq!(whole.body, bytes.body);
        let total: u64 = whole.spans.iter().map(|s| s.0).sum();
        assert_eq!(total, input.len() as u64, "every byte labeled once");
        whole
    }

    #[test]
    fn content_length_request() {
        let req = b"POST /v1/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n{}{}";
        let log = run(true, req);
        assert_eq!(log.events, ["head 0 @0 POST /v1/completions", "end 0 @65 true"]);
        assert_eq!(log.merged(), [(65, Lab::Msg(0))]);
        assert_eq!(log.body, b"{}{}");
    }

    #[test]
    fn chunked_response_with_trailers_then_keep_alive() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            5;x=y\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n\
            HTTP/1.1 204 No Content\r\n\r\n";
        let log = run(false, resp);
        let head1 = 47;
        assert_eq!(
            log.merged(),
            [
                (head1, Lab::Msg(0)),
                (7, Lab::Framing),
                (5, Lab::Msg(0)),
                (2 + 3, Lab::Framing),
                (6, Lab::Msg(0)),
                (2 + 3, Lab::Framing),
                (8, Lab::Msg(0)),
                (2, Lab::Framing),
                (27, Lab::Msg(0)),
            ]
        );
        assert_eq!(log.body, b"hello world");
        assert_eq!(
            log.events,
            [
                "head 0 @0 200",
                "end 0 @85 true",
                "head 0 @85 204",
                "end 0 @112 true"
            ]
        );
    }

    #[test]
    fn response_until_close_and_head_reply() {
        let log = run(false, b"HTTP/1.0 200 OK\r\n\r\nabc");
        assert_eq!(log.events, ["head 0 @0 200", "end 0 @22 true"]);
        let mut log = Log {
            reply: HeadReply {
                no_body: true,
                tunnel: false,
            },
            ..Log::default()
        };
        let mut p = H1::new(false);
        p.data(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            1,
            &mut log,
        );
        assert_eq!(
            log.events[..3],
            ["head 0 @0 200", "end 0 @38 true", "head 0 @38 200"]
        );
    }

    #[test]
    fn interim_response_then_final() {
        let log = run(
            false,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
        );
        assert_eq!(log.events, ["head 0 @0 100", "head 0 @25 200", "end 0 @64 true"]);
    }

    #[test]
    fn gap_in_body_is_skipped_but_in_head_desyncs() {
        let mut log = Log::default();
        let mut p = H1::new(true);
        p.data(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nab", 1, &mut log);
        p.gap(5, &mut log);
        p.data(b"cdeGET / HTTP/1.1\r\n", 2, &mut log);
        p.gap(3, &mut log);
        p.data(b"zz", 3, &mut log);
        p.finish(&mut log);
        assert_eq!(
            log.events,
            ["head 0 @0 POST /", "body_gap 0 5", "end 0 @49 true", "desync gap"]
        );
        assert_eq!(
            log.merged(),
            [
                (41, Lab::Msg(0)),
                (5, Lab::Gap),
                (3, Lab::Msg(0)),
                (16, Lab::Unexplained),
                (3, Lab::Gap),
                (2, Lab::Unexplained),
            ]
        );
    }

    #[test]
    fn truncated_message_at_end() {
        let log = run(true, b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nab");
        assert_eq!(log.events, ["head 0 @0 POST /", "end 0 @41 false"]);
        let log = run(true, b"POST / HTTP/1.1\r\nHost");
        assert!(log.events.is_empty());
        assert_eq!(log.merged(), [(21, Lab::Unexplained)]);
    }

    #[test]
    fn garbage_desyncs() {
        for (req, input) in [
            (true, &b"\x16\x03\x01\x02\x00"[..]),
            (true, b"GET /a b HTTP/1.1\r\n\r\n"),
            (true, b"GET / HTTP/1.1\r\n folded\r\n\r\n"),
            (
                true,
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            ),
            (true, b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n"),
            (false, b"HTTP/1.1 2000 OK\r\n\r\n"),
            (false, b"data: x\n\n"),
        ] {
            let log = run(req, input);
            assert!(
                log.events.last().unwrap().starts_with("desync"),
                "{input:?}: {:?}",
                log.events
            );
            assert_eq!(
                log.merged(),
                [(input.len() as u64, Lab::Unexplained)],
                "{input:?}"
            );
        }
    }

    #[test]
    fn bad_chunk_size_desyncs_mid_message() {
        let log = run(
            false,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        );
        assert_eq!(
            log.events,
            ["head 0 @0 200", "end 0 @47 false", "desync bad_chunk_size"]
        );
    }

    #[test]
    fn chunk_size_parsing() {
        assert_eq!(chunk_size(b"1a\r\n"), Some(26));
        assert_eq!(chunk_size(b"A;name=v\r\n"), Some(10));
        assert_eq!(chunk_size(b"\r\n"), None);
        assert_eq!(chunk_size(b"1g\r\n"), None);
        assert_eq!(chunk_size(b"1000000000000000\r\n"), None);
    }
}
