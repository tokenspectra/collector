//! Response body framing shared by every Wire Protocol (spec §5): bytes in,
//! frames out, so a protocol only ever sees whole events.
//!
//! - [`Framing::Sse`]: server-sent events (the WHATWG `text/event-stream`
//!   format). Lines end in CRLF, LF or CR; a blank line ends an event. Only
//!   events with at least one `data` field are reported, with their `event`
//!   name when they have one, so the same framer serves data-only streams
//!   (OpenAI Chat) and named-event streams (OpenAI Responses, Anthropic). A
//!   gap loses the event boundaries, so framing stops there.
//! - [`Framing::Ndjson`]: one JSON value per line (Ollama native). Lines end
//!   in LF, with an optional CR before it; blank lines are skipped. A JSON
//!   line never holds a raw newline, so after a gap framing drops the cut
//!   line and starts again at the next one.
//! - [`Framing::Json`]: the whole body is one frame, read once it is
//!   complete. It has no framer.

/// Longest line kept; longer lines are dropped, not truncated.
const MAX_LINE: usize = 16 << 20;

/// How a response body is cut into frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    /// The whole body is one JSON document.
    Json,
    /// Server-sent events, with or without `event:` names.
    Sse,
    /// Newline-delimited JSON.
    Ndjson,
}

impl Framing {
    /// The framing a media type (lowercase, no parameters) implies, if any.
    pub fn of_media_type(media_type: Option<&str>) -> Option<Framing> {
        match media_type? {
            "application/json" => Some(Framing::Json),
            "text/event-stream" => Some(Framing::Sse),
            "application/x-ndjson"
            | "application/ndjson"
            | "application/jsonl"
            | "application/x-jsonlines" => Some(Framing::Ndjson),
            _ => None,
        }
    }

    /// Whether bytes are framed as they arrive.
    pub fn is_stream(self) -> bool {
        self != Framing::Json
    }
}

/// What a protocol decoder is handed: one event, one line, or a whole body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The SSE `event` name; `None` for data-only events and other framings.
    pub event: Option<&'a [u8]>,
    /// SSE: the `data` fields joined with `\n`. NDJSON: the line without its
    /// ending. JSON: the whole body.
    pub data: &'a [u8],
}

/// One frame cut from a streamed body: where it lies in the (de-chunked)
/// body and when its last byte was captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Framed {
    pub body_off: u64,
    pub len: u64,
    pub ts_ns: u64,
    pub event: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

impl Framed {
    pub fn frame(&self) -> Frame<'_> {
        Frame {
            event: self.event.as_deref(),
            data: &self.data,
        }
    }
}

/// A streaming framer: [`Framing::Sse`] or [`Framing::Ndjson`].
pub enum Framer {
    Sse(Sse),
    Ndjson(Ndjson),
}

impl Framer {
    /// The framer for `framing`; `None` for [`Framing::Json`].
    pub fn new(framing: Framing) -> Option<Self> {
        match framing {
            Framing::Json => None,
            Framing::Sse => Some(Framer::Sse(Sse::default())),
            Framing::Ndjson => Some(Framer::Ndjson(Ndjson::default())),
        }
    }

    /// Takes in body bytes captured at `ts_ns`; frames they complete go to
    /// `out`.
    pub fn push(&mut self, bytes: &[u8], ts_ns: u64, out: &mut Vec<Framed>) {
        match self {
            Framer::Sse(s) => s.push(bytes, ts_ns, out),
            Framer::Ndjson(n) => n.push(bytes, ts_ns, out),
        }
    }

    /// `len` body bytes were never captured.
    pub fn gap(&mut self, len: u64) {
        match self {
            Framer::Sse(s) => s.gap(len),
            Framer::Ndjson(n) => n.gap(len),
        }
    }

    /// The body ended at `ts_ns`; a last frame without its ending goes to
    /// `out` where the framing allows one.
    pub fn finish(&mut self, ts_ns: u64, out: &mut Vec<Framed>) {
        match self {
            // An unterminated event is discarded (WHATWG).
            Framer::Sse(_) => {}
            Framer::Ndjson(n) => n.finish(ts_ns, out),
        }
    }

    /// Frames lost to a gap or an over-long line. The protocol never saw
    /// them, so the response was not read whole.
    pub fn lost(&self) -> u64 {
        match self {
            Framer::Sse(s) => u64::from(s.broken),
            Framer::Ndjson(n) => n.lost,
        }
    }
}

#[derive(Default)]
pub struct Sse {
    /// Body offset of the next byte.
    off: u64,
    line: Vec<u8>,
    line_too_long: bool,
    /// The previous byte was a CR, so an LF right after it is part of the
    /// same line ending.
    after_cr: bool,
    /// Body offset where the current event began.
    event_start: Option<u64>,
    event: Option<Vec<u8>>,
    data: Vec<u8>,
    has_data: bool,
    /// Stopped at a gap.
    broken: bool,
}

impl Sse {
    pub fn push(&mut self, bytes: &[u8], ts_ns: u64, out: &mut Vec<Framed>) {
        if self.broken {
            return;
        }
        for &b in bytes {
            let at = self.off;
            self.off += 1;
            if self.after_cr {
                self.after_cr = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\r' | b'\n' => {
                    self.after_cr = b == b'\r';
                    self.end_line(ts_ns, out);
                }
                _ => {
                    self.event_start.get_or_insert(at);
                    if self.line.len() < MAX_LINE {
                        self.line.push(b);
                    } else {
                        self.line_too_long = true;
                    }
                }
            }
        }
    }

    pub fn gap(&mut self, _len: u64) {
        self.broken = true;
    }

    fn end_line(&mut self, ts_ns: u64, out: &mut Vec<Framed>) {
        let line = std::mem::take(&mut self.line);
        let too_long = std::mem::take(&mut self.line_too_long);
        if line.is_empty() && !too_long {
            let event = self.event.take();
            if let Some(start) = self.event_start.take() {
                if self.has_data {
                    let mut data = std::mem::take(&mut self.data);
                    data.pop();
                    out.push(Framed {
                        body_off: start,
                        len: self.off - start,
                        ts_ns,
                        event,
                        data,
                    });
                }
            }
            self.data.clear();
            self.has_data = false;
            return;
        }
        if too_long || line.starts_with(b":") {
            return;
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (&line[..], &b""[..]),
        };
        match name {
            b"data" => {
                self.data.extend_from_slice(value);
                self.data.push(b'\n');
                self.has_data = true;
            }
            b"event" => self.event = Some(value.to_vec()),
            _ => {}
        }
    }
}

#[derive(Default)]
pub struct Ndjson {
    /// Body offset of the next byte.
    off: u64,
    /// Body offset where the current line began.
    start: u64,
    line: Vec<u8>,
    line_too_long: bool,
    /// Skipping the rest of a line cut by a gap.
    resync: bool,
    lost: u64,
}

impl Ndjson {
    pub fn push(&mut self, bytes: &[u8], ts_ns: u64, out: &mut Vec<Framed>) {
        for &b in bytes {
            self.off += 1;
            if b == b'\n' {
                self.end_line(ts_ns, out);
                continue;
            }
            if self.resync {
                continue;
            }
            if self.line.len() < MAX_LINE {
                self.line.push(b);
            } else {
                self.line_too_long = true;
            }
        }
    }

    pub fn gap(&mut self, len: u64) {
        if !self.resync && (!self.line.is_empty() || self.line_too_long) {
            self.lost += 1;
        }
        self.line.clear();
        self.line_too_long = false;
        self.off += len;
        // The bytes after the gap may be the middle of a line.
        self.resync = true;
    }

    pub fn finish(&mut self, ts_ns: u64, out: &mut Vec<Framed>) {
        if !self.line.is_empty() || self.line_too_long {
            self.end_line(ts_ns, out);
        }
    }

    fn end_line(&mut self, ts_ns: u64, out: &mut Vec<Framed>) {
        let start = std::mem::replace(&mut self.start, self.off);
        let mut line = std::mem::take(&mut self.line);
        let too_long = std::mem::take(&mut self.line_too_long);
        if std::mem::take(&mut self.resync) {
            return;
        }
        if too_long {
            self.lost += 1;
            return;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        out.push(Framed {
            body_off: start,
            len: self.off - start,
            ts_ns,
            event: None,
            data: line,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (body offset, length, ts, event name, data)
    type Got = (u64, u64, u64, Option<String>, String);

    enum In<'a> {
        Bytes(&'a [u8]),
        Gap(u64),
    }

    fn run(framing: Framing, input: &[In]) -> (Vec<Got>, u64) {
        let mut f = Framer::new(framing).unwrap();
        let mut out = Vec::new();
        for (i, piece) in input.iter().enumerate() {
            match piece {
                In::Bytes(b) => f.push(b, i as u64, &mut out),
                In::Gap(n) => f.gap(*n),
            }
        }
        f.finish(input.len() as u64, &mut out);
        let got = out
            .iter()
            .map(|e| {
                (
                    e.body_off,
                    e.len,
                    e.ts_ns,
                    e.event.as_ref().map(|n| String::from_utf8_lossy(n).into_owned()),
                    String::from_utf8_lossy(&e.data).into_owned(),
                )
            })
            .collect();
        (got, f.lost())
    }

    fn ev(
        off: u64,
        len: u64,
        ts: u64,
        name: Option<&str>,
        data: &str,
    ) -> (u64, u64, u64, Option<String>, String) {
        (off, len, ts, name.map(str::to_owned), data.to_owned())
    }

    #[test]
    fn media_types() {
        assert_eq!(
            Framing::of_media_type(Some("application/json")),
            Some(Framing::Json)
        );
        assert_eq!(
            Framing::of_media_type(Some("text/event-stream")),
            Some(Framing::Sse)
        );
        assert_eq!(
            Framing::of_media_type(Some("application/x-ndjson")),
            Some(Framing::Ndjson)
        );
        assert_eq!(Framing::of_media_type(Some("text/plain")), None);
        assert_eq!(Framing::of_media_type(None), None);
        assert!(Framer::new(Framing::Json).is_none());
    }

    #[test]
    fn sse_data_only_split_across_segments_and_line_endings() {
        let (got, lost) = run(
            Framing::Sse,
            &[
                In::Bytes(b"data: {\"a\":1}\n\ndata: x\r"),
                In::Bytes(b"\ndata:y\r\n\r\n: comment\n\nevent: e\ndata: [DONE]\r\r"),
            ],
        );
        assert_eq!(
            got,
            [
                ev(0, 15, 0, None, "{\"a\":1}"),
                ev(15, 18, 1, None, "x\ny"),
                ev(45, 23, 1, Some("e"), "[DONE]"),
            ]
        );
        assert_eq!(lost, 0);
    }

    #[test]
    fn sse_named_events_split_byte_by_byte() {
        let body: &[u8] = b"event: message_start\ndata: {\"t\":1}\n\nevent: ping\ndata: {}\n\nid: 3\nevent: delta\ndata: a\ndata: b\n\nevent: no_data\n\n";
        let pieces: Vec<In> = body.chunks(1).map(In::Bytes).collect();
        let (got, lost) = run(Framing::Sse, &pieces);
        assert_eq!(
            got,
            [
                ev(0, 36, 35, Some("message_start"), "{\"t\":1}"),
                ev(36, 22, 57, Some("ping"), "{}"),
                ev(58, 36, 93, Some("delta"), "a\nb"),
            ]
        );
        assert_eq!(lost, 0);
        // The name does not leak into the next event.
        let (got, _) = run(Framing::Sse, &[In::Bytes(b"event: x\n\ndata: y\n\n")]);
        assert_eq!(got, [ev(10, 9, 0, None, "y")]);
    }

    #[test]
    fn sse_stops_at_a_gap() {
        let (got, lost) = run(
            Framing::Sse,
            &[
                In::Bytes(b"event: a\ndata: 1\n\ndata: 2"),
                In::Gap(5),
                In::Bytes(b"\n\ndata: 3\n\n"),
            ],
        );
        assert_eq!(got, [ev(0, 18, 0, Some("a"), "1")]);
        assert_eq!(lost, 1);
    }

    #[test]
    fn ndjson_lines_split_across_segments() {
        let (got, lost) = run(
            Framing::Ndjson,
            &[
                In::Bytes(b"{\"a\":1}\n{\"b\""),
                In::Bytes(b":2}\r\n\n  \n{\"c\":3}"),
            ],
        );
        assert_eq!(
            got,
            [
                ev(0, 8, 0, None, "{\"a\":1}"),
                ev(8, 9, 1, None, "{\"b\":2}"),
                // No final newline: flushed when the body ends.
                ev(21, 7, 2, None, "{\"c\":3}"),
            ]
        );
        assert_eq!(lost, 0);
    }

    #[test]
    fn ndjson_resumes_after_a_gap() {
        let (got, lost) = run(
            Framing::Ndjson,
            &[
                In::Bytes(b"{\"a\":1}\n{\"b\":"),
                In::Gap(4),
                In::Bytes(b"tail}\n{\"c\":3}\n"),
                In::Gap(3),
                In::Bytes(b"x\n{\"d\":4}\n"),
            ],
        );
        assert_eq!(
            got,
            [
                ev(0, 8, 0, None, "{\"a\":1}"),
                ev(23, 8, 2, None, "{\"c\":3}"),
                ev(36, 8, 4, None, "{\"d\":4}"),
            ]
        );
        // The line cut by the first gap is lost. The second gap fell on a
        // line boundary, but the bytes after it might be a line's tail, so
        // they are dropped without being counted as a lost frame.
        assert_eq!(lost, 1);
    }

    #[test]
    fn ndjson_byte_by_byte_matches_one_push() {
        let body: &[u8] = b"{\"m\":\"x\",\"done\":false}\n{\"done\":true}\n";
        let whole = run(Framing::Ndjson, &[In::Bytes(body)]).0;
        let split = run(
            Framing::Ndjson,
            &body.chunks(1).map(In::Bytes).collect::<Vec<_>>(),
        )
        .0;
        let strip = |v: Vec<Got>| {
            v.into_iter()
                .map(|(o, l, _, n, d)| (o, l, n, d))
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(whole), strip(split));
    }
}
