//! Server-sent events (the WHATWG `text/event-stream` format), split out of
//! a response body as it arrives.
//!
//! Lines end in CRLF, LF or CR; a blank line ends an event. Only events
//! with at least one `data` field are reported. A gap in the body loses the
//! event boundaries, so parsing stops there.

/// Longest line kept; longer lines are dropped, not truncated.
const MAX_LINE: usize = 16 << 20;

/// One event: where it lies in the (de-chunked) body and when its last
/// byte was captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub body_off: u64,
    pub len: u64,
    pub ts_ns: u64,
    /// The `data` fields joined with `\n`.
    pub data: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct Sse {
    /// Body offset of the next byte.
    off: u64,
    line: Vec<u8>,
    line_too_long: bool,
    /// The previous byte was a CR, so an LF right after it is part of the
    /// same line ending.
    after_cr: bool,
    /// Body offset where the current event began.
    event_start: Option<u64>,
    data: Vec<u8>,
    has_data: bool,
    /// Stopped at a gap.
    pub broken: bool,
}

impl Sse {
    pub fn push(&mut self, bytes: &[u8], ts_ns: u64, events: &mut Vec<Event>) {
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
                    self.end_line(ts_ns, events);
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

    pub fn gap(&mut self) {
        self.broken = true;
    }

    fn end_line(&mut self, ts_ns: u64, events: &mut Vec<Event>) {
        let line = std::mem::take(&mut self.line);
        let too_long = std::mem::take(&mut self.line_too_long);
        if line.is_empty() && !too_long {
            if let Some(start) = self.event_start.take() {
                if self.has_data {
                    let mut data = std::mem::take(&mut self.data);
                    data.pop();
                    events.push(Event {
                        body_off: start,
                        len: self.off - start,
                        ts_ns,
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
        if name == b"data" {
            self.data.extend_from_slice(value);
            self.data.push(b'\n');
            self.has_data = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(chunks: &[&[u8]]) -> Vec<Event> {
        let mut s = Sse::default();
        let mut out = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            s.push(c, i as u64, &mut out);
        }
        out
    }

    #[test]
    fn splits_events_across_chunks_and_line_endings() {
        let ev = events(&[
            b"data: {\"a\":1}\n\ndata: x\r",
            b"\ndata:y\r\n\r\n: comment\n\nevent: e\ndata: [DONE]\r\r",
        ]);
        let got: Vec<(u64, u64, u64, &[u8])> = ev
            .iter()
            .map(|e| (e.body_off, e.len, e.ts_ns, e.data.as_slice()))
            .collect();
        assert_eq!(
            got,
            [
                (0, 15, 0, &b"{\"a\":1}"[..]),
                (15, 18, 1, &b"x\ny"[..]),
                (45, 23, 1, &b"[DONE]"[..]),
            ]
        );
    }

    #[test]
    fn gap_stops_parsing() {
        let mut s = Sse::default();
        let mut out = Vec::new();
        s.push(b"data: a", 0, &mut out);
        s.gap();
        s.push(b"\n\ndata: b\n\n", 1, &mut out);
        assert!(out.is_empty() && s.broken);
    }
}
