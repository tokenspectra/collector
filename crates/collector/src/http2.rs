//! HTTP/2 framing of one direction of a Flow (RFC 9113), for cleartext h2c
//! with prior knowledge.
//!
//! Frame headers, the client preface, padding, priority fields and the
//! SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY and RST_STREAM frames are
//! framing. Header blocks and DATA payloads belong to their stream's
//! message; PUSH_PROMISE header blocks are HTTP but never a Workunit. Frames
//! of unknown type are unexplained: they carry bytes nobody parses.
//!
//! A gap inside a frame whose length is known (DATA payload, padding, skipped
//! frames) keeps sync. A gap in a frame header or a header block loses it:
//! frame boundaries or the HPACK table are gone.

use crate::hpack;
use crate::http::{Head, Lab, Out, StartLine};

pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// Largest frame payload buffered whole (header blocks, RST_STREAM), and
/// largest header block.
const MAX_BUFFERED: u32 = 1 << 20;

#[derive(Clone, Copy, Debug)]
struct Frame {
    len: u32,
    ty: u8,
    flags: u8,
    stream: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    /// The client preface; this many bytes matched.
    Preface(usize),
    /// Reading a 9-byte frame header into `buf`.
    Header,
    /// Reading the whole payload into `buf`.
    Buffer,
    /// The pad-length byte of a padded DATA frame.
    DataPad,
    /// DATA payload: bytes left, then padding.
    DataBody {
        left: u32,
        pad: u32,
    },
    /// Payload bytes passed over with one label.
    Skip {
        left: u32,
        lab: Lab,
    },
    Dead,
}

/// A header block in progress (HEADERS or PUSH_PROMISE, then
/// CONTINUATION frames until END_HEADERS).
struct Block {
    stream: u32,
    /// Stream offset of the frame that opened it.
    start: u64,
    ts_ns: u64,
    fragment: Vec<u8>,
    end_stream: bool,
    push: bool,
    /// Labels held back until the head is reported, so the decoder knows
    /// the message before seeing its bytes.
    spans: Vec<(u64, Lab)>,
}

pub(crate) struct H2 {
    /// Stream offset of the next byte to read.
    off: u64,
    st: St,
    /// Bytes read but not labeled yet.
    buf: Vec<u8>,
    frame: Frame,
    frame_start: u64,
    frame_ts: u64,
    block: Option<Block>,
    hpack: hpack::Decoder,
    last_ts: u64,
}

impl H2 {
    /// `client`: this direction starts with the connection preface.
    pub fn new(client: bool) -> Self {
        H2 {
            off: 0,
            st: if client { St::Preface(0) } else { St::Header },
            buf: Vec::new(),
            frame: Frame {
                len: 0,
                ty: 0,
                flags: 0,
                stream: 0,
            },
            frame_start: 0,
            frame_ts: 0,
            block: None,
            hpack: hpack::Decoder::default(),
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

    pub fn gap(&mut self, mut len: u64, out: &mut dyn Out) {
        while len > 0 {
            match self.st {
                St::DataBody { left, pad } if left > 0 => {
                    let n = len.min(u64::from(left));
                    out.body_gap(self.frame.stream, n);
                    self.label(out, n, Lab::Gap);
                    len -= n;
                    self.st = St::DataBody {
                        left: left - n as u32,
                        pad,
                    };
                    self.after_data(out);
                }
                St::Skip { left, lab } => {
                    let n = len.min(u64::from(left));
                    self.label(out, n, Lab::Gap);
                    len -= n;
                    self.st = St::Skip {
                        left: left - n as u32,
                        lab,
                    };
                    if n == u64::from(left) {
                        self.frame_done(out);
                    }
                }
                St::Dead => {
                    self.label(out, len, Lab::Gap);
                    len = 0;
                }
                _ => self.desync(out, "gap"),
            }
        }
    }

    /// End of the stream: unfinished frames are unexplained.
    pub fn finish(&mut self, out: &mut dyn Out) {
        self.flush_unlabeled(out);
        self.st = St::Dead;
    }

    fn label(&mut self, out: &mut dyn Out, len: u64, lab: Lab) {
        if len == 0 {
            return;
        }
        self.off += len;
        match &mut self.block {
            Some(b) => b.spans.push((len, lab)),
            None => out.span(len, lab),
        }
    }

    /// Labels everything read but not labeled yet as unexplained.
    fn flush_unlabeled(&mut self, out: &mut dyn Out) {
        if let Some(b) = self.block.take() {
            for (len, lab) in b.spans {
                let lab = if lab == Lab::Gap {
                    Lab::Gap
                } else {
                    Lab::Unexplained
                };
                out.span(len, lab);
            }
        }
        let n = std::mem::take(&mut self.buf).len() as u64;
        self.label(out, n, Lab::Unexplained);
    }

    fn desync(&mut self, out: &mut dyn Out, reason: &'static str) {
        out.desync(reason);
        self.flush_unlabeled(out);
        self.st = St::Dead;
    }

    fn step(&mut self, data: &[u8], ts: u64, out: &mut dyn Out) -> usize {
        match self.st {
            St::Preface(got) => {
                let n = data.len().min(PREFACE.len() - got);
                if data[..n] != PREFACE[got..got + n] {
                    self.desync(out, "bad_preface");
                    return 0;
                }
                self.buf.extend_from_slice(&data[..n]);
                if got + n == PREFACE.len() {
                    self.buf.clear();
                    self.label(out, PREFACE.len() as u64, Lab::Framing);
                    self.st = St::Header;
                } else {
                    self.st = St::Preface(got + n);
                }
                n
            }
            St::Header => {
                if self.buf.is_empty() {
                    self.frame_start = self.off;
                    self.frame_ts = ts;
                }
                let n = data.len().min(9 - self.buf.len());
                self.buf.extend_from_slice(&data[..n]);
                if self.buf.len() == 9 {
                    self.start_frame(out);
                }
                n
            }
            St::Buffer => {
                let n = data.len().min(self.frame.len as usize - self.buf.len());
                self.buf.extend_from_slice(&data[..n]);
                if self.buf.len() == self.frame.len as usize {
                    self.end_buffered(out);
                }
                n
            }
            St::DataPad => {
                let pad = u32::from(data[0]);
                if pad >= self.frame.len {
                    self.desync(out, "bad_padding");
                    return 0;
                }
                self.label(out, 1, Lab::Framing);
                self.st = St::DataBody {
                    left: self.frame.len - 1 - pad,
                    pad,
                };
                self.after_data(out);
                1
            }
            St::DataBody { left, pad } => {
                let n = data.len().min(left as usize);
                out.body(self.frame.stream, &data[..n], ts);
                self.label(out, n as u64, Lab::Msg(self.frame.stream));
                self.st = St::DataBody {
                    left: left - n as u32,
                    pad,
                };
                self.after_data(out);
                n
            }
            St::Skip { left, lab } => {
                let n = data.len().min(left as usize);
                self.label(out, n as u64, lab);
                self.st = St::Skip {
                    left: left - n as u32,
                    lab,
                };
                if n == left as usize {
                    self.frame_done(out);
                }
                n
            }
            St::Dead => {
                self.label(out, data.len() as u64, Lab::Unexplained);
                data.len()
            }
        }
    }

    /// Once DATA bytes are done, skip the padding, then finish the frame.
    fn after_data(&mut self, out: &mut dyn Out) {
        if let St::DataBody { left: 0, pad } = self.st {
            if pad > 0 {
                self.st = St::Skip {
                    left: pad,
                    lab: Lab::Framing,
                };
            } else {
                self.frame_done(out);
            }
        }
    }

    /// `buf` holds a frame header.
    fn start_frame(&mut self, out: &mut dyn Out) {
        let h = std::mem::take(&mut self.buf);
        let f = Frame {
            len: u32::from_be_bytes([0, h[0], h[1], h[2]]),
            ty: h[3],
            flags: h[4],
            stream: u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
        };
        self.frame = f;
        let in_block = self.block.as_ref().map(|b| b.stream);
        let ok = match (f.ty, in_block) {
            (CONTINUATION, Some(s)) => f.stream == s,
            (_, Some(_)) | (CONTINUATION, None) => false,
            (DATA | HEADERS | PUSH_PROMISE | RST_STREAM, None) => f.stream != 0,
            _ => true,
        };
        if !ok {
            self.buf = h;
            return self.desync(out, "bad_frame_sequence");
        }
        self.label(out, 9, Lab::Framing);
        self.st = match f.ty {
            DATA if f.flags & PADDED != 0 => {
                if f.len == 0 {
                    return self.desync(out, "bad_padding");
                }
                St::DataPad
            }
            DATA => St::DataBody { left: f.len, pad: 0 },
            HEADERS | PUSH_PROMISE | CONTINUATION | RST_STREAM => {
                if f.len > MAX_BUFFERED {
                    return self.desync(out, "frame_too_large");
                }
                St::Buffer
            }
            SETTINGS | PING | GOAWAY | WINDOW_UPDATE | PRIORITY => St::Skip {
                left: f.len,
                lab: Lab::Framing,
            },
            _ => St::Skip {
                left: f.len,
                lab: Lab::Unexplained,
            },
        };
        match self.st {
            St::Buffer if f.len == 0 => self.end_buffered(out),
            St::DataBody { left: 0, .. } => self.frame_done(out),
            St::Skip { left: 0, .. } => self.frame_done(out),
            _ => {}
        }
    }

    fn frame_done(&mut self, out: &mut dyn Out) {
        let f = self.frame;
        self.st = St::Header;
        if f.ty == DATA && f.flags & END_STREAM != 0 {
            out.end(f.stream, self.off, self.last_ts, true);
        }
    }

    /// `buf` holds a whole HEADERS, PUSH_PROMISE, CONTINUATION or
    /// RST_STREAM payload.
    fn end_buffered(&mut self, out: &mut dyn Out) {
        let f = self.frame;
        let p = std::mem::take(&mut self.buf);
        if f.ty == RST_STREAM {
            if p.len() != 4 {
                self.buf = p;
                return self.desync(out, "bad_rst_stream");
            }
            self.label(out, 4, Lab::Framing);
            out.reset(f.stream);
            return self.frame_done(out);
        }
        // Split the payload: [pad length] [priority | promised id] fragment [padding].
        let mut lead = 0usize;
        let mut pad = 0usize;
        if f.ty != CONTINUATION && f.flags & PADDED != 0 {
            pad = usize::from(*p.first().unwrap_or(&0));
            lead = 1;
        }
        if f.ty == HEADERS && f.flags & PRIORITY_FLAG != 0 {
            lead += 5;
        }
        if f.ty == PUSH_PROMISE {
            lead += 4;
        }
        if lead + pad > p.len() || (f.flags & PADDED != 0 && f.ty != CONTINUATION && p.is_empty()) {
            self.buf = p;
            return self.desync(out, "bad_padding");
        }
        let fragment = &p[lead..p.len() - pad];
        if f.ty != CONTINUATION {
            self.block = Some(Block {
                stream: f.stream,
                start: self.frame_start,
                ts_ns: self.frame_ts,
                fragment: Vec::new(),
                end_stream: f.ty == HEADERS && f.flags & END_STREAM != 0,
                push: f.ty == PUSH_PROMISE,
                spans: Vec::new(),
            });
        }
        let block = self.block.as_mut().expect("block open");
        if block.fragment.len() + fragment.len() > MAX_BUFFERED as usize {
            self.buf = p;
            return self.desync(out, "header_block_too_large");
        }
        block.fragment.extend_from_slice(fragment);
        let lab = if block.push {
            Lab::Other
        } else {
            Lab::Msg(f.stream)
        };
        self.label(out, lead as u64, Lab::Framing);
        self.label(out, fragment.len() as u64, lab);
        self.label(out, pad as u64, Lab::Framing);
        self.st = St::Header;
        if f.flags & END_HEADERS != 0 {
            self.end_block(out);
        }
    }

    fn end_block(&mut self, out: &mut dyn Out) {
        let block = self.block.as_ref().expect("block open");
        let list = match self.hpack.decode(&block.fragment) {
            Ok(list) => list,
            Err(_) => return self.desync(out, "hpack"),
        };
        let block = self.block.take().expect("block open");
        if !block.push {
            let head = match to_head(list) {
                Some(h) => h,
                None => {
                    self.block = Some(block);
                    return self.desync(out, "bad_pseudo_headers");
                }
            };
            out.head(block.stream, block.start, block.ts_ns, head);
        }
        for (len, lab) in block.spans {
            out.span(len, lab);
        }
        if block.end_stream {
            out.end(block.stream, self.off, self.last_ts, true);
        }
    }
}

/// Splits pseudo-headers from fields.
fn to_head(list: hpack::HeaderList) -> Option<Head> {
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut status = None;
    let mut headers = Vec::new();
    for (name, value) in list {
        let v = || String::from_utf8_lossy(&value).into_owned();
        match name.as_slice() {
            b":method" => method = Some(v()),
            b":path" => path = Some(v()),
            b":authority" => authority = Some(v()),
            b":status" => status = Some(v()),
            n if n.starts_with(b":") => {}
            _ => headers.push((name.to_ascii_lowercase(), value)),
        }
    }
    let start = match (method, status) {
        (Some(method), None) => StartLine::Request {
            target: path.or(authority).unwrap_or_default(),
            method,
        },
        (None, Some(s)) => {
            let status = s.parse::<u16>().ok().filter(|s| (100..1000).contains(s))?;
            StartLine::Response { status }
        }
        (None, None) => StartLine::Trailers,
        (Some(_), Some(_)) => return None,
    };
    Some(Head { start, headers })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hpack::tests::hex;
    use crate::http1::tests::Log;

    pub(crate) fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = len.to_be_bytes()[1..].to_vec();
        f.push(ty);
        f.push(flags);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A literal header field without indexing, new name, no Huffman.
    pub(crate) fn lit(name: &str, value: &str) -> Vec<u8> {
        assert!(name.len() < 127 && value.len() < 127);
        let mut b = vec![0x00, name.len() as u8];
        b.extend_from_slice(name.as_bytes());
        b.push(value.len() as u8);
        b.extend_from_slice(value.as_bytes());
        b
    }

    fn run(client: bool, input: &[u8]) -> Log {
        let mut whole = Log::default();
        let mut p = H2::new(client);
        p.data(input, 1, &mut whole);
        p.finish(&mut whole);
        let mut bytes = Log::default();
        let mut p = H2::new(client);
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
    fn client_request_with_continuation_and_padded_data() {
        let mut input = PREFACE.to_vec();
        input.extend(frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]));
        // :method POST, :scheme http, :path from a Python-encoded block.
        let block = hex("8386448e63b85824e34b043d35d05498f523");
        let (a, b) = block.split_at(5);
        input.extend(frame(
            HEADERS,
            PADDED | PRIORITY_FLAG,
            1,
            &[[2u8].as_slice(), &[0; 5], a, &[0, 0]].concat(),
        ));
        input.extend(frame(CONTINUATION, END_HEADERS, 1, b));
        input.extend(frame(DATA, PADDED | END_STREAM, 1, b"\x03{}xyz"));
        input.extend(frame(WINDOW_UPDATE, 0, 0, &[0, 0, 1, 0]));
        let log = run(true, &input);
        assert_eq!(
            log.events,
            ["head 1 @39 POST /v1/chat/completions", "end 1 @98 true"]
        );
        assert_eq!(log.body, b"{}");
        assert_eq!(
            log.merged(),
            [
                (24 + 15 + 9 + 6, Lab::Framing),
                (5, Lab::Msg(1)),
                (2 + 9, Lab::Framing),
                (13, Lab::Msg(1)),
                (9 + 1, Lab::Framing),
                (2, Lab::Msg(1)),
                (3 + 13, Lab::Framing),
            ]
        );
    }

    #[test]
    fn server_response_trailers_reset_and_push() {
        let mut input = frame(SETTINGS, 0, 0, b"");
        let status = [0x88u8]; // :status 200
        input.extend(frame(
            HEADERS,
            END_HEADERS,
            1,
            &[&status[..], &lit("content-type", "text/event-stream")].concat(),
        ));
        input.extend(frame(DATA, 0, 1, b"data: x\n\n"));
        input.extend(frame(
            HEADERS,
            END_HEADERS | END_STREAM,
            1,
            &lit("grpc-status", "0"),
        ));
        input.extend(frame(
            PUSH_PROMISE,
            END_HEADERS,
            1,
            &[&[0, 0, 0, 2][..], &hex("8284")].concat(),
        ));
        input.extend(frame(RST_STREAM, 0, 3, &[0, 0, 0, 8]));
        input.extend(frame(0xfa, 0, 0, b"secret"));
        let log = run(false, &input);
        assert_eq!(
            log.events,
            [
                "head 1 @9 200",
                "head 1 @69 trailers",
                "end 1 @93 true",
                "reset 3"
            ]
        );
        let merged = log.merged();
        assert_eq!(
            merged[merged.len() - 2..],
            [(13 + 9, Lab::Framing), (6, Lab::Unexplained)]
        );
        assert!(merged.contains(&(2, Lab::Other)));
    }

    #[test]
    fn gap_in_data_keeps_sync_but_gap_in_header_block_desyncs() {
        let mut log = Log::default();
        let mut p = H2::new(false);
        let mut head = frame(HEADERS, END_HEADERS, 1, &[0x88]);
        head.extend(frame(DATA, END_STREAM, 1, b"0123456789")[..12].to_vec());
        p.data(&head, 1, &mut log);
        p.gap(7, &mut log);
        p.data(&frame(HEADERS, END_HEADERS, 3, &[0x88, 0x88])[..10], 2, &mut log);
        p.gap(1, &mut log);
        p.data(b"more", 3, &mut log);
        p.finish(&mut log);
        assert_eq!(
            log.events,
            ["head 1 @0 200", "body_gap 1 7", "end 1 @29 true", "desync gap"]
        );
        assert_eq!(
            log.merged(),
            [
                (9, Lab::Framing),
                (1, Lab::Msg(1)),
                (9, Lab::Framing),
                (3, Lab::Msg(1)),
                (7, Lab::Gap),
                (9, Lab::Framing),
                (1, Lab::Unexplained),
                (1, Lab::Gap),
                (4, Lab::Unexplained),
            ]
        );
    }

    #[test]
    fn protocol_errors_desync() {
        for input in [
            b"PRI * HTTP/1.1\r\n".to_vec(),
            [PREFACE, &frame(DATA, 0, 0, b"x")].concat(),
            [PREFACE, &frame(CONTINUATION, END_HEADERS, 1, b"")].concat(),
            [PREFACE, &frame(HEADERS, END_HEADERS, 1, &[0x80])].concat(),
            [PREFACE, &frame(HEADERS, END_HEADERS | PADDED, 1, &[9, 0x82])].concat(),
            [PREFACE, &frame(HEADERS, 0, 1, &[0x82]), &frame(DATA, 0, 1, b"x")].concat(),
        ] {
            let log = run(true, &input);
            assert!(
                log.events.iter().any(|e| e.starts_with("desync")),
                "{input:?}: {:?}",
                log.events
            );
        }
    }
}
