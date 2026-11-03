//! Content codings (`Content-Encoding`, RFC 9110 §8.4), removed so a body
//! can be parsed (spec §6).
//!
//! The body hash stays on the bytes as on the wire; decoding only feeds the
//! Wire Protocols and a second hash, over the decoded bytes. Bodies are
//! adversarial, so decoding stops at a cap: an absolute number of decoded
//! bytes, and a ratio of decoded to wire bytes past a small floor.

use std::io::{self, Write};

use serde::Serialize;

use crate::mh;

/// Decoded bytes below which the ratio cap does not apply, so a small body
/// that compresses well (`{}` under gzip is 20 bytes on the wire) is read.
pub const RATIO_FLOOR: u64 = 1 << 20;

/// How far one body may decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most decoded bytes per body.
    pub max_decoded: u64,
    /// Most decoded bytes per wire byte, once past [`RATIO_FLOOR`].
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_decoded: 64 << 20,
            max_ratio: 100,
        }
    }
}

/// A content coding the Collector decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Gzip,
    /// `deflate`: zlib (RFC 1950) as the RFC says, or raw deflate (RFC 1951)
    /// as some servers send it, told apart by the first two bytes.
    Deflate,
    Br,
    Zstd,
}

/// What a `Content-Encoding` header asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// No header, an empty one, or only `identity`.
    Identity,
    Coded(Coding),
    /// An unknown coding, or more than one.
    Unsupported,
}

impl Encoding {
    pub fn of(header: Option<&str>) -> Encoding {
        let mut codings = header
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity"));
        let Some(first) = codings.next() else {
            return Encoding::Identity;
        };
        if codings.next().is_some() {
            return Encoding::Unsupported;
        }
        match first.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Encoding::Coded(Coding::Gzip),
            "deflate" => Encoding::Coded(Coding::Deflate),
            "br" => Encoding::Coded(Coding::Br),
            "zstd" => Encoding::Coded(Coding::Zstd),
            _ => Encoding::Unsupported,
        }
    }
}

/// Why a coded body was not decoded to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeError {
    /// A coding the Collector does not decode, or more than one.
    Unsupported,
    /// The bytes are not that coding (or fail its checksum).
    Corrupt,
    /// The body ended before the coded stream did.
    Truncated,
    /// The message never reached its end.
    Incomplete,
    /// Part of the body was never captured.
    Gap,
    /// Decoded bytes passed [`Limits::max_decoded`].
    OverCap,
    /// Decoded bytes passed [`Limits::max_ratio`] times the wire bytes.
    OverRatio,
}

impl DecodeError {
    /// The name written in the tables.
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeError::Unsupported => "unsupported",
            DecodeError::Corrupt => "corrupt",
            DecodeError::Truncated => "truncated",
            DecodeError::Incomplete => "incomplete",
            DecodeError::Gap => "gap",
            DecodeError::OverCap => "over_cap",
            DecodeError::OverRatio => "over_ratio",
        }
    }
}

/// Collects decoded bytes, refusing any past the caps.
struct Capped {
    buf: Vec<u8>,
    written: u64,
    max: u64,
    ratio_max: u64,
    over: Option<DecodeError>,
}

impl Write for Capped {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let total = self.written + b.len() as u64;
        if total > self.max {
            self.over = Some(DecodeError::OverCap);
        } else if total > self.ratio_max {
            self.over = Some(DecodeError::OverRatio);
        }
        if self.over.is_some() {
            return Err(io::Error::other("decoded body over the cap"));
        }
        self.written = total;
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `deflate`, zlib-wrapped or raw, decided once two bytes are in.
struct Deflate {
    head: Vec<u8>,
    d: Option<flate2::Decompress>,
    ended: bool,
}

impl Deflate {
    /// A zlib header: method 8, a window of at most 32 KiB, and a check
    /// value that makes the pair a multiple of 31.
    fn is_zlib(b: [u8; 2]) -> bool {
        b[0] & 0x0f == 8 && b[0] >> 4 <= 7 && u16::from_be_bytes(b).is_multiple_of(31)
    }

    fn push(&mut self, mut data: &[u8], out: &mut Capped) -> Result<(), DecodeError> {
        if self.d.is_none() {
            let need = 2 - self.head.len();
            let take = need.min(data.len());
            self.head.extend_from_slice(&data[..take]);
            if self.head.len() < 2 {
                return Ok(());
            }
            let head = std::mem::take(&mut self.head);
            let zlib = Self::is_zlib([head[0], head[1]]);
            self.d = Some(flate2::Decompress::new(zlib));
            self.run(&head, out)?;
            data = &data[take..];
        }
        self.run(data, out)
    }

    fn run(&mut self, mut data: &[u8], out: &mut Capped) -> Result<(), DecodeError> {
        let d = self.d.as_mut().expect("started");
        let mut tmp = Vec::with_capacity(32 << 10);
        while !data.is_empty() {
            if self.ended {
                return Err(DecodeError::Corrupt);
            }
            tmp.clear();
            let (in0, out0) = (d.total_in(), d.total_out());
            let status = d
                .decompress_vec(data, &mut tmp, flate2::FlushDecompress::None)
                .map_err(|_| DecodeError::Corrupt)?;
            let used = (d.total_in() - in0) as usize;
            data = &data[used..];
            if out.write_all(&tmp).is_err() {
                return Err(out.over.unwrap_or(DecodeError::Corrupt));
            }
            match status {
                flate2::Status::StreamEnd => self.ended = true,
                _ if used == 0 && d.total_out() == out0 => return Err(DecodeError::Corrupt),
                _ => {}
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DecodeError> {
        if self.ended {
            Ok(())
        } else {
            Err(DecodeError::Truncated)
        }
    }
}

enum Stage {
    Gzip(flate2::write::MultiGzDecoder<Capped>),
    Deflate(Deflate, Capped),
    Br(Box<brotli::DecompressorWriter<Capped>>),
    Zstd(zstd::stream::write::Decoder<'static, Capped>),
}

impl Stage {
    fn new(coding: Coding) -> Self {
        let out = Capped {
            buf: Vec::new(),
            written: 0,
            max: 0,
            ratio_max: 0,
            over: None,
        };
        match coding {
            Coding::Gzip => Stage::Gzip(flate2::write::MultiGzDecoder::new(out)),
            Coding::Deflate => Stage::Deflate(
                Deflate {
                    head: Vec::new(),
                    d: None,
                    ended: false,
                },
                out,
            ),
            Coding::Br => Stage::Br(Box::new(brotli::DecompressorWriter::new(out, 32 << 10))),
            Coding::Zstd => Stage::Zstd(zstd::stream::write::Decoder::new(out).expect("zstd context")),
        }
    }

    fn out(&mut self) -> &mut Capped {
        match self {
            Stage::Gzip(w) => w.get_mut(),
            Stage::Deflate(_, out) => out,
            Stage::Br(w) => w.get_mut(),
            Stage::Zstd(w) => w.get_mut(),
        }
    }

    /// Writes `data` through, and flushes what it decodes to.
    fn push(&mut self, data: &[u8]) -> Result<(), DecodeError> {
        let r = match self {
            Stage::Gzip(w) => w.write_all(data).and_then(|_| w.flush()),
            Stage::Deflate(d, out) => return d.push(data, out),
            Stage::Br(w) => w.write_all(data).and_then(|_| w.flush()),
            Stage::Zstd(w) => w.write_all(data).and_then(|_| w.flush()),
        };
        r.map_err(|_| self.out().over.unwrap_or(DecodeError::Corrupt))
    }

    fn finish(&mut self) -> Result<(), DecodeError> {
        let r = match self {
            Stage::Gzip(w) => w.try_finish(),
            Stage::Deflate(d, _) => return d.finish(),
            Stage::Br(w) => w.close(),
            Stage::Zstd(w) => w.do_finish(),
        };
        r.map_err(|e| match self.out().over {
            Some(over) => over,
            None if e.kind() == io::ErrorKind::InvalidData => DecodeError::Corrupt,
            // A cut-off stream: an unexpected end (brotli, zstd), or a gzip
            // trailer missing its bytes.
            None => DecodeError::Truncated,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    Done,
    Failed(DecodeError),
}

/// Decodes one body as its wire bytes stream in.
pub struct Decoding {
    stage: Option<Stage>,
    limits: Limits,
    in_len: u64,
    out_len: u64,
    hasher: blake3::Hasher,
    state: State,
}

impl Decoding {
    /// A decoding for what `encoding` asks for, or `None` for identity.
    pub fn of(encoding: Encoding, limits: Limits) -> Option<Decoding> {
        let (stage, state) = match encoding {
            Encoding::Identity => return None,
            Encoding::Coded(c) => (Some(Stage::new(c)), State::Running),
            Encoding::Unsupported => (None, State::Failed(DecodeError::Unsupported)),
        };
        Some(Decoding {
            stage,
            limits,
            in_len: 0,
            out_len: 0,
            hasher: blake3::Hasher::new(),
            state,
        })
    }

    /// More wire bytes; returns the bytes they decode to (none once
    /// decoding has stopped).
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.state != State::Running || data.is_empty() {
            return Vec::new();
        }
        self.in_len += data.len() as u64;
        self.run(|s| s.push(data))
    }

    /// The body ended at its declared end: returns the last decoded bytes.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.state != State::Running {
            return Vec::new();
        }
        if self.in_len == 0 {
            // No content (HEAD, 204, 304): nothing to decode.
            self.state = State::Done;
            self.stage = None;
            return Vec::new();
        }
        let out = self.run(Stage::finish);
        if self.state == State::Running {
            self.state = State::Done;
            self.stage = None;
        }
        out
    }

    /// Part of the body was never captured: decoding cannot go on.
    pub fn gap(&mut self) {
        if self.state == State::Running {
            self.fail(DecodeError::Gap);
        }
    }

    fn run(&mut self, op: impl FnOnce(&mut Stage) -> Result<(), DecodeError>) -> Vec<u8> {
        let ratio_max = self.in_len.saturating_mul(self.limits.max_ratio).max(RATIO_FLOOR);
        let stage = self.stage.as_mut().expect("running");
        let out = stage.out();
        out.max = self.limits.max_decoded;
        out.ratio_max = ratio_max;
        let r = op(stage);
        let decoded = std::mem::take(&mut stage.out().buf);
        self.out_len += decoded.len() as u64;
        self.hasher.update(&decoded);
        if let Err(e) = r {
            self.fail(e);
        }
        decoded
    }

    fn fail(&mut self, e: DecodeError) {
        self.state = State::Failed(e);
        self.stage = None;
    }

    /// Decoded bytes so far; `None` for a coding that is not decoded.
    pub fn decoded_len(&self) -> Option<u64> {
        (self.state != State::Failed(DecodeError::Unsupported)).then_some(self.out_len)
    }

    /// Decoded to the end of the coded stream, within the caps.
    pub fn done(&self) -> bool {
        self.state == State::Done
    }

    /// Why decoding stopped short; [`DecodeError::Incomplete`] while it is
    /// still waiting for bytes.
    pub fn error(&self) -> Option<DecodeError> {
        match self.state {
            State::Running => Some(DecodeError::Incomplete),
            State::Done => None,
            State::Failed(e) => Some(e),
        }
    }

    /// Stopped on a cap or on bad bytes, as opposed to waiting for more.
    pub fn failed(&self) -> bool {
        matches!(self.state, State::Failed(_))
    }

    /// BLAKE3 of the decoded bytes, once decoded to the end.
    pub fn hash(&self) -> Option<String> {
        self.done().then(|| mh::name(&self.hasher.finalize()))
    }
}

/// Decodes a whole body, for views over stored bodies.
pub fn decode_all(encoding: Encoding, body: &[u8], limits: Limits) -> Result<Vec<u8>, DecodeError> {
    let Some(mut d) = Decoding::of(encoding, limits) else {
        return Ok(body.to_vec());
    };
    let mut out = d.push(body);
    out.extend(d.finish());
    match d.error() {
        None => Ok(out),
        Some(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &[u8] = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n\
        data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n";

    fn gzip(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    fn zlib(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    fn br(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(b).unwrap();
        }
        out
    }

    fn zstd(b: &[u8]) -> Vec<u8> {
        zstd::encode_all(b, 3).unwrap()
    }

    fn coded() -> Vec<(Coding, Vec<u8>)> {
        vec![
            (Coding::Gzip, gzip(TEXT)),
            (Coding::Deflate, zlib(TEXT)),
            (Coding::Deflate, raw_deflate(TEXT)),
            (Coding::Br, br(TEXT)),
            (Coding::Zstd, zstd(TEXT)),
        ]
    }

    /// Feeds `wire` in pieces of `step` bytes.
    fn decode_in_steps(c: Coding, wire: &[u8], step: usize, limits: Limits) -> (Vec<u8>, Decoding) {
        let mut d = Decoding::of(Encoding::Coded(c), limits).unwrap();
        let mut out = Vec::new();
        for piece in wire.chunks(step) {
            out.extend(d.push(piece));
        }
        out.extend(d.finish());
        (out, d)
    }

    #[test]
    fn parses_content_encoding() {
        assert_eq!(Encoding::of(None), Encoding::Identity);
        assert_eq!(Encoding::of(Some("")), Encoding::Identity);
        assert_eq!(Encoding::of(Some("identity")), Encoding::Identity);
        assert_eq!(Encoding::of(Some(" GZIP ")), Encoding::Coded(Coding::Gzip));
        assert_eq!(Encoding::of(Some("x-gzip")), Encoding::Coded(Coding::Gzip));
        assert_eq!(Encoding::of(Some("deflate")), Encoding::Coded(Coding::Deflate));
        assert_eq!(Encoding::of(Some("br")), Encoding::Coded(Coding::Br));
        assert_eq!(Encoding::of(Some("zstd")), Encoding::Coded(Coding::Zstd));
        assert_eq!(Encoding::of(Some("identity, br")), Encoding::Coded(Coding::Br));
        assert_eq!(Encoding::of(Some("gzip, br")), Encoding::Unsupported);
        assert_eq!(Encoding::of(Some("compress")), Encoding::Unsupported);
    }

    #[test]
    fn every_coding_decodes_split_at_any_byte() {
        for (c, wire) in coded() {
            for step in [1, 2, 3, 7, 64, wire.len()] {
                let (out, d) = decode_in_steps(c, &wire, step, Limits::default());
                assert_eq!(out, TEXT, "{c:?} step {step}");
                assert!(d.done(), "{c:?} step {step}: {:?}", d.error());
                assert_eq!(d.decoded_len(), Some(TEXT.len() as u64));
                assert_eq!(d.hash(), Some(mh::name(&blake3::hash(TEXT))));
            }
        }
    }

    #[test]
    fn bytes_come_out_as_they_go_in() {
        // A server that flushes after each event (gzip with Z_SYNC_FLUSH).
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut d = Decoding::of(Encoding::Coded(Coding::Gzip), Limits::default()).unwrap();
        for event in [&b"data: a\n\n"[..], b"data: b\n\n"] {
            e.write_all(event).unwrap();
            e.flush().unwrap();
            let wire = std::mem::take(e.get_mut());
            assert_eq!(d.push(&wire), event);
        }
        let tail = e.finish().unwrap();
        assert_eq!(d.push(&tail), b"");
        assert_eq!(d.finish(), b"");
        assert!(d.done());
    }

    #[test]
    fn a_cut_off_stream_is_truncated() {
        for (c, wire) in coded() {
            let (_, d) = decode_in_steps(c, &wire[..wire.len() - 3], 5, Limits::default());
            assert!(!d.done(), "{c:?}");
            assert!(d.hash().is_none());
            assert!(
                matches!(d.error(), Some(DecodeError::Truncated | DecodeError::Corrupt)),
                "{c:?}: {:?}",
                d.error()
            );
        }
    }

    #[test]
    fn bad_bytes_and_trailing_garbage_fail() {
        for c in [Coding::Gzip, Coding::Deflate, Coding::Br, Coding::Zstd] {
            let (_, d) = decode_in_steps(c, b"{\"model\":\"not coded at all\"}", 4, Limits::default());
            assert!(!d.done(), "{c:?}");
            assert!(d.failed(), "{c:?}");
        }
        let mut wire = gzip(TEXT);
        wire.extend_from_slice(b"junk");
        let (_, d) = decode_in_steps(Coding::Gzip, &wire, 16, Limits::default());
        assert!(!d.done(), "{:?}", d.error());
    }

    #[test]
    fn a_bomb_stops_at_the_caps() {
        let zeros = vec![0u8; 8 << 20];
        for (c, wire) in [
            (Coding::Gzip, gzip(&zeros)),
            (Coding::Deflate, zlib(&zeros)),
            (Coding::Br, br(&zeros)),
            (Coding::Zstd, zstd(&zeros)),
        ] {
            // 8 MiB of zeros is far past 100:1.
            let (out, d) = decode_in_steps(c, &wire, 1 << 10, Limits::default());
            assert_eq!(d.error(), Some(DecodeError::OverRatio), "{c:?}");
            assert!(out.len() as u64 <= RATIO_FLOOR.max(100 * wire.len() as u64));
            assert!(d.hash().is_none());
            // With no ratio cap, the absolute cap stops it.
            let limits = Limits {
                max_decoded: 2 << 20,
                max_ratio: u64::MAX,
            };
            let (out, d) = decode_in_steps(c, &wire, 1 << 10, limits);
            assert_eq!(d.error(), Some(DecodeError::OverCap), "{c:?}");
            assert!(out.len() <= 2 << 20);
        }
    }

    #[test]
    fn small_bodies_pass_under_the_ratio_floor() {
        let body = vec![b'a'; 512 << 10];
        let (out, d) = decode_in_steps(Coding::Gzip, &gzip(&body), 100, Limits::default());
        assert!(d.done(), "{:?}", d.error());
        assert_eq!(out, body);
    }

    #[test]
    fn gaps_unsupported_and_empty_bodies() {
        let mut d = Decoding::of(Encoding::Coded(Coding::Gzip), Limits::default()).unwrap();
        d.push(&gzip(TEXT)[..10]);
        d.gap();
        assert_eq!(d.error(), Some(DecodeError::Gap));
        let d = Decoding::of(Encoding::Unsupported, Limits::default()).unwrap();
        assert_eq!(d.error(), Some(DecodeError::Unsupported));
        assert_eq!(d.decoded_len(), None);
        let mut d = Decoding::of(Encoding::Coded(Coding::Br), Limits::default()).unwrap();
        assert_eq!(d.error(), Some(DecodeError::Incomplete));
        d.finish();
        assert!(d.done());
        assert_eq!(d.hash(), Some(mh::name(&blake3::hash(b""))));
        assert!(Decoding::of(Encoding::Identity, Limits::default()).is_none());
    }

    #[test]
    fn decode_all_whole_bodies() {
        let enc = Encoding::Coded(Coding::Zstd);
        assert_eq!(decode_all(enc, &zstd(TEXT), Limits::default()).unwrap(), TEXT);
        assert_eq!(
            decode_all(Encoding::Identity, TEXT, Limits::default()).unwrap(),
            TEXT
        );
        assert!(decode_all(enc, b"nope", Limits::default()).is_err());
    }
}
