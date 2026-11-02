//! HPACK header decoding for HTTP/2 (RFC 7541).
//!
//! Hand-written and bounds-checked: header blocks are adversarial. One
//! [`Decoder`] per direction of a Flow, since each side's encoder keeps its
//! own dynamic table. Any error leaves the table out of step with the
//! encoder, so the caller must stop decoding that direction.

use std::collections::VecDeque;
use std::sync::OnceLock;

use crate::hpack_huffman::HUFFMAN_CODES;

/// Largest dynamic table a size update may ask for. The protocol default is
/// 4096; peers rarely raise it, and each Flow direction holds one table.
const MAX_TABLE_SIZE: usize = 64 << 10;
/// Largest decoded header list, which stops a small block that repeats a
/// large table entry from expanding without bound.
const MAX_LIST_SIZE: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HpackError {
    Truncated,
    BadIndex,
    IntegerOverflow,
    BadHuffman,
    TableSizeTooLarge,
    LateSizeUpdate,
    ListTooLarge,
}

pub(crate) type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) struct Decoder {
    /// Newest entry first.
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder {
            table: VecDeque::new(),
            size: 0,
            max_size: 4096,
        }
    }
}

fn entry_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + 32
}

impl Decoder {
    /// Decodes one complete header block.
    pub fn decode(&mut self, block: &[u8]) -> Result<HeaderList, HpackError> {
        let mut r = Reader { buf: block, pos: 0 };
        let mut out: HeaderList = Vec::new();
        let mut list_size = 0usize;
        while !r.done() {
            let b = r.peek()?;
            let (name, value) = if b & 0x80 != 0 {
                let idx = r.int(7)?;
                self.get(idx)?
            } else if b & 0xc0 == 0x40 {
                let (n, v) = self.literal(&mut r, 6)?;
                self.insert(n.clone(), v.clone());
                (n, v)
            } else if b & 0xe0 == 0x20 {
                if !out.is_empty() {
                    return Err(HpackError::LateSizeUpdate);
                }
                let size = r.int(5)?;
                if size > MAX_TABLE_SIZE {
                    return Err(HpackError::TableSizeTooLarge);
                }
                self.max_size = size;
                self.evict(0);
                continue;
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                self.literal(&mut r, 4)?
            };
            list_size += entry_size(&name, &value);
            if list_size > MAX_LIST_SIZE {
                return Err(HpackError::ListTooLarge);
            }
            out.push((name, value));
        }
        Ok(out)
    }

    fn literal(&self, r: &mut Reader, prefix: u8) -> Result<(Vec<u8>, Vec<u8>), HpackError> {
        let idx = r.int(prefix)?;
        let name = if idx == 0 { r.string()? } else { self.get(idx)?.0 };
        let value = r.string()?;
        Ok((name, value))
    }

    fn get(&self, idx: usize) -> Result<(Vec<u8>, Vec<u8>), HpackError> {
        match idx {
            0 => Err(HpackError::BadIndex),
            1..=61 => {
                let (n, v) = STATIC_TABLE[idx - 1];
                Ok((n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            }
            _ => self.table.get(idx - 62).cloned().ok_or(HpackError::BadIndex),
        }
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = entry_size(&name, &value);
        if size > self.max_size {
            // An entry larger than the table empties it (RFC 7541 §4.4).
            self.table.clear();
            self.size = 0;
            return;
        }
        self.evict(size);
        self.size += size;
        self.table.push_front((name, value));
    }

    /// Evicts the oldest entries until `extra` more bytes fit.
    fn evict(&mut self, extra: usize) {
        while self.size + extra > self.max_size {
            let Some((n, v)) = self.table.pop_back() else {
                break;
            };
            self.size -= entry_size(&n, &v);
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek(&self) -> Result<u8, HpackError> {
        self.buf.get(self.pos).copied().ok_or(HpackError::Truncated)
    }

    fn byte(&mut self) -> Result<u8, HpackError> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    /// An integer with an `n`-bit prefix (RFC 7541 §5.1), at most 2^28.
    fn int(&mut self, n: u8) -> Result<usize, HpackError> {
        let max_prefix = (1usize << n) - 1;
        let mut v = usize::from(self.byte()?) & max_prefix;
        if v < max_prefix {
            return Ok(v);
        }
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            if shift > 21 {
                return Err(HpackError::IntegerOverflow);
            }
            v += usize::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
    }

    fn string(&mut self) -> Result<Vec<u8>, HpackError> {
        let huffman = self.peek()? & 0x80 != 0;
        let len = self.int(7)?;
        let end = self.pos.checked_add(len).ok_or(HpackError::Truncated)?;
        let raw = self.buf.get(self.pos..end).ok_or(HpackError::Truncated)?;
        self.pos = end;
        if huffman {
            huffman_decode(raw)
        } else {
            Ok(raw.to_vec())
        }
    }
}

/// The Huffman code as a binary tree: `nodes[i]` holds the two children of
/// node `i`. A child below `LEAF` is another node; `LEAF + sym` is a symbol.
struct Tree {
    nodes: Vec<[u16; 2]>,
}

const LEAF: u16 = 0x8000;
const EMPTY: u16 = 0;

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut nodes = vec![[EMPTY; 2]];
        for (sym, &(code, len)) in HUFFMAN_CODES.iter().enumerate() {
            let mut node = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                if i == 0 {
                    nodes[node][bit] = LEAF + sym as u16;
                } else {
                    if nodes[node][bit] == EMPTY {
                        nodes.push([EMPTY; 2]);
                        nodes[node][bit] = (nodes.len() - 1) as u16;
                    }
                    node = nodes[node][bit] as usize;
                }
            }
        }
        Tree { nodes }
    })
}

fn huffman_decode(raw: &[u8]) -> Result<Vec<u8>, HpackError> {
    let t = tree();
    let mut out = Vec::with_capacity(raw.len() * 8 / 5);
    let mut node = 0usize;
    // Bits read since the last symbol, and whether they were all ones.
    let mut pending = 0u32;
    let mut all_ones = true;
    for &byte in raw {
        for i in (0..8).rev() {
            let bit = usize::from((byte >> i) & 1);
            let next = t.nodes[node][bit];
            pending += 1;
            all_ones &= bit == 1;
            if next & LEAF != 0 {
                let sym = next - LEAF;
                if sym == 256 {
                    return Err(HpackError::BadHuffman);
                }
                out.push(sym as u8);
                node = 0;
                pending = 0;
                all_ones = true;
            } else if next == EMPTY {
                return Err(HpackError::BadHuffman);
            } else {
                node = next as usize;
            }
        }
    }
    // Padding: at most 7 bits, all ones (a prefix of EOS).
    if pending > 7 || !all_ones {
        return Err(HpackError::BadHuffman);
    }
    Ok(out)
}

const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pairs(list: &HeaderList) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| {
                (
                    String::from_utf8(n.clone()).unwrap(),
                    String::from_utf8(v.clone()).unwrap(),
                )
            })
            .collect()
    }

    fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    // Vectors from the Python `hpack` encoder.
    #[test]
    fn huffman_and_dynamic_table() {
        let mut d = Decoder::default();
        let b1 = hex("8386448e63b85824e34b043d35d05498f523418a089d5c0b8170dc7800075f8b1d75d0620d263d4c7441ea7a8dd5596a87231afd2673d4a05707");
        let req = [
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/v1/chat/completions"),
            (":authority", "127.0.0.1:8000"),
            ("content-type", "application/json"),
            ("user-agent", "OpenAI/Python 1.0"),
        ];
        assert_eq!(pairs(&d.decode(&b1).unwrap()), owned(&req));
        // The second block reuses the first one's dynamic entries.
        let b2 = hex("8386c1c0bfbe4086f2b12d424f4f93fffe3fffeea7fff8ffffbaa7ff7fe7ffefff7f");
        let mut want = owned(&req);
        want.push(("x-custom".into(), "été ~|{}".into()));
        assert_eq!(pairs(&d.decode(&b2).unwrap()), want);
    }

    #[test]
    fn size_update_and_long_literal() {
        let mut block = hex("3fe101885f11746578742f6576656e742d73747265616d4006782d6c6f6e677fad01");
        block.extend(std::iter::repeat_n(b'a', 300));
        let mut d = Decoder::default();
        let list = d.decode(&block).unwrap();
        assert_eq!(d.max_size, 256);
        assert_eq!(
            pairs(&list[..2].to_vec()),
            owned(&[(":status", "200"), ("content-type", "text/event-stream")])
        );
        assert_eq!(list[2].1.len(), 300);
        // 300 + 6 + 32 bytes do not fit in 256: the table stays empty.
        assert!(d.table.is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        let mut d = Decoder::default();
        assert_eq!(d.decode(&[0x80]), Err(HpackError::BadIndex));
        assert_eq!(d.decode(&[0xbe]), Err(HpackError::BadIndex));
        assert_eq!(d.decode(&[0x41, 0x05, b'a']), Err(HpackError::Truncated));
        assert_eq!(
            d.decode(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(HpackError::IntegerOverflow)
        );
        // A size update after a header field.
        assert_eq!(d.decode(&[0x82, 0x20]), Err(HpackError::LateSizeUpdate));
        assert_eq!(d.decode(&hex("3fe1ff07")), Err(HpackError::TableSizeTooLarge));
        // Padding longer than 7 bits, and padding that is not all ones.
        assert_eq!(d.decode(&hex("0081ff0161")), Err(HpackError::BadHuffman));
        assert_eq!(
            d.decode(&[0x00, 0x81, 0x00, 0x01, b'a']),
            Err(HpackError::BadHuffman)
        );
    }

    #[test]
    fn list_size_is_capped() {
        let mut d = Decoder::default();
        // One 4000-byte entry, then indexed 300 times: 1.2 MB decoded.
        let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'v', 4000));
        block.extend(std::iter::repeat_n(0xbe, 300));
        assert_eq!(d.decode(&block), Err(HpackError::ListTooLarge));
    }
}
