//! Packs (spec §8): many KB-sized items in one object, each its own zstd
//! frame, followed by a seek table in the zstd seekable format, so standard
//! tools can still read the pack. Any item is one range read plus a
//! single-frame decode.

use std::io;

/// Where an item sits in its pack: the compressed frame is
/// `[offset, offset + len)`, and decodes to `raw_len` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub offset: u64,
    pub len: u64,
    pub raw_len: u64,
}

const SKIPPABLE_MAGIC: u32 = 0x184D_2A5E;
const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;

/// Builds a pack from items in order. Returns the pack bytes and one entry
/// per item.
pub fn build<'a>(items: impl IntoIterator<Item = &'a [u8]>, level: i32) -> io::Result<(Vec<u8>, Vec<Entry>)> {
    let mut out = Vec::new();
    let mut entries = Vec::new();
    for item in items {
        let frame = zstd::bulk::compress(item, level)?;
        let fits = |n: usize| u32::try_from(n).is_ok();
        if !fits(frame.len()) || !fits(item.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pack item over 4 GiB",
            ));
        }
        entries.push(Entry {
            offset: out.len() as u64,
            len: frame.len() as u64,
            raw_len: item.len() as u64,
        });
        out.extend_from_slice(&frame);
    }
    // Seek table: a skippable frame of (compressed, decompressed) sizes and
    // a footer (frame count, descriptor without checksums, magic).
    let table_len = entries.len() * 8 + 9;
    out.extend_from_slice(&SKIPPABLE_MAGIC.to_le_bytes());
    out.extend_from_slice(&(table_len as u32).to_le_bytes());
    for e in &entries {
        out.extend_from_slice(&(e.len as u32).to_le_bytes());
        out.extend_from_slice(&(e.raw_len as u32).to_le_bytes());
    }
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.push(0);
    out.extend_from_slice(&SEEKABLE_MAGIC.to_le_bytes());
    Ok((out, entries))
}

/// Reads one item back from a pack.
pub fn read(pack: &[u8], e: &Entry) -> io::Result<Vec<u8>> {
    let frame = usize::try_from(e.offset)
        .ok()
        .zip(usize::try_from(e.offset + e.len).ok())
        .and_then(|(s, t)| pack.get(s..t))
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "entry outside the pack"))?;
    zstd::bulk::decompress(frame, e.raw_len as usize)
}

/// Reads the seek table at the end of a pack.
pub fn seek_table(pack: &[u8]) -> io::Result<Vec<Entry>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "no seek table");
    let n = pack.len();
    let u32_at = |i: usize| -> io::Result<u32> {
        let b = pack.get(i..i + 4).ok_or_else(bad)?;
        Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    };
    if n < 17 || u32_at(n - 4)? != SEEKABLE_MAGIC || pack[n - 5] != 0 {
        return Err(bad());
    }
    let frames = u32_at(n - 9)? as usize;
    let start = n.checked_sub(9 + frames * 8 + 8).ok_or_else(bad)?;
    if u32_at(start)? != SKIPPABLE_MAGIC || u32_at(start + 4)? as usize != frames * 8 + 9 {
        return Err(bad());
    }
    let mut offset = 0;
    (0..frames)
        .map(|i| {
            let at = start + 8 + i * 8;
            let e = Entry {
                offset,
                len: u64::from(u32_at(at)?),
                raw_len: u64::from(u32_at(at + 4)?),
            };
            offset += e.len;
            Ok(e)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_read_back_and_seek_table_matches() {
        let items: Vec<&[u8]> = vec![b"first item", b"", &[7u8; 5000]];
        let (pack, entries) = build(items.iter().copied(), 3).unwrap();
        assert_eq!(seek_table(&pack).unwrap(), entries);
        for (item, e) in items.iter().zip(&entries) {
            assert_eq!(read(&pack, e).unwrap(), *item);
        }
        // The whole pack decodes as one zstd stream: the items, joined.
        let all = zstd::stream::decode_all(&pack[..]).unwrap();
        assert_eq!(all, items.concat());
    }
}
