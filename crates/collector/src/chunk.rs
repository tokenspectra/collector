//! L0 chunks (spec §6–8): one pcapng file per Link per window, written by
//! hand so the bytes depend only on the packets. The Merkle root over the
//! chunk's packet hashes is [`commit::merkle_root`].
//!
//! The pcapng is little-endian: a Section Header Block, one Interface
//! Description Block per link type in order of first use (`if_name` is the
//! Link, `if_tsresol` is nanoseconds), then one Enhanced Packet Block per
//! packet with its captured bytes (possibly cut by the Capture Rate) and its
//! original length.

pub use commit::merkle_root;

/// One packet as stored in a chunk.
pub struct Packet<'a> {
    pub link_type: u32,
    pub ts_ns: u64,
    pub orig_len: u32,
    /// The bytes to store: all captured bytes, or a truncated prefix.
    pub data: &'a [u8],
}

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 1;
const EPB: u32 = 6;

fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let len = (12 + body.len().next_multiple_of(4)) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + body.len().next_multiple_of(4) - body.len(), 0);
    out.extend_from_slice(&len.to_le_bytes());
}

fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(&(value.len() as u16).to_le_bytes());
    body.extend_from_slice(value);
    body.resize(body.len() + value.len().next_multiple_of(4) - value.len(), 0);
}

/// The pcapng bytes of one chunk.
pub fn pcapng<'a>(link: &str, packets: impl IntoIterator<Item = Packet<'a>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&u64::MAX.to_le_bytes());
    block(&mut out, SHB, &shb);
    let mut interfaces: Vec<u32> = Vec::new();
    for p in packets {
        let iface = match interfaces.iter().position(|&t| t == p.link_type) {
            Some(i) => i,
            None => {
                let mut idb = Vec::new();
                idb.extend_from_slice(&(p.link_type as u16).to_le_bytes());
                idb.extend_from_slice(&0u16.to_le_bytes());
                idb.extend_from_slice(&0u32.to_le_bytes());
                option(&mut idb, 2, link.as_bytes());
                option(&mut idb, 9, &[9]);
                option(&mut idb, 0, &[]);
                block(&mut out, IDB, &idb);
                interfaces.push(p.link_type);
                interfaces.len() - 1
            }
        };
        let mut epb = Vec::with_capacity(20 + p.data.len());
        epb.extend_from_slice(&(iface as u32).to_le_bytes());
        epb.extend_from_slice(&((p.ts_ns >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(p.ts_ns as u32).to_le_bytes());
        epb.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&p.orig_len.to_le_bytes());
        epb.extend_from_slice(p.data);
        block(&mut out, EPB, &epb);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_chunk_reads_back() {
        let a = [1u8; 60];
        let b = [2u8; 7];
        let bytes = pcapng(
            "lo",
            [
                Packet {
                    link_type: 1,
                    ts_ns: 1_700_000_000_123_456_789,
                    orig_len: 60,
                    data: &a,
                },
                Packet {
                    link_type: 1,
                    ts_ns: 1_700_000_001_000_000_001,
                    orig_len: 1500,
                    data: &b,
                },
            ],
        );
        assert_eq!(bytes.len() % 4, 0);
        let mut r = pcap_file::pcapng::PcapNgReader::new(&bytes[..]).unwrap();
        let mut seen = Vec::new();
        while let Some(block) = r.next_block() {
            if let pcap_file::pcapng::Block::EnhancedPacket(p) = block.unwrap() {
                seen.push((p.timestamp.as_nanos() as u64, p.original_len, p.data.to_vec()));
            }
        }
        assert_eq!(
            seen,
            vec![
                (1_700_000_000_123_456_789, 60, a.to_vec()),
                (1_700_000_001_000_000_001, 1500, b.to_vec()),
            ]
        );
    }
}
