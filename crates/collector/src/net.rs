//! Link, IP and transport header decoding.
//!
//! Hand-written and bounds-checked: these bytes are adversarial. Checksums
//! are not verified (offload makes them wrong on many captures).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

impl TcpHeader {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Flags as letters, e.g. `"SA"` for SYN+ACK.
    pub fn flag_letters(&self) -> String {
        const NAMES: [(u8, char); 8] = [
            (0x02, 'S'),
            (0x10, 'A'),
            (0x08, 'P'),
            (0x01, 'F'),
            (0x04, 'R'),
            (0x20, 'U'),
            (0x40, 'E'),
            (0x80, 'C'),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| self.flags & bit != 0)
            .map(|(_, c)| *c)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp(TcpHeader),
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    /// Any other IP protocol, and every IP fragment (not reassembled in v1).
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub fragment: bool,
    pub transport: Transport,
    /// Captured payload bytes, trimmed to the declared length (no padding).
    pub payload: &'a [u8],
    /// Payload length on the wire, from the IP header.
    pub payload_len: u32,
    /// Offset of `payload` within the captured packet.
    pub payload_offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unsupported link type {0}")]
    UnsupportedLinkType(u32),
    #[error("not IP")]
    NotIp,
    #[error("truncated {0} header")]
    Truncated(&'static str),
    #[error("malformed {0} header")]
    Malformed(&'static str),
}

impl DecodeError {
    /// A short machine-readable reason for output records.
    pub fn code(&self) -> &'static str {
        match self {
            DecodeError::UnsupportedLinkType(_) => "unsupported_link_type",
            DecodeError::NotIp => "not_ip",
            DecodeError::Truncated(_) => "truncated_header",
            DecodeError::Malformed(_) => "malformed_header",
        }
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Decodes one captured packet. `data` is the captured bytes.
pub fn decode(link_type: u32, data: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    let ip_at = match link_type {
        LINKTYPE_ETHERNET => ethernet(data)?,
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => 0,
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            if data.len() < 4 {
                return Err(DecodeError::Truncated("loopback"));
            }
            let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let be = be32(data, 0);
            let family = if link_type == LINKTYPE_LOOP {
                be
            } else {
                le.min(be)
            };
            match family {
                2 | 10 | 24 | 28 | 30 => 4,
                _ => return Err(DecodeError::NotIp),
            }
        }
        LINKTYPE_LINUX_SLL => {
            if data.len() < 16 {
                return Err(DecodeError::Truncated("sll"));
            }
            ip_ethertype(be16(data, 14), 16)?
        }
        LINKTYPE_LINUX_SLL2 => {
            if data.len() < 20 {
                return Err(DecodeError::Truncated("sll2"));
            }
            ip_ethertype(be16(data, 0), 20)?
        }
        other => return Err(DecodeError::UnsupportedLinkType(other)),
    };
    ip(data, ip_at)
}

fn ip_ethertype(ethertype: u16, at: usize) -> Result<usize, DecodeError> {
    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => Ok(at),
        _ => Err(DecodeError::NotIp),
    }
}

fn ethernet(data: &[u8]) -> Result<usize, DecodeError> {
    let mut at = 12;
    loop {
        if data.len() < at + 2 {
            return Err(DecodeError::Truncated("ethernet"));
        }
        match be16(data, at) {
            ETHERTYPE_VLAN | ETHERTYPE_QINQ => at += 4,
            t => return ip_ethertype(t, at + 2),
        }
    }
}

fn ip(data: &[u8], at: usize) -> Result<Decoded<'_>, DecodeError> {
    let Some(&first) = data.get(at) else {
        return Err(DecodeError::Truncated("ip"));
    };
    match first >> 4 {
        4 => ipv4(data, at),
        6 => ipv6(data, at),
        _ => Err(DecodeError::NotIp),
    }
}

fn ipv4(data: &[u8], at: usize) -> Result<Decoded<'_>, DecodeError> {
    let h = &data[at..];
    if h.len() < 20 {
        return Err(DecodeError::Truncated("ipv4"));
    }
    let ihl = usize::from(h[0] & 0x0f) * 4;
    if ihl < 20 {
        return Err(DecodeError::Malformed("ipv4"));
    }
    if h.len() < ihl {
        return Err(DecodeError::Truncated("ipv4"));
    }
    let total = usize::from(be16(h, 2));
    // A total length of 0 appears with TCP segmentation offload: trust the capture.
    let total = if total == 0 { h.len() } else { total };
    if total < ihl {
        return Err(DecodeError::Malformed("ipv4"));
    }
    let frag = be16(h, 6);
    let fragment = frag & 0x3fff != 0; // MF flag or a non-zero offset
    let proto = h[9];
    let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
    transport(data, at + ihl, total - ihl, src, dst, proto, fragment)
}

fn ipv6(data: &[u8], at: usize) -> Result<Decoded<'_>, DecodeError> {
    let h = &data[at..];
    if h.len() < 40 {
        return Err(DecodeError::Truncated("ipv6"));
    }
    let declared = usize::from(be16(h, 4));
    // Payload length 0 means a jumbogram: trust the capture.
    let mut remaining = if declared == 0 { h.len() - 40 } else { declared };
    let mut next = h[6];
    let addr = |o: usize| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&h[o..o + 16]);
        IpAddr::V6(Ipv6Addr::from(b))
    };
    let src = addr(8);
    let dst = addr(24);
    let mut off = at + 40;
    let mut fragment = false;
    loop {
        let ext_len = match next {
            0 | 43 | 60 => {
                let e = data
                    .get(off..off + 2)
                    .ok_or(DecodeError::Truncated("ipv6 extension"))?;
                (usize::from(e[1]) + 1) * 8
            }
            44 => {
                let e = data
                    .get(off..off + 8)
                    .ok_or(DecodeError::Truncated("ipv6 fragment"))?;
                if be16(e, 2) & 0xfff9 != 0 {
                    fragment = true;
                }
                8
            }
            51 => {
                let e = data
                    .get(off..off + 2)
                    .ok_or(DecodeError::Truncated("ipv6 extension"))?;
                (usize::from(e[1]) + 2) * 4
            }
            _ => break,
        };
        if ext_len > remaining {
            return Err(DecodeError::Malformed("ipv6 extension"));
        }
        next = data[off];
        off += ext_len;
        remaining -= ext_len;
    }
    transport(data, off, remaining, src, dst, next, fragment)
}

fn transport(
    data: &[u8],
    at: usize,
    ip_payload_len: usize,
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    fragment: bool,
) -> Result<Decoded<'_>, DecodeError> {
    let captured = data.len().saturating_sub(at).min(ip_payload_len);
    let l4 = &data[at.min(data.len())..at.min(data.len()) + captured];
    let (transport, hdr_len) = if fragment {
        (Transport::Other, 0)
    } else {
        match proto {
            IPPROTO_TCP => {
                if l4.len() < 20 {
                    return Err(DecodeError::Truncated("tcp"));
                }
                let hlen = usize::from(l4[12] >> 4) * 4;
                if hlen < 20 || hlen > ip_payload_len {
                    return Err(DecodeError::Malformed("tcp"));
                }
                if l4.len() < hlen {
                    return Err(DecodeError::Truncated("tcp"));
                }
                let tcp = TcpHeader {
                    src_port: be16(l4, 0),
                    dst_port: be16(l4, 2),
                    seq: be32(l4, 4),
                    ack: be32(l4, 8),
                    flags: l4[13],
                };
                (Transport::Tcp(tcp), hlen)
            }
            IPPROTO_UDP => {
                if l4.len() < 8 {
                    return Err(DecodeError::Truncated("udp"));
                }
                if ip_payload_len < 8 {
                    return Err(DecodeError::Malformed("udp"));
                }
                let udp = Transport::Udp {
                    src_port: be16(l4, 0),
                    dst_port: be16(l4, 2),
                };
                (udp, 8)
            }
            _ => (Transport::Other, 0),
        }
    };
    Ok(Decoded {
        src,
        dst,
        proto,
        fragment,
        transport,
        payload: &l4[hdr_len..],
        payload_len: (ip_payload_len - hdr_len) as u32,
        payload_offset: (at + hdr_len) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_tcp(payload: &[u8], pad: usize) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 20 + payload.len()) as u16;
        p.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            6,
            0,
            0,
        ]);
        p.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        p.extend_from_slice(&[0x1f, 0x90, 0xc3, 0x50]);
        p.extend_from_slice(&100u32.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.extend_from_slice(&[0x50, TCP_ACK | TCP_PSH, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        p.extend(std::iter::repeat_n(0xee, pad));
        p
    }

    #[test]
    fn tcp_over_ethernet_ignores_padding() {
        let pkt = eth_ipv4_tcp(b"hi", 4);
        let d = decode(LINKTYPE_ETHERNET, &pkt).unwrap();
        assert_eq!(d.payload, b"hi");
        assert_eq!(d.payload_len, 2);
        assert_eq!(d.payload_offset, 54);
        let Transport::Tcp(t) = d.transport else { panic!() };
        assert_eq!((t.src_port, t.dst_port, t.seq, t.ack), (8080, 50000, 100, 7));
        assert_eq!(t.flag_letters(), "AP");
    }

    #[test]
    fn truncated_payload_keeps_declared_length() {
        let pkt = eth_ipv4_tcp(b"hello world", 0);
        let d = decode(LINKTYPE_ETHERNET, &pkt[..60]).unwrap();
        assert_eq!(d.payload, b"hello ");
        assert_eq!(d.payload_len, 11);
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(
            decode(LINKTYPE_ETHERNET, &[0; 10]),
            Err(DecodeError::Truncated("ethernet"))
        );
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06, 0, 0]);
        assert_eq!(decode(LINKTYPE_ETHERNET, &arp), Err(DecodeError::NotIp));
        let mut bad = eth_ipv4_tcp(b"", 0);
        bad[14] = 0x44; // IHL 16 bytes
        assert_eq!(
            decode(LINKTYPE_ETHERNET, &bad),
            Err(DecodeError::Malformed("ipv4"))
        );
        assert_eq!(decode(999, &bad), Err(DecodeError::UnsupportedLinkType(999)));
    }

    #[test]
    fn ipv4_fragment_is_other() {
        let mut pkt = eth_ipv4_tcp(b"xx", 0);
        pkt[20] = 0x20; // MF
        let d = decode(LINKTYPE_ETHERNET, &pkt).unwrap();
        assert!(d.fragment);
        assert_eq!(d.transport, Transport::Other);
        assert_eq!(d.payload_len, 22);
    }
}
