//! Flow identity (spec §4 "Flow key").

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Serialize;

use crate::net::{IPPROTO_TCP, IPPROTO_UDP};
use crate::packet::LinkId;

/// One end of a Flow. `port` is 0 for protocols without ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// How a Flow is assembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlowKind {
    /// Reassembled into one byte stream per direction.
    Tcp,
    /// Each datagram is a separate unit.
    Udp,
    /// Any other IP protocol, and IP fragments: counted in bytes only.
    Ip(u8),
}

impl FlowKind {
    pub fn from_proto(proto: u8, fragment: bool) -> Self {
        match proto {
            IPPROTO_TCP if !fragment => FlowKind::Tcp,
            IPPROTO_UDP if !fragment => FlowKind::Udp,
            p => FlowKind::Ip(p),
        }
    }
}

impl fmt::Display for FlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowKind::Tcp => f.write_str("tcp"),
            FlowKind::Udp => f.write_str("udp"),
            FlowKind::Ip(p) => write!(f, "ip{p}"),
        }
    }
}

impl Serialize for FlowKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// A Flow key without its generation: (Link, protocol, the two endpoints
/// sorted).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tuple {
    pub link: LinkId,
    pub kind: FlowKind,
    pub lo: Endpoint,
    pub hi: Endpoint,
}

impl Tuple {
    pub fn new(link: LinkId, kind: FlowKind, a: Endpoint, b: Endpoint) -> Self {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        Tuple { link, kind, lo, hi }
    }
}

/// A Flow's id: its tuple plus a generation counter that starts a new Flow
/// when the tuple is reused after FIN/RST or a long idle gap. Rendered as
/// `link|kind|lo|hi|generation`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(Arc<str>);

impl FlowId {
    pub fn new(tuple: &Tuple, generation: u32) -> Self {
        FlowId(Arc::from(format!(
            "{}|{}|{}|{}|{}",
            tuple.link, tuple.kind, tuple.lo, tuple.hi, generation
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for FlowId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Which way bytes travel within a Flow. `Orig` is the endpoint that sent the
/// SYN, or, without a handshake, the sender of the first packet seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    Orig,
    Resp,
}

impl Dir {
    pub fn as_str(self) -> &'static str {
        match self {
            Dir::Orig => "orig",
            Dir::Resp => "resp",
        }
    }

    pub fn idx(self) -> usize {
        match self {
            Dir::Orig => 0,
            Dir::Resp => 1,
        }
    }

    pub fn other(self) -> Dir {
        match self {
            Dir::Orig => Dir::Resp,
            Dir::Resp => Dir::Orig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_sorts_endpoints() {
        let a = Endpoint {
            ip: "10.0.0.2".parse().unwrap(),
            port: 80,
        };
        let b = Endpoint {
            ip: "10.0.0.1".parse().unwrap(),
            port: 5000,
        };
        let link = LinkId::new("lo");
        assert_eq!(
            Tuple::new(link.clone(), FlowKind::Tcp, a, b),
            Tuple::new(link.clone(), FlowKind::Tcp, b, a)
        );
        let id = FlowId::new(&Tuple::new(link, FlowKind::Tcp, a, b), 2);
        assert_eq!(id.as_str(), "lo|tcp|10.0.0.1:5000|10.0.0.2:80|2");
    }

    #[test]
    fn ipv6_endpoint_display() {
        let e = Endpoint {
            ip: "::1".parse().unwrap(),
            port: 443,
        };
        assert_eq!(e.to_string(), "[::1]:443");
    }
}
