//! What the parser is handed: a packet as captured, its Link and its place
//! in L0. Sources and windowing produce these; nothing here does I/O.

use std::fmt;
use std::sync::Arc;

use serde::Serialize;

/// A Link, named after the capture interface (`if_name` in the pcapng
/// Interface Description Block, or `if<N>` when the block has no name).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(pub Arc<str>);

impl LinkId {
    pub fn new(name: &str) -> Self {
        LinkId(Arc::from(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for LinkId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// One packet as captured on a Link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    pub link_id: LinkId,
    /// pcap LINKTYPE_* of the interface.
    pub link_type: u32,
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub ts_ns: u64,
    /// Length of the packet on the wire.
    pub orig_len: u32,
    /// Captured bytes (`data.len()` is the captured length).
    pub data: Vec<u8>,
}

/// Where a packet sits in L0: the chunk (this Link's packets in the window
/// starting at `window_start_ns`) and its index within that chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PacketRef {
    pub window_start_ns: u64,
    pub index: u32,
}
