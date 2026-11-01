//! Packet input: the [`PacketSource`] trait and [`FileSource`] (spec §3).
//!
//! Every timestamp comes from the capture file, never from the wall clock, so
//! the same files always yield the same packets.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::TsResolution;

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

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: {source}")]
    Pcap {
        path: PathBuf,
        #[source]
        source: pcap_file::PcapError,
    },
    #[error("{path}: {msg}")]
    Format { path: PathBuf, msg: String },
    #[error("dumpcap: {0}")]
    Dumpcap(String),
}

/// Yields packets in capture order.
pub trait PacketSource {
    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>>;
}

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// Reads `.pcap` and `.pcapng` files, one after the other, with `pcap-file`.
pub struct FileSource {
    pending: VecDeque<PathBuf>,
    current: Option<OpenFile>,
}

impl FileSource {
    /// A source over one file or an ordered list of files.
    pub fn new<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        FileSource {
            pending: paths.into_iter().map(Into::into).collect(),
            current: None,
        }
    }

    /// Adds a file to the end of the list.
    pub fn push_path(&mut self, path: impl Into<PathBuf>) {
        self.pending.push_back(path.into());
    }
}

impl PacketSource for FileSource {
    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>> {
        loop {
            if let Some(file) = &mut self.current {
                match file.next() {
                    Some(item) => return Some(item),
                    None => self.current = None,
                }
            }
            let path = self.pending.pop_front()?;
            match OpenFile::open(&path) {
                Ok(file) => self.current = Some(file),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

struct OpenFile {
    path: PathBuf,
    reader: Reader,
    failed: bool,
}

enum Reader {
    Ng(Box<PcapNgReader<BufReader<File>>>),
    Legacy {
        reader: Box<PcapReader<BufReader<File>>>,
        link_type: u32,
        nanos: bool,
    },
}

impl OpenFile {
    fn open(path: &Path) -> Result<Self, SourceError> {
        let io_err = |source| SourceError::Io {
            path: path.to_owned(),
            source,
        };
        let pcap_err = |source| SourceError::Pcap {
            path: path.to_owned(),
            source,
        };
        let mut file = File::open(path).map_err(io_err)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(io_err)?;
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        let buf = BufReader::new(file);
        let reader = if magic == PCAPNG_MAGIC {
            Reader::Ng(Box::new(PcapNgReader::new(buf).map_err(pcap_err)?))
        } else {
            let reader = PcapReader::new(buf).map_err(pcap_err)?;
            let header = reader.header();
            Reader::Legacy {
                link_type: u32::from(header.datalink),
                nanos: header.ts_resolution == TsResolution::NanoSecond,
                reader: Box::new(reader),
            }
        };
        Ok(OpenFile {
            path: path.to_owned(),
            reader,
            failed: false,
        })
    }

    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>> {
        if self.failed {
            return None;
        }
        let item = match &mut self.reader {
            Reader::Ng(reader) => next_pcapng(&self.path, reader),
            Reader::Legacy {
                reader,
                link_type,
                nanos,
            } => next_legacy(&self.path, reader, *link_type, *nanos),
        };
        if matches!(item, Some(Err(_))) {
            self.failed = true;
        }
        item
    }
}

fn format_err(path: &Path, msg: impl Into<String>) -> SourceError {
    SourceError::Format {
        path: path.to_owned(),
        msg: msg.into(),
    }
}

fn next_pcapng(
    path: &Path,
    reader: &mut PcapNgReader<BufReader<File>>,
) -> Option<Result<CapturedPacket, SourceError>> {
    loop {
        let block = match reader.next_block()? {
            Ok(block) => block,
            Err(source) => {
                return Some(Err(SourceError::Pcap {
                    path: path.to_owned(),
                    source,
                }))
            }
        };
        let (interface_id, raw_ts, orig_len, data) = match block {
            Block::EnhancedPacket(epb) => (
                epb.interface_id,
                // pcap-file stores the raw timestamp units as nanoseconds; the
                // real unit comes from the interface's if_tsresol.
                epb.timestamp.as_nanos() as u64,
                epb.original_len,
                epb.data.into_owned(),
            ),
            Block::SimplePacket(_) | Block::Packet(_) => {
                return Some(Err(format_err(
                    path,
                    "only Enhanced Packet Blocks are supported (Simple Packet Blocks carry no timestamp)",
                )))
            }
            _ => continue,
        };
        let Some(idb) = reader.interfaces().get(interface_id as usize) else {
            return Some(Err(format_err(
                path,
                format!("packet refers to unknown interface {interface_id}"),
            )));
        };
        let ts_ns = match pcapng_ts_ns(idb, raw_ts) {
            Some(ts) => ts,
            None => return Some(Err(format_err(path, "timestamp out of range"))),
        };
        return Some(Ok(CapturedPacket {
            link_id: link_id(idb, interface_id),
            link_type: u32::from(idb.linktype),
            ts_ns,
            orig_len,
            data,
        }));
    }
}

fn link_id(idb: &InterfaceDescriptionBlock, interface_id: u32) -> LinkId {
    for opt in &idb.options {
        if let InterfaceDescriptionOption::IfName(name) = opt {
            return LinkId::new(name);
        }
    }
    LinkId::new(&format!("if{interface_id}"))
}

/// Converts a raw pcapng timestamp to nanoseconds using `if_tsresol`
/// (default 10^-6) and `if_tsoffset` (seconds, default 0).
fn pcapng_ts_ns(idb: &InterfaceDescriptionBlock, raw: u64) -> Option<u64> {
    let mut resol = 6u8;
    let mut offset_s = 0u64;
    for opt in &idb.options {
        match opt {
            InterfaceDescriptionOption::IfTsResol(r) => resol = *r,
            InterfaceDescriptionOption::IfTsOffset(o) => offset_s = *o,
            _ => {}
        }
    }
    let raw = raw as u128;
    let ns: u128 = if resol & 0x80 == 0 {
        let exp = u32::from(resol);
        if exp <= 9 {
            raw.checked_mul(10u128.pow(9 - exp))?
        } else {
            raw / 10u128.checked_pow(exp - 9)?
        }
    } else {
        let exp = u32::from(resol & 0x7f);
        if exp > 64 {
            return None;
        }
        raw.checked_mul(1_000_000_000)? >> exp
    };
    let ns = ns.checked_add(u128::from(offset_s).checked_mul(1_000_000_000)?)?;
    u64::try_from(ns).ok()
}

fn next_legacy(
    path: &Path,
    reader: &mut PcapReader<BufReader<File>>,
    link_type: u32,
    nanos: bool,
) -> Option<Result<CapturedPacket, SourceError>> {
    // Raw packets: pcap-file's validated reader rejects orig_len > snaplen,
    // which is exactly what a truncated capture looks like.
    let raw = match reader.next_raw_packet()? {
        Ok(raw) => raw,
        Err(source) => {
            return Some(Err(SourceError::Pcap {
                path: path.to_owned(),
                source,
            }))
        }
    };
    let frac_ns = if nanos {
        u64::from(raw.ts_frac)
    } else {
        u64::from(raw.ts_frac) * 1000
    };
    if frac_ns >= 1_000_000_000 {
        return Some(Err(format_err(path, "timestamp fraction out of range")));
    }
    if raw.incl_len > raw.orig_len {
        return Some(Err(format_err(path, "captured length exceeds original length")));
    }
    Some(Ok(CapturedPacket {
        link_id: LinkId::new("if0"),
        link_type,
        ts_ns: u64::from(raw.ts_sec) * 1_000_000_000 + frac_ns,
        orig_len: raw.orig_len,
        data: raw.data.into_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn idb(opts: Vec<InterfaceDescriptionOption<'static>>) -> InterfaceDescriptionBlock<'static> {
        InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::ETHERNET,
            snaplen: 0,
            options: opts,
        }
    }

    #[test]
    fn ts_default_resolution_is_microseconds() {
        assert_eq!(pcapng_ts_ns(&idb(vec![]), 1_500_000), Some(1_500_000_000));
    }

    #[test]
    fn ts_nanosecond_and_binary_resolution() {
        let ns = idb(vec![InterfaceDescriptionOption::IfTsResol(9)]);
        assert_eq!(pcapng_ts_ns(&ns, 42), Some(42));
        let bin = idb(vec![InterfaceDescriptionOption::IfTsResol(0x80 | 10)]);
        assert_eq!(pcapng_ts_ns(&bin, 1024), Some(1_000_000_000));
        let off = idb(vec![
            InterfaceDescriptionOption::IfTsResol(9),
            InterfaceDescriptionOption::IfTsOffset(2),
        ]);
        assert_eq!(pcapng_ts_ns(&off, 5), Some(2_000_000_005));
    }

    #[test]
    fn link_id_from_if_name() {
        let named = idb(vec![InterfaceDescriptionOption::IfName(Cow::Borrowed("lo"))]);
        assert_eq!(link_id(&named, 3).as_str(), "lo");
        assert_eq!(link_id(&idb(vec![]), 3).as_str(), "if3");
    }
}
