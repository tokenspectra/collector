//! Packet input: the [`PacketSource`] trait and [`FileSource`] (spec §3).
//!
//! Every timestamp comes from the capture file, never from the wall clock, so
//! the same files always yield the same packets.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use pcap_file::pcap::{PcapReadError, PcapReader, PcapTsResolution};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::interface_statistics::InterfaceStatisticsOption;
use pcap_file::pcapng::{Block, PcapNgReadError, PcapNgReader};

pub use crate::packet::{CapturedPacket, LinkId};

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
        source: PcapReadError,
    },
    #[error("{path}: {source}")]
    PcapNg {
        path: PathBuf,
        #[source]
        source: PcapNgReadError,
    },
    #[error("{path}: {msg}")]
    Format { path: PathBuf, msg: String },
    #[error("dumpcap: {0}")]
    Dumpcap(String),
    #[error(
        "dumpcap not found: `{}` is not on PATH or does not exist. Live capture needs Wireshark's \
         dumpcap (Debian/Ubuntu: `sudo apt install wireshark-common`; Fedora: `sudo dnf install \
         wireshark-cli`; macOS: install Wireshark), or point to it with `--dumpcap <path>`. \
         Reading files (`collector files ...`) does not need it",
        program.display()
    )]
    DumpcapNotFound { program: PathBuf },
    #[error(
        "not allowed to run `{}`: live capture needs membership of the `wireshark` group \
         (`sudo usermod -aG wireshark $USER`, then log in again, or run under \
         `sg wireshark -c \"...\"`)",
        program.display()
    )]
    DumpcapNotPermitted { program: PathBuf },
    #[error("dumpcap exited with {status}{}", if log.is_empty() { String::new() } else { format!(": {log}") })]
    DumpcapFailed {
        status: std::process::ExitStatus,
        log: String,
    },
}

/// Yields packets in capture order.
pub trait PacketSource {
    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>>;

    /// Packets the capture reported dropped so far, if it reports drops.
    /// Diagnostics only: drops never change the output.
    fn capture_drops(&self) -> Option<u64> {
        None
    }
}

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// Reads `.pcap` and `.pcapng` files, one after the other, with `pcap-file`.
pub struct FileSource {
    pending: VecDeque<PathBuf>,
    current: Option<OpenFile>,
    /// The latest `isb_ifdrop` per Link. The counter runs from the start of
    /// the capture, so a later block (or ring file) replaces an earlier one.
    drops: BTreeMap<LinkId, u64>,
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
            drops: BTreeMap::new(),
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
                let item = file.next(&mut self.drops);
                match item {
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

    /// The sum over Links of the latest Interface Statistics Block
    /// `isb_ifdrop`, once any file has one.
    fn capture_drops(&self) -> Option<u64> {
        (!self.drops.is_empty()).then(|| self.drops.values().sum())
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
        let pcapng_err = |source| SourceError::PcapNg {
            path: path.to_owned(),
            source,
        };
        let mut file = File::open(path).map_err(io_err)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(io_err)?;
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        let buf = BufReader::new(file);
        let reader = if magic == PCAPNG_MAGIC {
            Reader::Ng(Box::new(PcapNgReader::new(buf).map_err(pcapng_err)?))
        } else {
            let reader = PcapReader::new(buf).map_err(pcap_err)?;
            let header = reader.header();
            Reader::Legacy {
                link_type: u32::from(header.datalink),
                nanos: header.ts_resolution == PcapTsResolution::NanoSecond,
                reader: Box::new(reader),
            }
        };
        Ok(OpenFile {
            path: path.to_owned(),
            reader,
            failed: false,
        })
    }

    fn next(&mut self, drops: &mut BTreeMap<LinkId, u64>) -> Option<Result<CapturedPacket, SourceError>> {
        if self.failed {
            return None;
        }
        let item = match &mut self.reader {
            Reader::Ng(reader) => next_pcapng(&self.path, reader, drops),
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
    drops: &mut BTreeMap<LinkId, u64>,
) -> Option<Result<CapturedPacket, SourceError>> {
    loop {
        let (block, state) = match reader.next_block()? {
            Ok(next) => next,
            Err(source) => {
                return Some(Err(SourceError::PcapNg {
                    path: path.to_owned(),
                    source,
                }))
            }
        };
        let (interface_id, ts, orig_len, data) = match block {
            Block::EnhancedPacket(epb) => (
                epb.interface_id,
                // pcap-file applies the interface's if_tsresol and
                // if_tsoffset: this is the time since the Unix epoch.
                epb.timestamp,
                epb.original_len,
                epb.data.into_owned(),
            ),
            Block::InterfaceStatistics(isb) => {
                let dropped = isb.options.iter().find_map(|o| match o {
                    InterfaceStatisticsOption::IsbIfDrop(n) => Some(*n),
                    _ => None,
                });
                let idb = state.interfaces().get(isb.interface_id as usize);
                if let (Some(n), Some(idb)) = (dropped, idb) {
                    drops.insert(link_id(idb, isb.interface_id), n);
                }
                continue;
            }
            Block::SimplePacket(_) | Block::Packet(_) => {
                return Some(Err(format_err(
                    path,
                    "only Enhanced Packet Blocks are supported (Simple Packet Blocks carry no timestamp)",
                )))
            }
            _ => continue,
        };
        let Some(idb) = state.interfaces().get(interface_id as usize) else {
            return Some(Err(format_err(
                path,
                format!("packet refers to unknown interface {interface_id}"),
            )));
        };
        let Ok(ts_ns) = u64::try_from(ts.as_nanos()) else {
            return Some(Err(format_err(path, "timestamp out of range")));
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
    use std::time::Duration;

    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use pcap_file::pcapng::blocks::interface_description::InterfaceTsResolution;
    use pcap_file::pcapng::PcapNgWriter;

    fn idb(opts: Vec<InterfaceDescriptionOption<'static>>) -> InterfaceDescriptionBlock<'static> {
        InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::ETHERNET,
            snaplen: 0,
            options: opts,
        }
    }

    /// Writes one packet per (if_tsresol, if_tsoffset) interface, timestamped
    /// `ts`, and reads the file back.
    fn read_back(interfaces: &[(InterfaceTsResolution, i64)], ts: Duration) -> Vec<u64> {
        let mut w = PcapNgWriter::new(Vec::new()).unwrap();
        for (resol, offset) in interfaces {
            let mut idb = idb(vec![InterfaceDescriptionOption::IfTsResol(*resol)]);
            if *offset != 0 {
                idb.options.push(InterfaceDescriptionOption::IfTsOffset(*offset));
            }
            w.write_pcapng_block(idb).unwrap();
        }
        for interface_id in 0..interfaces.len() as u32 {
            w.write_pcapng_block(EnhancedPacketBlock {
                interface_id,
                timestamp: ts,
                original_len: 4,
                data: Cow::Borrowed(&[0; 4]),
                options: vec![],
            })
            .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ts.pcapng");
        std::fs::write(&path, w.into_inner()).unwrap();
        let mut src = FileSource::new([path]);
        std::iter::from_fn(|| src.next())
            .map(|p| p.unwrap().ts_ns)
            .collect()
    }

    /// if_tsresol (decimal and binary) and if_tsoffset all land on the same
    /// nanoseconds since the Unix epoch.
    #[test]
    fn ts_honours_resolution_and_offset() {
        let ts = Duration::new(1_793_620_800, 0);
        let got = read_back(
            &[
                (InterfaceTsResolution::MICRO, 0),
                (InterfaceTsResolution::NANO, 0),
                (InterfaceTsResolution::new(true, 10).unwrap(), 0),
                (InterfaceTsResolution::NANO, 1_000),
            ],
            ts,
        );
        assert_eq!(got, vec![1_793_620_800_000_000_000; 4]);
    }

    #[test]
    fn link_id_from_if_name() {
        let named = idb(vec![InterfaceDescriptionOption::IfName(Cow::Borrowed("lo"))]);
        assert_eq!(link_id(&named, 3).as_str(), "lo");
        assert_eq!(link_id(&idb(vec![]), 3).as_str(), "if3");
    }
}
