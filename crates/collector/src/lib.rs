//! TokenSpectra Collector.
//!
//! Packet input ([`source`], [`ring`]), windowing ([`window`]), Flow
//! assembly ([`assembler`]), and protocol identification, byte accounting,
//! HTTP/1.1 and h2c ([`decode`]), Wire Protocols, their response framing
//! (SSE, NDJSON) and Request Workunits ([`wire`]), multihash
//! names ([`mh`]) and body views ([`views`]). Hashing, the Capture Rate
//! cut and the object store: L0 chunks ([`chunk`], [`capture`]), packs
//! ([`pack`]), Parquet index tables ([`index`]), all written by [`store`]. Counters and diagnostics
//! logs ([`stats`], [`observe`]) sit beside the pipeline and never change
//! its output. See `docs/spec.md` §3–8 and §14.

pub mod assembler;
pub mod capture;
pub mod chunk;
pub mod coding;
pub mod decode;
pub mod flow;
mod hpack;
mod hpack_huffman;
mod http;
mod http1;
mod http2;
pub mod index;
pub mod manifest;
pub mod mh;
pub mod net;
pub mod observe;
pub mod output;
pub mod pack;
pub mod ring;
pub mod run;
pub mod ship;
pub mod source;
pub mod spool;
pub mod stats;
pub mod store;
mod tcp;
#[cfg(unix)]
pub mod views;
pub mod window;
pub mod wire;

pub use assembler::{Assembler, AssemblerConfig, FlowSink};
pub use decode::{Decoder, DecoderConfig, RecordSink};
pub use ring::{RingConfig, RingSource};
pub use source::{CapturedPacket, FileSource, LinkId, PacketSource, SourceError};
pub use window::{PacketRef, Windower};
pub use wire::{Protocols, WireProtocol};
