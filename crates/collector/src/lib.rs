//! TokenSpectra Collector.
//!
//! Packet input ([`source`], [`ring`]), windowing ([`window`]), Flow
//! assembly ([`assembler`]), and protocol identification, byte accounting,
//! HTTP/1.1, h2c, SSE and OpenAI Request Workunits ([`decode`]), multihash
//! names ([`mh`]) and body views ([`views`]). See `docs/spec.md` §3–8.

pub mod assembler;
pub mod decode;
pub mod flow;
mod hpack;
mod hpack_huffman;
mod http;
mod http1;
mod http2;
pub mod mh;
pub mod net;
pub mod openai;
pub mod output;
pub mod ring;
pub mod run;
pub mod source;
mod sse;
mod tcp;
#[cfg(unix)]
pub mod views;
pub mod window;

pub use assembler::{Assembler, AssemblerConfig, FlowSink};
pub use decode::{Decoder, DecoderConfig, RecordSink};
pub use ring::{RingConfig, RingSource};
pub use source::{CapturedPacket, FileSource, LinkId, PacketSource, SourceError};
pub use window::{PacketRef, Windower};
