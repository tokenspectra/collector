//! TokenSpectra Collector.
//!
//! Stage 1: packet input ([`source`], [`ring`]), windowing ([`window`]) and
//! Flow assembly ([`assembler`]). See `docs/design/collector.md` §3–4 in the
//! main repo.

pub mod assembler;
pub mod flow;
pub mod net;
pub mod output;
pub mod ring;
pub mod run;
pub mod source;
mod tcp;
pub mod window;

pub use assembler::{Assembler, AssemblerConfig, FlowSink};
pub use ring::{RingConfig, RingSource};
pub use source::{CapturedPacket, FileSource, LinkId, PacketSource, SourceError};
pub use window::{PacketRef, Windower};
