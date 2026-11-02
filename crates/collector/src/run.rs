//! Drives a [`PacketSource`] through windowing, Flow assembly and protocol
//! decoding.

use crate::assembler::{Assembler, AssemblerConfig};
use crate::decode::{Decoder, DecoderConfig, RecordSink};
use crate::source::{PacketSource, SourceError};
use crate::window::Windower;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub packets: u64,
    pub windows: u64,
}

/// Runs every packet of `source` through the assembler and decoder,
/// closing windows of `window_ns` as capture time passes, and ends all
/// Flows at the end.
pub fn run(
    source: &mut dyn PacketSource,
    window_ns: u64,
    cfg: AssemblerConfig,
    decoder_cfg: DecoderConfig,
    sink: &mut dyn RecordSink,
) -> Result<Summary, SourceError> {
    let mut windower = Windower::new(window_ns);
    let mut assembler = Assembler::new(cfg);
    let mut decoder = Decoder::new(decoder_cfg, sink);
    let mut summary = Summary::default();
    while let Some(pkt) = source.next() {
        let pkt = pkt?;
        let placed = windower.place(&pkt.link_id, pkt.ts_ns);
        if let Some(closed) = placed.closed {
            assembler.close_window(closed, pkt.ts_ns, &mut decoder);
            summary.windows += 1;
        }
        assembler.push(&pkt, placed.at, &mut decoder);
        summary.packets += 1;
    }
    if let Some(last) = windower.current() {
        assembler.finish(last, &mut decoder);
        summary.windows += 1;
    }
    debug_assert_eq!(decoder.open_flows(), 0, "every Flow ended");
    Ok(summary)
}
