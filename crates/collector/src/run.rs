//! Drives a [`PacketSource`] through windowing and Flow assembly.

use crate::assembler::{Assembler, AssemblerConfig, FlowSink};
use crate::source::{PacketSource, SourceError};
use crate::window::Windower;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub packets: u64,
    pub windows: u64,
}

/// Runs every packet of `source` through the assembler, closing windows of
/// `window_ns` as capture time passes, and ends all Flows at the end.
pub fn run(
    source: &mut dyn PacketSource,
    window_ns: u64,
    cfg: AssemblerConfig,
    sink: &mut dyn FlowSink,
) -> Result<Summary, SourceError> {
    let mut windower = Windower::new(window_ns);
    let mut assembler = Assembler::new(cfg);
    let mut summary = Summary::default();
    while let Some(pkt) = source.next() {
        let pkt = pkt?;
        let placed = windower.place(&pkt.link_id, pkt.ts_ns);
        if let Some(closed) = placed.closed {
            assembler.close_window(closed, pkt.ts_ns, sink);
            summary.windows += 1;
        }
        assembler.push(&pkt, placed.at, sink);
        summary.packets += 1;
    }
    if let Some(last) = windower.current() {
        assembler.finish(last, sink);
        summary.windows += 1;
    }
    Ok(summary)
}
