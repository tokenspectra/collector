//! Cutting the packet stream into windows (spec §3 "Windows").
//!
//! A window is `[k·W, (k+1)·W)` in capture time. One L0 chunk holds one Link's
//! packets for one window, so a packet's address is (Link, window start,
//! index within that chunk). Window `W` is the Slice length.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::source::LinkId;

/// Where a packet sits in L0: the chunk (this Link's packets in the window
/// starting at `window_start_ns`) and its index within that chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PacketRef {
    pub window_start_ns: u64,
    pub index: u32,
}

/// Assigns packets to windows in capture order.
///
/// Windows only move forward. A packet whose timestamp is earlier than the
/// current window (capture clocks can step back slightly) stays in the
/// current window; its own timestamp is kept as is.
pub struct Windower {
    window_ns: u64,
    current: Option<u64>,
    next_index: BTreeMap<LinkId, u32>,
}

/// The result of placing one packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Placed {
    pub at: PacketRef,
    /// The window that this packet closed, if it opened a new one.
    pub closed: Option<u64>,
}

impl Windower {
    pub fn new(window_ns: u64) -> Self {
        assert!(window_ns > 0, "window length must be positive");
        Windower {
            window_ns,
            current: None,
            next_index: BTreeMap::new(),
        }
    }

    pub fn window_ns(&self) -> u64 {
        self.window_ns
    }

    /// The window currently open, if any packet has been seen.
    pub fn current(&self) -> Option<u64> {
        self.current
    }

    pub fn place(&mut self, link: &LinkId, ts_ns: u64) -> Placed {
        let start = ts_ns - ts_ns % self.window_ns;
        let mut closed = None;
        match self.current {
            None => self.current = Some(start),
            Some(cur) if start > cur => {
                closed = Some(cur);
                self.current = Some(start);
                self.next_index.clear();
            }
            Some(_) => {}
        }
        let window_start_ns = self.current.unwrap_or(start);
        let index = self.next_index.entry(link.clone()).or_insert(0);
        let at = PacketRef {
            window_start_ns,
            index: *index,
        };
        *index += 1;
        Placed { at, closed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_per_link_and_window() {
        let mut w = Windower::new(10);
        let a = LinkId::new("a");
        let b = LinkId::new("b");
        assert_eq!(
            w.place(&a, 3).at,
            PacketRef {
                window_start_ns: 0,
                index: 0
            }
        );
        assert_eq!(
            w.place(&b, 4).at,
            PacketRef {
                window_start_ns: 0,
                index: 0
            }
        );
        assert_eq!(
            w.place(&a, 9).at,
            PacketRef {
                window_start_ns: 0,
                index: 1
            }
        );
        let p = w.place(&a, 25);
        assert_eq!(
            p.at,
            PacketRef {
                window_start_ns: 20,
                index: 0
            }
        );
        assert_eq!(p.closed, Some(0));
    }

    #[test]
    fn late_packet_stays_in_current_window() {
        let mut w = Windower::new(10);
        let a = LinkId::new("a");
        w.place(&a, 12);
        let p = w.place(&a, 8);
        assert_eq!(
            p.at,
            PacketRef {
                window_start_ns: 10,
                index: 1
            }
        );
        assert_eq!(p.closed, None);
    }
}
