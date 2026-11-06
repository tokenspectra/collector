//! The Capture Rate cut (spec §7): which packets an L0 chunk keeps in full
//! and which it truncates. Hashes and metadata always cover 100%; only the
//! stored payload follows the Capture Rate.
//!
//! | Packet carries | Stored |
//! |---|---|
//! | no stream bytes (handshakes, ACKs), `http_other`, `framing` only, a kept Request Workunit, an anomaly | in full |
//! | otherwise `unexplained` bytes, or a UDP / other IP datagram (the alarm) | in full up to `alarm_cap_bytes` per Flow per Slice, then truncated |
//! | a Request Workunit not kept, besides `framing` or `gap` | truncated to `truncate_to` bytes |
//!
//! Whether a Workunit is kept is a draw keyed by a per-window secret that
//! the Operator cannot predict and that is never derived from the traffic.
//! Each window's secret is `KDF(seed, window)`, with the seed of the epoch
//! the Fleet handed out for that window ([`SeedBook`]), so the Collector
//! doesn't need the channel up every window, and the control plane can
//! recompute any window's secret. `--capture-key` stands in for the seed in
//! development.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::decode::{Bucket, WorkunitTag};

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Share of Request Workunits whose packets are kept in full, 0 to 1.
    pub rate: f64,
    /// Development only: a run key the per-window secrets are derived from.
    pub key: Option<[u8; 32]>,
    /// The Fleet's seed epochs; they win over `key`. One of the two is
    /// needed when `rate < 1`.
    pub seeds: Option<Arc<SeedBook>>,
    /// Captured bytes left in a truncated packet.
    pub truncate_to: u32,
    /// Captured bytes of alarm packets kept in full per Flow per Slice.
    pub alarm_cap_bytes: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            rate: 1.0,
            key: None,
            seeds: None,
            truncate_to: 128,
            alarm_cap_bytes: 16 << 20,
        }
    }
}

/// `KDF(seed, window)`: the secret of the window starting at
/// `window_start_ns`, as the control plane recomputes it.
pub fn derive_secret(seed: &[u8; 32], window_start_ns: u64) -> [u8; 32] {
    *blake3::keyed_hash(seed, &window_start_ns.to_be_bytes()).as_bytes()
}

/// One seed epoch. The seed stays out of `Debug` and logs.
struct Epoch {
    epoch: u64,
    /// The first window start it covers.
    from_ns: u64,
    seed: [u8; 32],
}

/// The seed epochs the Fleet has handed out, in order. A window takes the
/// last epoch that has started by then, or the first one for a window
/// before them all, so with the channel cut the current epoch simply goes
/// on.
///
/// A window's epoch never changes once asked for: an epoch that arrives
/// late starts after the last window drawn on, whatever its `from_ns` said.
/// The manifest names the epoch each window used.
#[derive(Default)]
pub struct SeedBook {
    inner: Mutex<Book>,
}

#[derive(Default)]
struct Book {
    epochs: Vec<Epoch>,
    /// The latest window asked about.
    drawn: Option<u64>,
}

impl fmt::Debug for SeedBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SeedBook")
    }
}

impl SeedBook {
    /// Adds an epoch and returns the window start it really covers from.
    /// An epoch not newer than the last one held is refused with `None`.
    pub fn add(&self, epoch: u64, from_ns: u64, seed: [u8; 32]) -> Option<u64> {
        let mut book = self.inner.lock().expect("seed book");
        let floor = book.drawn.map_or(0, |w| w.saturating_add(1));
        let last = book.epochs.last();
        if last.is_some_and(|e| e.epoch >= epoch) {
            return None;
        }
        let from_ns = from_ns
            .max(floor)
            .max(last.map_or(0, |e| e.from_ns.saturating_add(1)));
        book.epochs.push(Epoch { epoch, from_ns, seed });
        Some(from_ns)
    }

    /// The epoch number and seed of the window starting at
    /// `window_start_ns`.
    pub fn epoch_of(&self, window_start_ns: u64) -> Option<(u64, [u8; 32])> {
        let mut book = self.inner.lock().expect("seed book");
        book.drawn = book.drawn.max(Some(window_start_ns));
        let found = book
            .epochs
            .iter()
            .rev()
            .find(|e| e.from_ns <= window_start_ns)
            .or(book.epochs.first());
        found.map(|e| (e.epoch, e.seed))
    }

    /// The newest epoch held.
    pub fn latest(&self) -> Option<u64> {
        let book = self.inner.lock().expect("seed book");
        book.epochs.last().map(|e| e.epoch)
    }
}

/// What a packet's bytes are, for the cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Kept in full.
    Full,
    /// Kept in full up to the alarm cap.
    Alarm,
    /// Bytes of a Request Workunit the Capture Rate did not keep.
    NotKept,
}

impl CaptureConfig {
    /// The secret of the window starting at `window_start_ns`.
    pub fn window_secret(&self, window_start_ns: u64) -> Option<[u8; 32]> {
        let key = match &self.seeds {
            Some(book) => book.epoch_of(window_start_ns).map(|(_, seed)| seed),
            None => self.key,
        };
        key.map(|k| derive_secret(&k, window_start_ns))
    }

    /// Whether the Capture Rate keeps this Workunit: a keyed draw on its id
    /// with the secret of the window its request started in.
    pub fn keeps(&self, tag: &WorkunitTag, window_ns: u64) -> bool {
        if self.rate >= 1.0 {
            return true;
        }
        if self.rate <= 0.0 {
            return false;
        }
        let window = tag.received_ts_ns - tag.received_ts_ns % window_ns;
        let Some(secret) = self.window_secret(window) else {
            return true;
        };
        let draw = blake3::keyed_hash(&secret, tag.workunit_id.as_bytes());
        let x = u64::from_be_bytes(draw.as_bytes()[..8].try_into().expect("8 bytes"));
        (x as f64) < self.rate * 18_446_744_073_709_551_616.0
    }

    /// Classifies a packet from the buckets of the stream bytes it carries.
    pub fn classify<'a>(
        &self,
        labels: impl IntoIterator<Item = (Bucket, Option<&'a WorkunitTag>)>,
        window_ns: u64,
    ) -> Class {
        let (mut alarm, mut full, mut not_kept) = (false, false, false);
        for (bucket, tag) in labels {
            match (bucket, tag) {
                // A fact's bytes are the alarm's too: the Classifier decides.
                (Bucket::Unexplained | Bucket::Fact, _) => alarm = true,
                (Bucket::HttpOther, _) => full = true,
                (Bucket::Workunit, Some(t)) if !self.keeps(t, window_ns) => not_kept = true,
                (Bucket::Workunit, _) => full = true,
                (Bucket::Framing | Bucket::Gap, _) => {}
            }
        }
        if full {
            Class::Full
        } else if alarm {
            Class::Alarm
        } else if not_kept {
            Class::NotKept
        } else {
            Class::Full
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_takes_the_epoch_that_had_started() {
        let book = SeedBook::default();
        assert_eq!(book.add(1, 100, [1; 32]), Some(100));
        assert_eq!(book.add(2, 200, [2; 32]), Some(200));
        assert_eq!(book.epoch_of(50).unwrap().0, 1, "before them all: the first");
        assert_eq!(book.epoch_of(150).unwrap().0, 1);
        assert_eq!(book.epoch_of(200).unwrap().0, 2);
        assert_eq!(
            book.epoch_of(9000).unwrap().0,
            2,
            "a cut channel: the current one goes on"
        );
        assert_eq!(book.latest(), Some(2));
    }

    #[test]
    fn a_late_epoch_never_changes_a_window_already_drawn_on() {
        let book = SeedBook::default();
        book.add(1, 0, [1; 32]);
        assert_eq!(book.epoch_of(500).unwrap().0, 1);
        assert_eq!(book.add(2, 300, [2; 32]), Some(501));
        assert_eq!(book.epoch_of(500).unwrap().0, 1);
        assert_eq!(book.epoch_of(501).unwrap().0, 2);
    }

    #[test]
    fn an_older_epoch_is_refused() {
        let book = SeedBook::default();
        book.add(5, 0, [1; 32]);
        assert_eq!(book.add(5, 10, [2; 32]), None);
        assert_eq!(book.add(4, 10, [2; 32]), None);
        assert_eq!(book.epoch_of(10).unwrap().1, [1; 32]);
    }

    #[test]
    fn seeds_derive_the_secret_and_win_over_a_run_key() {
        let book = Arc::new(SeedBook::default());
        book.add(1, 0, [9; 32]);
        let cfg = CaptureConfig {
            key: Some([3; 32]),
            seeds: Some(book),
            ..CaptureConfig::default()
        };
        assert_eq!(cfg.window_secret(77), Some(derive_secret(&[9; 32], 77)));
        assert_ne!(cfg.window_secret(77), cfg.window_secret(78));
    }

    fn tag(i: u64) -> WorkunitTag {
        WorkunitTag {
            workunit_id: crate::mh::of(&i.to_be_bytes()),
            received_ts_ns: 5_000_000_000 + i,
        }
    }

    #[test]
    fn draw_follows_the_rate_and_the_key() {
        let mut cfg = CaptureConfig {
            rate: 0.25,
            key: Some([7; 32]),
            ..CaptureConfig::default()
        };
        let w = 1_000_000_000;
        let kept = (0..4000).filter(|&i| cfg.keeps(&tag(i), w)).count();
        assert!((800..1200).contains(&kept), "{kept}");
        let first: Vec<bool> = (0..64).map(|i| cfg.keeps(&tag(i), w)).collect();
        assert_eq!(first, (0..64).map(|i| cfg.keeps(&tag(i), w)).collect::<Vec<_>>());
        cfg.key = Some([8; 32]);
        assert_ne!(first, (0..64).map(|i| cfg.keeps(&tag(i), w)).collect::<Vec<_>>());
        cfg.rate = 1.0;
        assert!((0..64).all(|i| cfg.keeps(&tag(i), w)));
        cfg.rate = 0.0;
        assert!((0..64).all(|i| !cfg.keeps(&tag(i), w)));
    }

    #[test]
    fn classes() {
        let cfg = CaptureConfig {
            rate: 0.0,
            key: Some([1; 32]),
            ..CaptureConfig::default()
        };
        let t = tag(1);
        let w = 1_000_000_000;
        let c = |l: &[(Bucket, Option<&WorkunitTag>)]| cfg.classify(l.iter().copied(), w);
        assert_eq!(c(&[]), Class::Full);
        assert_eq!(c(&[(Bucket::Framing, None)]), Class::Full);
        assert_eq!(
            c(&[(Bucket::Workunit, Some(&t)), (Bucket::Framing, None)]),
            Class::NotKept
        );
        assert_eq!(
            c(&[(Bucket::Workunit, Some(&t)), (Bucket::HttpOther, None)]),
            Class::Full
        );
        assert_eq!(
            c(&[(Bucket::Workunit, Some(&t)), (Bucket::Unexplained, None)]),
            Class::Alarm
        );
        // `http_other` and kept Workunit bytes stay whole beside `unexplained`.
        assert_eq!(
            c(&[(Bucket::Unexplained, None), (Bucket::HttpOther, None)]),
            Class::Full
        );
        let all = CaptureConfig {
            rate: 1.0,
            ..cfg.clone()
        };
        assert_eq!(
            all.classify([(Bucket::Unexplained, None), (Bucket::Workunit, Some(&t))], w),
            Class::Full
        );
    }
}
