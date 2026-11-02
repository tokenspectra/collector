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
//! The control plane hands out that secret; until it does, each window's
//! secret is derived from a run key (`--capture-key`).

use crate::decode::{Bucket, WorkunitTag};

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Share of Request Workunits whose packets are kept in full, 0 to 1.
    pub rate: f64,
    /// Key the per-window secrets are derived from. Needed when `rate < 1`.
    pub key: Option<[u8; 32]>,
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
            truncate_to: 128,
            alarm_cap_bytes: 16 << 20,
        }
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
        self.key
            .map(|k| *blake3::keyed_hash(&k, &window_start_ns.to_be_bytes()).as_bytes())
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
                (Bucket::Unexplained, _) => alarm = true,
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
