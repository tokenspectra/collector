//! The trusted core of the window commitment
//! (`docs/design/hardware-collector.md` §7): the Merkle tree ([`merkle`])
//! and hash names ([`mh`]). No I/O and no `std`, so it builds for the
//! browser and stays small enough to mirror in a hardware Commit Point.
//! `crates/collector/tests/boundary.rs` holds that line.

#![no_std]

extern crate alloc;

pub mod merkle;
pub mod mh;

pub use merkle::merkle_root;
