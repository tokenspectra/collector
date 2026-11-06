//! The bundle's formats (`docs/design/hardware-collector.md` §7): the window
//! manifest and its format version ([`manifest`]) and the index-table
//! schemas ([`index`]). Types only: signing, the on-disk log and writing the
//! tables stay in the Collector. `crates/collector/tests/boundary.rs` holds
//! that line.

pub mod index;
pub mod manifest;
