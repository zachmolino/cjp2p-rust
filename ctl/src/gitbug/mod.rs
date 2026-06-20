//! Native-Rust git-bug-format review board. The FOUNDATION layer (jcs/id/clock)
//! is git-bug-independent; `gobytes` is the git-bug-specific on-disk
//! serialization (Go `encoding/json` byte-exact), conformance-tested against
//! git-bug v0.10.1 (see `tests/conformance/`).

pub mod clock;
pub mod gobytes;
pub mod id;
pub mod jcs;
pub mod store;
