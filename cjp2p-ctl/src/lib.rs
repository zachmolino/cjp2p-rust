//! cjp2p-ctl — a CLI + TUI for a local cjp2p / LCDP node.
//!
//! The node runs as a hardened systemd service (stdin = /dev/null), so the
//! interactive `/publish`-style stdin commands are unreachable. Everything here
//! talks to the node's loopback HTTP/WS surface on 127.0.0.1:24255 instead.
//! One shared `actions` layer is called by the CLI, the TUI, and (later) the
//! git remote helper, so there is exactly one copy of the wire logic.

pub mod actions;
pub mod cli;
pub mod client;
pub mod git;
pub mod gitbug;
pub mod review;
pub mod types;

#[cfg(feature = "tui")]
pub mod tui;
