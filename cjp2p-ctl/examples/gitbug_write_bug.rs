//! Conformance probe: write a git-bug bug into an existing repo using cjp2p's
//! native Rust layer, then a vanilla `git-bug` should be able to read it.
//!
//!   cargo run --example gitbug_write_bug -- <repo-dir> <author-id> [title]
//!
//! Prints the derived bug id.

use cjp2p_ctl::gitbug::gobytes::{Author, CreateOp, Nonce, Operation, OperationPack};
use cjp2p_ctl::gitbug::store::Store;

fn main() {
    let mut args = std::env::args().skip(1);
    let repo = args.next().expect("usage: <repo-dir> <author-id> [title]");
    let author = args.next().expect("usage: <repo-dir> <author-id> [title]");
    let title = args.next().unwrap_or_else(|| "Written by cjp2p".to_string());

    let pack = OperationPack {
        author: Author {
            id: author,
        },
        ops: vec![Operation::Create(CreateOp::new(
            1781944244,
            Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80="),
            title,
            "Body from cjp2p".to_string(),
        ))],
    };
    let store = Store::open(&repo).expect("open repo");
    let id = store.create_bug(&pack, 2, 1781944245).expect("create bug");
    println!("{}", id.full());
}
