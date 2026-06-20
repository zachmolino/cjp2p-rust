//! Seed a git-bug review board (its own repo) with one "change" item per
//! published feature branch, using cjp2p's native layer. View it with
//! `git-bug termui` / `git-bug webui` in the resulting repo.
//!
//!   cargo run -p cjp2p-ctl --example seed_review_board -- <board-repo-dir>

use cjp2p_ctl::gitbug::gobytes::{
    Author, CreateOp, IdentityVersion, LabelChangeOp, Nonce, Operation, OperationPack,
};
use cjp2p_ctl::gitbug::store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A valid, distinct 20-byte nonce derived deterministically (no rand dep).
fn nonce(seed: &str) -> Nonce {
    Nonce(Sha256::digest(seed.as_bytes())[..20].to_vec())
}

fn main() {
    let repo = std::env::args().nth(1).expect("usage: <board-repo-dir>");
    let store = Store::init(&repo).expect("init board repo");
    let ts = 1781944244;

    // One board identity.
    let version = IdentityVersion {
        version: 2,
        times: BTreeMap::new(),
        unix_time: ts,
        name: "Zach Norman".into(),
        email: "z@a-i.sh".into(),
        nonce: nonce("zach-identity"),
    };
    let author_id = store.write_identity(&version, ts).expect("identity").full().to_string();

    let node = "0xb448f524b2f806075e38ef8d40269f767727bd6c77c7edf7e37e23c07fe586d8";
    // (bundle name, title, type label)
    let items: &[(&str, &str, &str)] = &[
        ("feat-build-fmt-tooling", "Adopt nightly rustfmt formatting standard", "type:change"),
        (
            "feat-build-publish-changes",
            "Add `make publish` for LCDP review delivery",
            "type:change",
        ),
        ("feat-config-project-kdl", "Propose project-wide config.kdl", "type:change"),
        ("feat-board-git-bug", "git-bug-format review board (native Rust)", "type:feature"),
        ("feat-tui-chat", "TUI group-chat client", "type:change"),
        ("feat-cjp2p-ctl", "cjp2p-ctl control tool + /content.json", "type:change"),
    ];

    let mut clock = 2u64; // the identity consumed lamport 1
    for (bundle, title, typ) in items {
        let body = format!(
            "Review change.\n\ntarget: /latest/{node}/{bundle}.bundle\n\
             fetch:  wget http://localhost:24255/latest/{node}/{bundle}.bundle -O b && git fetch b"
        );
        let create = OperationPack {
            author: Author {
                id: author_id.clone(),
            },
            ops: vec![Operation::Create(CreateOp::new(
                ts,
                nonce(&format!("create-{bundle}")),
                title.to_string(),
                body,
            ))],
        };
        let bug = store.create_bug(&create, clock, ts).expect("create item");
        clock += 1;

        let labels = OperationPack {
            author: Author {
                id: author_id.clone(),
            },
            ops: vec![Operation::LabelChange(LabelChangeOp::new(
                ts,
                nonce(&format!("label-{bundle}")),
                vec![typ.to_string(), "review:open".to_string()],
                vec![],
            ))],
        };
        store.append_pack(&bug, &labels, clock, ts).expect("label item");
        clock += 1;

        println!("{}  [{}]  {}", &bug.full()[..7], typ, title);
    }
    println!("\nboard seeded at {repo}\nview: (cd {repo} && git-bug termui)   or   git-bug webui");
}
