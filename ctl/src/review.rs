//! Local git-bug review board: list / show / post review items over a repo.
//!
//! Read side folds `refs/bugs/*` into current state; post side authors a new
//! "change" item (Create + labels) the same way `seed_review_board` does, but
//! reusing/creating one board identity and advancing the Lamport clock.

use crate::gitbug::bug::BugState;
use crate::gitbug::gobytes::{
    Author, CreateOp, IdentityVersion, LabelChangeOp, Nonce, Operation, OperationPack,
};
use crate::gitbug::id::Id;
use crate::gitbug::store::Store;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A valid 20-byte nonce derived from a seed (no rand dep; distinct per op).
fn nonce(seed: &str) -> Nonce {
    Nonce(Sha256::digest(seed.as_bytes())[..20].to_vec())
}

/// Every review item, folded to current state.
pub fn list(repo: &Path) -> Result<Vec<BugState>> {
    Store::open(repo)?.list_bugs()
}

/// One item resolved by id prefix.
pub fn show(repo: &Path, id_prefix: &str) -> Result<BugState> {
    let store = Store::open(repo)?;
    store.read_bug(&resolve(&store, id_prefix)?)
}

/// Post a new review item; returns its id.
pub fn post(repo: &Path, title: &str, message: &str, labels: &[String]) -> Result<Id> {
    let store = Store::open_or_init(repo)?;
    let author = ensure_identity(&store)?.full().to_string();
    let ts = now();
    let base = store.next_lamport()?;

    let create = OperationPack {
        author: Author {
            id: author.clone(),
        },
        ops: vec![Operation::Create(CreateOp::new(
            ts,
            nonce(&format!("create-{title}-{ts}")),
            title.to_string(),
            message.to_string(),
        ))],
    };
    let id = store.create_bug(&create, base, ts)?;

    if !labels.is_empty() {
        let lbls = OperationPack {
            author: Author {
                id: author,
            },
            ops: vec![Operation::LabelChange(LabelChangeOp::new(
                ts,
                nonce(&format!("label-{title}-{ts}")),
                labels.to_vec(),
                vec![],
            ))],
        };
        store.append_pack(&id, &lbls, base + 1, ts)?;
    }
    Ok(id)
}

/// Reuse the board's identity, or create one (Zach Norman <z@a-i.sh>).
fn ensure_identity(store: &Store) -> Result<Id> {
    if let Some(id) = store.identity_ids()?.into_iter().next() {
        return Ok(id);
    }
    let version = IdentityVersion {
        version: 2,
        times: BTreeMap::new(),
        unix_time: now(),
        name: "Zach Norman".to_string(),
        email: "z@a-i.sh".to_string(),
        nonce: nonce("identity-z@a-i.sh"),
    };
    store.write_identity(&version, now())
}

fn resolve(store: &Store, prefix: &str) -> Result<Id> {
    let matches: Vec<Id> =
        store.bug_ids()?.into_iter().filter(|id| id.full().starts_with(prefix)).collect();
    match matches.len() {
        1 => Ok(matches.into_iter().next().unwrap()),
        0 => bail!("no review item matches id {prefix:?}"),
        n => bail!("ambiguous id {prefix:?} matches {n} items"),
    }
}
