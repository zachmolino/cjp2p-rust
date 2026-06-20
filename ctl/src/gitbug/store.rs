//! gix-backed read/write of git-bug entities as native git objects.
//!
//! Mirrors git-bug v0.10.1's on-disk layout (observed, see `tests/conformance/`):
//! each entity (`refs/bugs/<id>`) is a chain of commits, one per operation
//! pack. A pack commit's tree carries:
//!   * `ops`                   — the pack JSON blob (gobytes).
//!   * `edit-clock-<N>`        — EMPTY blob; the lamport value is in the name.
//!   * `create-clock-<N>`      — EMPTY blob; FIRST pack only.
//!   * `version-4`             — EMPTY blob; the format version is in the name.
//! Commit author/committer are empty (` <> `); authorship lives in the pack.
//!
//! Pure Rust via gix (no libgit2). This is the object/ref layer; bundles still
//! go through the `git` CLI (Task #6).

use crate::gitbug::bug::{self, BugState};
use crate::gitbug::gobytes::{to_gobytes, IdentityVersion, OperationPack};
use crate::gitbug::id::Id;
use anyhow::{Context, Result};
use gix::objs::tree::{Entry, EntryKind};
use gix::objs::{Commit, Tree};
use gix::refs::transaction::PreviousValue;
use std::path::Path;

pub struct Store {
    repo: gix::Repository,
}

impl Store {
    /// Initialize a fresh git repository to hold git-bug entities.
    pub fn init(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            repo: gix::init(path)?,
        })
    }

    /// Open an existing repository.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            repo: gix::open(path.as_ref().to_path_buf())?,
        })
    }

    /// Open an existing repo, or initialize a fresh one if it isn't a git repo.
    pub fn open_or_init(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        match gix::open(p.to_path_buf()) {
            Ok(repo) => Ok(Self {
                repo,
            }),
            Err(_) => Self::init(p),
        }
    }

    fn empty_blob(&self) -> Result<gix::ObjectId> {
        Ok(self.repo.write_blob([])?.detach())
    }

    /// Write the tree for one operation pack. `create_clock` is `Some` only for
    /// a bug's first (creation) pack. Tree entries are auto-sorted on write.
    fn pack_tree(
        &self,
        pack: &OperationPack,
        create_clock: Option<u64>,
        edit_clock: u64,
    ) -> Result<gix::ObjectId> {
        let ops_oid = self.repo.write_blob(to_gobytes(pack))?.detach();
        let empty = self.empty_blob()?;
        let blob: gix::objs::tree::EntryMode = EntryKind::Blob.into();
        let mut entries = vec![
            Entry {
                mode: blob,
                filename: "ops".into(),
                oid: ops_oid,
            },
            Entry {
                mode: blob,
                filename: format!("edit-clock-{edit_clock}").into(),
                oid: empty,
            },
            Entry {
                mode: blob,
                filename: "version-4".into(),
                oid: empty,
            },
        ];
        if let Some(cc) = create_clock {
            entries.push(Entry {
                mode: blob,
                filename: format!("create-clock-{cc}").into(),
                oid: empty,
            });
        }
        // git requires tree entries sorted by filename; gix asserts it.
        entries.sort();
        Ok(self
            .repo
            .write_object(&Tree {
                entries,
            })?
            .detach())
    }

    /// An empty-name/empty-email signature (` <> <time> +0000`), as git-bug writes.
    fn empty_sig(&self, time: i64) -> gix::actor::Signature {
        gix::actor::Signature {
            name: Default::default(),
            email: Default::default(),
            time: gix::date::Time {
                seconds: time,
                offset: 0,
            },
        }
    }

    fn write_commit(
        &self,
        tree: gix::ObjectId,
        parent: Option<gix::ObjectId>,
        time: i64,
    ) -> Result<gix::ObjectId> {
        let sig = self.empty_sig(time);
        let commit = Commit {
            tree,
            parents: parent.into_iter().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: Default::default(),
            extra_headers: Vec::new(),
        };
        Ok(self.repo.write_object(&commit)?.detach())
    }

    /// Write an identity (its first version object) to `refs/identities/<id>`.
    /// The identity tree is a single `version` blob (no clock/version markers,
    /// unlike bug packs). Returns the id (= `sha256(gobytes(version))`).
    pub fn write_identity(&self, version: &IdentityVersion, commit_time: i64) -> Result<Id> {
        let id = version.id();
        let version_oid = self.repo.write_blob(to_gobytes(version))?.detach();
        let blob: gix::objs::tree::EntryMode = EntryKind::Blob.into();
        let tree = self
            .repo
            .write_object(&Tree {
                entries: vec![Entry {
                    mode: blob,
                    filename: "version".into(),
                    oid: version_oid,
                }],
            })?
            .detach();
        let commit = self.write_commit(tree, None, commit_time)?;
        self.repo.reference(
            format!("refs/identities/{}", id.full()),
            commit,
            PreviousValue::MustNotExist,
            "git-bug: identity",
        )?;
        Ok(id)
    }

    /// Create a new bug from its first (Create) operation pack, at lamport time
    /// `lamport`. Returns the bug id (= the Create operation's id).
    pub fn create_bug(&self, pack: &OperationPack, lamport: u64, commit_time: i64) -> Result<Id> {
        let bug_id = pack.ops.first().context("operation pack has no ops")?.id();
        let tree = self.pack_tree(pack, Some(lamport), lamport)?;
        let commit = self.write_commit(tree, None, commit_time)?;
        self.repo.reference(
            format!("refs/bugs/{}", bug_id.full()),
            commit,
            PreviousValue::MustNotExist,
            "git-bug: create",
        )?;
        Ok(bug_id)
    }

    /// Append an operation pack to an existing bug at lamport edit time `edit_clock`.
    pub fn append_pack(
        &self,
        bug_id: &Id,
        pack: &OperationPack,
        edit_clock: u64,
        commit_time: i64,
    ) -> Result<()> {
        let refname = format!("refs/bugs/{}", bug_id.full());
        let parent = self.repo.find_reference(&refname)?.into_fully_peeled_id()?.detach();
        let tree = self.pack_tree(pack, None, edit_clock)?;
        let commit = self.write_commit(tree, Some(parent), commit_time)?;
        self.repo.reference(refname, commit, PreviousValue::Any, "git-bug: edit")?;
        Ok(())
    }

    /// Read a bug's operation-pack blobs (raw gobytes), oldest first.
    pub fn read_bug_packs(&self, bug_id: &Id) -> Result<Vec<Vec<u8>>> {
        let refname = format!("refs/bugs/{}", bug_id.full());
        let head = self.repo.find_reference(&refname)?.into_fully_peeled_id()?.detach();
        let mut packs = Vec::new();
        let mut oid = Some(head);
        while let Some(o) = oid {
            let commit = self.repo.find_object(o)?.try_into_commit()?;
            let tree = commit.tree()?;
            let entry = tree.find_entry("ops").context("pack commit has no `ops` entry")?;
            packs.push(entry.object()?.detach().data);
            oid = commit.parent_ids().next().map(|id| id.detach());
        }
        packs.reverse();
        Ok(packs)
    }

    /// All bug ids present in the repository (`refs/bugs/*`).
    pub fn bug_ids(&self) -> Result<Vec<Id>> {
        let mut ids = Vec::new();
        for r in self.repo.references()?.prefixed("refs/bugs/")? {
            let r = r.map_err(|e| anyhow::anyhow!("{e}"))?;
            let name = r.name().as_bstr().to_string();
            if let Some(hex) = name.strip_prefix("refs/bugs/") {
                ids.push(Id::new(hex)?);
            }
        }
        Ok(ids)
    }

    /// Read and fold a bug into its current state.
    pub fn read_bug(&self, bug_id: &Id) -> Result<BugState> {
        bug::fold_packs(bug_id.clone(), &self.read_bug_packs(bug_id)?)
    }

    /// Every bug, folded to current state.
    pub fn list_bugs(&self) -> Result<Vec<BugState>> {
        self.bug_ids()?.iter().map(|id| self.read_bug(id)).collect()
    }

    /// All identity ids present (`refs/identities/*`).
    pub fn identity_ids(&self) -> Result<Vec<Id>> {
        let mut ids = Vec::new();
        for r in self.repo.references()?.prefixed("refs/identities/")? {
            let r = r.map_err(|e| anyhow::anyhow!("{e}"))?;
            let name = r.name().as_bstr().to_string();
            if let Some(hex) = name.strip_prefix("refs/identities/") {
                ids.push(Id::new(hex)?);
            }
        }
        Ok(ids)
    }

    /// Next Lamport value for a new op: one past every existing op + identity.
    /// git-bug's global clock ticks once per op; the exact value only affects
    /// merge order, which a single author posting sequentially keeps monotonic.
    pub fn next_lamport(&self) -> Result<u64> {
        let mut ticks = self.identity_ids()?.len() as u64;
        for id in self.bug_ids()? {
            for pack in self.read_bug_packs(&id)? {
                let v: serde_json::Value = serde_json::from_slice(&pack)?;
                ticks +=
                    v.get("ops").and_then(|o| o.as_array()).map(|a| a.len() as u64).unwrap_or(1);
            }
        }
        Ok(ticks + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitbug::gobytes::{
        status, Author, CreateOp, LabelChangeOp, Nonce, Operation, SetStatusOp,
    };

    #[test]
    fn read_bug_folds_title_labels_status() {
        let dir = tempdir();
        let store = Store::init(&dir).unwrap();
        let n = Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80=");
        let author = || Author {
            id: "a".repeat(64),
        };

        let create = OperationPack {
            author: author(),
            ops: vec![Operation::Create(CreateOp::new(
                1,
                n.clone(),
                "My change".into(),
                "desc".into(),
            ))],
        };
        let id = store.create_bug(&create, 2, 1).unwrap();
        let labels = OperationPack {
            author: author(),
            ops: vec![Operation::LabelChange(LabelChangeOp::new(
                1,
                n.clone(),
                vec!["type:change".into(), "review:open".into()],
                vec![],
            ))],
        };
        store.append_pack(&id, &labels, 3, 1).unwrap();
        let close = OperationPack {
            author: author(),
            ops: vec![Operation::SetStatus(SetStatusOp::new(1, n.clone(), status::CLOSED))],
        };
        store.append_pack(&id, &close, 4, 1).unwrap();

        let st = store.read_bug(&id).unwrap();
        assert_eq!(st.title, "My change");
        assert_eq!(st.status, crate::gitbug::bug::Status::Closed);
        assert!(st.labels.contains("type:change"));
        assert_eq!(st.review_state(), Some("open"));
        assert_eq!(st.kind(), Some("change"));
        assert_eq!(st.comments.len(), 1, "the Create message is the first comment");
    }

    fn sample_pack() -> (OperationPack, &'static str) {
        let pack = OperationPack {
            author: Author {
                id: "3458f17954ad620635b7ff59cc4efa11ec716788226a7d894c87a3a874aebd0f".into(),
            },
            ops: vec![Operation::Create(CreateOp::new(
                1781944244,
                Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80="),
                "Test bug title".into(),
                "Initial description".into(),
            ))],
        };
        // The bug id git-bug derived for this exact op.
        (pack, "674ebc4379ad77f98082b9ae774cd04d2336bb307323c4c65dc27de0c6a636da")
    }

    #[test]
    fn create_bug_then_read_roundtrips_and_ids_match() {
        let dir = tempdir();
        let store = Store::init(&dir).unwrap();
        let (pack, want_id) = sample_pack();

        let bug_id = store.create_bug(&pack, 2, 1781944245).unwrap();
        assert_eq!(bug_id.full(), want_id, "bug id == Create op id");

        // The ref exists and is the only bug.
        assert_eq!(store.bug_ids().unwrap(), vec![bug_id.clone()]);

        // The stored ops blob is byte-identical to our gobytes of the pack.
        let packs = store.read_bug_packs(&bug_id).unwrap();
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0], to_gobytes(&pack));
    }

    #[test]
    fn pack_tree_has_expected_entry_names() {
        let dir = tempdir();
        let store = Store::init(&dir).unwrap();
        let (pack, _) = sample_pack();
        let tree_oid = store.pack_tree(&pack, Some(2), 2).unwrap();
        let tree = store.repo.find_object(tree_oid).unwrap().try_into_tree().unwrap();
        let mut names: Vec<String> =
            tree.iter().map(|e| e.unwrap().filename().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["create-clock-2", "edit-clock-2", "ops", "version-4"]);
    }

    // Minimal unique temp dir without pulling a tempfile dep into the lib.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "cjp2p-gitbug-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
