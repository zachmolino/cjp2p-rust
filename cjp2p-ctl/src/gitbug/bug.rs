//! Fold git-bug operation packs into a bug's current state.
//!
//! Reading is Value-based (not the strict write-side [`Operation`] enum) so
//! unknown/future op types are tolerated, not fatal — matching git-bug's own
//! forgiving read model. Ops are applied in commit order (a bug's ref is a
//! linear chain, oldest→newest).
//!
//! [`Operation`]: crate::gitbug::gobytes::Operation

use crate::gitbug::gobytes::{op_type, status};
use crate::gitbug::id::Id;
use anyhow::Result;
use std::collections::BTreeSet;

/// A bug's coarse status (git-bug's native open/closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open,
    Closed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Closed => "closed",
        }
    }
}

/// One folded comment (the Create message counts as the first comment).
#[derive(Clone, Debug)]
pub struct Comment {
    pub author: String,
    pub message: String,
}

/// The folded state of a bug / review item.
#[derive(Clone, Debug)]
pub struct BugState {
    pub id: Id,
    pub title: String,
    pub status: Status,
    pub labels: BTreeSet<String>,
    pub comments: Vec<Comment>,
    /// The authoring identity id (from the first pack).
    pub author: String,
}

impl BugState {
    /// The review lifecycle drawn from the `review:*` label, if present
    /// (e.g. `review:in-progress` -> `Some("in-progress")`).
    pub fn review_state(&self) -> Option<&str> {
        self.labels.iter().find_map(|l| l.strip_prefix("review:"))
    }

    /// The `type:*` label value, if present (e.g. `type:change` -> `change`).
    pub fn kind(&self) -> Option<&str> {
        self.labels.iter().find_map(|l| l.strip_prefix("type:"))
    }
}

/// Fold a bug's operation-pack blobs (oldest first) into its current state.
pub fn fold_packs(id: Id, packs: &[Vec<u8>]) -> Result<BugState> {
    let mut st = BugState {
        id,
        title: String::new(),
        status: Status::Open,
        labels: BTreeSet::new(),
        comments: Vec::new(),
        author: String::new(),
    };

    for bytes in packs {
        let pack: serde_json::Value = serde_json::from_slice(bytes)?;
        let author = pack
            .get("author")
            .and_then(|a| a.get("id"))
            .and_then(|i| i.as_str())
            .unwrap_or_default()
            .to_string();
        if st.author.is_empty() {
            st.author = author.clone();
        }

        let empty = Vec::new();
        let ops = pack.get("ops").and_then(|o| o.as_array()).unwrap_or(&empty);
        for op in ops {
            let str_field = |k: &str| op.get(k).and_then(|v| v.as_str());
            match op.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u8 {
                op_type::CREATE => {
                    if let Some(t) = str_field("title") {
                        st.title = t.to_string();
                    }
                    if let Some(m) = str_field("message").filter(|m| !m.is_empty()) {
                        st.comments.push(Comment {
                            author: author.clone(),
                            message: m.to_string(),
                        });
                    }
                    st.status = Status::Open;
                }
                op_type::SET_TITLE =>
                    if let Some(t) = str_field("title") {
                        st.title = t.to_string();
                    },
                op_type::ADD_COMMENT =>
                    if let Some(m) = str_field("message") {
                        st.comments.push(Comment {
                            author: author.clone(),
                            message: m.to_string(),
                        });
                    },
                op_type::SET_STATUS => {
                    let n =
                        op.get("status").and_then(|v| v.as_u64()).unwrap_or(status::OPEN as u64);
                    st.status = if n as u8 == status::CLOSED {
                        Status::Closed
                    } else {
                        Status::Open
                    };
                }
                op_type::LABEL_CHANGE => {
                    for l in op.get("added").and_then(|v| v.as_array()).unwrap_or(&empty) {
                        if let Some(s) = l.as_str() {
                            st.labels.insert(s.to_string());
                        }
                    }
                    for l in op.get("removed").and_then(|v| v.as_array()).unwrap_or(&empty) {
                        if let Some(s) = l.as_str() {
                            st.labels.remove(s);
                        }
                    }
                }
                _ => {} // unknown/future op types: tolerated, not fatal
            }
        }
    }
    Ok(st)
}
