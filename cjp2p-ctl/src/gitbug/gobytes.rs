//! git-bug ON-DISK serialization: byte-exact Go `encoding/json` reproduction.
//!
//! git-bug derives every entity/operation id by hashing the Go `encoding/json`
//! bytes of the object. To interoperate (same ids, verifiable by a vanilla
//! `git-bug`) we must reproduce those bytes EXACTLY. This differs from
//! [`crate::gitbug::jcs`] (RFC 8785) in three load-bearing ways, all verified
//! against `git-bug v0.10.1` output:
//!
//! 1. **Field order = Go struct declaration order**, NOT sorted keys.
//! 2. **HTML-escaping**: `<`→`<`, `>`→`>`, `&`→`&` (plus
//!    U+2028/U+2029), exactly like Go's default `json.Marshal`.
//! 3. **nil slice → `null`** (e.g. `"files":null`), empty *map* → `{}`,
//!    nonce → standard base64. Compact (no whitespace).
//!
//! Verified id derivation (git-bug v0.10.1):
//! * operation id  = `hex(sha256(gobytes(single op)))`; a bug's id is its first
//!   operation's id.
//! * identity id   = `hex(sha256(gobytes(identity version)))`.

use crate::gitbug::id::{derive_id, Id};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::io;

/// A `serde_json` formatter that matches Go's `encoding/json` byte output:
/// compact, plus HTML-escaping of `<`, `>`, `&` and U+2028/U+2029 that
/// `serde_json` leaves unescaped. All other escaping (`\"`, `\\`, control
/// chars) is inherited from the compact default, which already matches Go.
struct GoFormatter;

impl serde_json::ser::Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let bytes = fragment.as_bytes();
        let mut start = 0;
        let mut i = 0;
        while i < bytes.len() {
            let (replacement, width): (Option<&'static [u8]>, usize) = match bytes[i] {
                b'<' => (Some(b"\\u003c"), 1),
                b'>' => (Some(b"\\u003e"), 1),
                b'&' => (Some(b"\\u0026"), 1),
                // U+2028 / U+2029 (Go escapes these too).
                0xE2 if i + 2 < bytes.len() && bytes[i + 1] == 0x80 && bytes[i + 2] == 0xA8 =>
                    (Some(b"\\u2028"), 3),
                0xE2 if i + 2 < bytes.len() && bytes[i + 1] == 0x80 && bytes[i + 2] == 0xA9 =>
                    (Some(b"\\u2029"), 3),
                _ => (None, 1),
            };
            match replacement {
                Some(rep) => {
                    if start < i {
                        writer.write_all(&bytes[start..i])?;
                    }
                    writer.write_all(rep)?;
                    i += width;
                    start = i;
                }
                None => i += 1,
            }
        }
        if start < bytes.len() {
            writer.write_all(&bytes[start..])?;
        }
        Ok(())
    }
}

/// Serialize a value to git-bug's on-disk bytes (Go `encoding/json` compatible).
///
/// Infallible for the types in this module (serialization targets an in-memory
/// `Vec`, and none use non-string map keys); panics on the impossible error.
pub fn to_gobytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut ser = serde_json::Serializer::with_formatter(Vec::new(), GoFormatter);
    value
        .serialize(&mut ser)
        .expect("gobytes: in-memory serialization cannot fail for these types");
    ser.into_inner()
}

/// An operation's random nonce. Serializes as standard base64 (matching Go's
/// `[]byte` json encoding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(pub Vec<u8>);

impl Nonce {
    /// Decode a standard-base64 nonce (as it appears in git-bug objects).
    pub fn from_b64(s: &str) -> Self {
        Nonce(STANDARD.decode(s).expect("invalid base64 nonce"))
    }
}

impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

/// git-bug operation type tags (the `"type"` int).
pub mod op_type {
    pub const CREATE: u8 = 1;
    pub const SET_TITLE: u8 = 2;
    pub const ADD_COMMENT: u8 = 3;
    pub const SET_STATUS: u8 = 4;
    pub const LABEL_CHANGE: u8 = 5;
    pub const EDIT_COMMENT: u8 = 6;
    pub const NO_OP: u8 = 7;
    pub const SET_METADATA: u8 = 8;
}

/// git-bug status values (`SetStatus.status`).
pub mod status {
    pub const OPEN: u8 = 1;
    pub const CLOSED: u8 = 2;
}

// --- Operations. Field order below is git-bug's Go struct declaration order
// --- and MUST NOT be reordered: the bytes (and thus ids) depend on it.

#[derive(Serialize, Clone, Debug)]
pub struct CreateOp {
    #[serde(rename = "type")]
    pub op_type: u8,
    pub timestamp: i64,
    pub nonce: Nonce,
    pub title: String,
    pub message: String,
    pub files: Option<Vec<String>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AddCommentOp {
    #[serde(rename = "type")]
    pub op_type: u8,
    pub timestamp: i64,
    pub nonce: Nonce,
    pub message: String,
    pub files: Option<Vec<String>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SetStatusOp {
    #[serde(rename = "type")]
    pub op_type: u8,
    pub timestamp: i64,
    pub nonce: Nonce,
    pub status: u8,
}

#[derive(Serialize, Clone, Debug)]
pub struct LabelChangeOp {
    #[serde(rename = "type")]
    pub op_type: u8,
    pub timestamp: i64,
    pub nonce: Nonce,
    pub added: Option<Vec<String>>,
    pub removed: Option<Vec<String>>,
}

impl CreateOp {
    pub fn new(timestamp: i64, nonce: Nonce, title: String, message: String) -> Self {
        Self {
            op_type: op_type::CREATE,
            timestamp,
            nonce,
            title,
            message,
            files: None,
        }
    }
}
impl AddCommentOp {
    pub fn new(timestamp: i64, nonce: Nonce, message: String) -> Self {
        Self {
            op_type: op_type::ADD_COMMENT,
            timestamp,
            nonce,
            message,
            files: None,
        }
    }
}
impl SetStatusOp {
    pub fn new(timestamp: i64, nonce: Nonce, status: u8) -> Self {
        Self {
            op_type: op_type::SET_STATUS,
            timestamp,
            nonce,
            status,
        }
    }
}
impl LabelChangeOp {
    pub fn new(timestamp: i64, nonce: Nonce, added: Vec<String>, removed: Vec<String>) -> Self {
        // git-bug encodes an empty change side as `null`, not `[]`.
        let none_if_empty = |v: Vec<String>| {
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        };
        Self {
            op_type: op_type::LABEL_CHANGE,
            timestamp,
            nonce,
            added: none_if_empty(added),
            removed: none_if_empty(removed),
        }
    }
}

/// One operation, serialized as its bare object (no envelope). Untagged: the
/// `"type"` discriminator lives inside each variant, so serialization yields
/// exactly the git-bug object.
#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum Operation {
    Create(CreateOp),
    AddComment(AddCommentOp),
    SetStatus(SetStatusOp),
    LabelChange(LabelChangeOp),
}

impl Operation {
    /// The git-bug operation id: `hex(sha256(gobytes(self)))`.
    pub fn id(&self) -> Id {
        derive_id(&to_gobytes(self))
    }
}

/// Reference to the authoring identity inside an operation pack (`{"id":…}`).
#[derive(Serialize, Clone, Debug)]
pub struct Author {
    pub id: String,
}

/// The `ops` blob: `{"author":{"id":…},"ops":[…]}`.
#[derive(Serialize, Clone, Debug)]
pub struct OperationPack {
    pub author: Author,
    pub ops: Vec<Operation>,
}

/// An identity's first version object (`refs/identities/<id>:version`).
///
/// Field order is git-bug's declaration order. Optional fields not yet modeled
/// (`login`, `avatar_url`, `keys`/`pub_keys`, `metadata`) carry `omitempty` and
/// are emitted only when present; when added they must slot into declaration
/// order (keys BEFORE `nonce`).
#[derive(Serialize, Clone, Debug)]
pub struct IdentityVersion {
    pub version: u32,
    pub times: BTreeMap<String, u64>,
    pub unix_time: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub email: String,
    pub nonce: Nonce,
}

impl IdentityVersion {
    /// The git-bug identity id: `hex(sha256(gobytes(self)))`.
    pub fn id(&self) -> Id {
        derive_id(&to_gobytes(self))
    }
}

#[cfg(test)]
mod tests {
    //! Golden vectors captured from `git-bug v0.10.1` (see
    //! `tests/conformance/`). Each asserts byte-exact serialization AND the
    //! id git-bug computed.
    use super::*;

    fn s(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn create_op_bytes_and_id() {
        let op = Operation::Create(CreateOp::new(
            1781944244,
            Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80="),
            "Test bug title".into(),
            "Initial description".into(),
        ));
        assert_eq!(
            s(to_gobytes(&op)),
            r#"{"type":1,"timestamp":1781944244,"nonce":"2hAOiWL+W83dtXHZGYXAE5ZYh80=","title":"Test bug title","message":"Initial description","files":null}"#
        );
        // A bug's id == its first (Create) operation's id.
        assert_eq!(
            op.id().full(),
            "674ebc4379ad77f98082b9ae774cd04d2336bb307323c4c65dc27de0c6a636da"
        );
    }

    #[test]
    fn add_comment_op_bytes() {
        let op = Operation::AddComment(AddCommentOp::new(
            1781944244,
            Nonce::from_b64("r02xq6HgRJDOQcsyLpFEL6RBdes="),
            "A follow-up comment".into(),
        ));
        assert_eq!(
            s(to_gobytes(&op)),
            r#"{"type":3,"timestamp":1781944244,"nonce":"r02xq6HgRJDOQcsyLpFEL6RBdes=","message":"A follow-up comment","files":null}"#
        );
    }

    #[test]
    fn label_change_op_bytes() {
        // added present, removed nil -> `null` (git-bug's nil-slice encoding).
        let op = Operation::LabelChange(LabelChangeOp::new(
            1781944245,
            Nonce::from_b64("8Xw3nkwIaK1Wksufgguyx5t03+c="),
            vec!["review:in-progress".into()],
            vec![],
        ));
        assert_eq!(
            s(to_gobytes(&op)),
            r#"{"type":5,"timestamp":1781944245,"nonce":"8Xw3nkwIaK1Wksufgguyx5t03+c=","added":["review:in-progress"],"removed":null}"#
        );
    }

    #[test]
    fn set_status_op_bytes() {
        let op = Operation::SetStatus(SetStatusOp::new(
            1781944245,
            Nonce::from_b64("cWbarxcrN2r5GEsidWiwWRsgXEE="),
            status::CLOSED,
        ));
        assert_eq!(
            s(to_gobytes(&op)),
            r#"{"type":4,"timestamp":1781944245,"nonce":"cWbarxcrN2r5GEsidWiwWRsgXEE=","status":2}"#
        );
    }

    #[test]
    fn html_escaping_matches_go() {
        // a<b>&c "q" \z  ->  a<b>&c \"q\" \\z   (Go encoding/json)
        let op = Operation::Create(CreateOp::new(
            1781944532,
            Nonce::from_b64("N52kKMGMwrPDyqH5qYTVEddNNJo="),
            r#"a<b>&c "q" \z"#.into(),
            "m&m <x>".into(),
        ));
        assert_eq!(
            s(to_gobytes(&op)),
            r#"{"type":1,"timestamp":1781944532,"nonce":"N52kKMGMwrPDyqH5qYTVEddNNJo=","title":"a\u003cb\u003e\u0026c \"q\" \\z","message":"m\u0026m \u003cx\u003e","files":null}"#
        );
    }

    #[test]
    fn operation_pack_bytes() {
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
        assert_eq!(
            s(to_gobytes(&pack)),
            r#"{"author":{"id":"3458f17954ad620635b7ff59cc4efa11ec716788226a7d894c87a3a874aebd0f"},"ops":[{"type":1,"timestamp":1781944244,"nonce":"2hAOiWL+W83dtXHZGYXAE5ZYh80=","title":"Test bug title","message":"Initial description","files":null}]}"#
        );
    }

    #[test]
    fn identity_version_bytes_and_id() {
        let id = IdentityVersion {
            version: 2,
            times: BTreeMap::new(),
            unix_time: 1781944244,
            name: "Test User".into(),
            email: "test@example.com".into(),
            nonce: Nonce::from_b64("bmh5eWgSjaEJuPkGnt1lHGef4DQ="),
        };
        assert_eq!(
            s(to_gobytes(&id)),
            r#"{"version":2,"times":{},"unix_time":1781944244,"name":"Test User","email":"test@example.com","nonce":"bmh5eWgSjaEJuPkGnt1lHGef4DQ="}"#
        );
        assert_eq!(
            id.id().full(),
            "3458f17954ad620635b7ff59cc4efa11ec716788226a7d894c87a3a874aebd0f"
        );
    }
}
