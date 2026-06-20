//! Canonical JSON (JCS, RFC 8785) for cjp2p's OWN content message_ids.
//!
//! This is JCS (RFC 8785): keys sorted, NO HTML-escaping. It is used for
//! cjp2p's OWN content message_ids (ReviewArticle, LogEvent). It is DISTINCT
//! from git-bug's on-disk serialization (Go `encoding/json`: struct field
//! order, HTML-escapes `<>&`) which will live in a separate `gobytes.rs`. Do
//! NOT use this for git-bug interop IDs.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Canonicalize a JSON value to its RFC 8785 (JCS) byte serialization.
///
/// Object keys are sorted, numbers use the canonical ECMAScript form, and
/// there is NO HTML-escaping of `<`, `>`, `&` (unlike Go's `encoding/json`).
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).context("RFC 8785 (JCS) canonicalization failed")
}

/// Content hash: lowercase `hex(sha256(canonicalize(value)))`, 64 chars.
pub fn content_hash(value: &serde_json::Value) -> Result<String> {
    let canonical = canonicalize(value)?;
    let digest = Sha256::digest(&canonical);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jcs_sorts_object_keys() {
        // RFC 8785: members of a JSON object are sorted by key.
        let v = json!({ "b": 1, "a": 2 });
        let out = String::from_utf8(canonicalize(&v).unwrap()).unwrap();
        assert_eq!(out, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn jcs_canonical_number_formatting() {
        // RFC 8785 mandates the ECMAScript Number-to-String canonical form.
        // A trailing-zero / redundant decimal is normalized.
        let v = json!({ "n": 1.0 });
        let out = String::from_utf8(canonicalize(&v).unwrap()).unwrap();
        assert_eq!(out, r#"{"n":1}"#);

        // 1e3 collapses to its shortest round-trippable decimal form: 1000.
        let v2: serde_json::Value = serde_json::from_str(r#"{"n":1e3}"#).unwrap();
        let out2 = String::from_utf8(canonicalize(&v2).unwrap()).unwrap();
        assert_eq!(out2, r#"{"n":1000}"#);
    }

    #[test]
    fn jcs_does_not_html_escape() {
        // Unlike Go encoding/json, JCS must NOT escape < > &.
        let v = json!({ "s": "a<b>&c" });
        let out = String::from_utf8(canonicalize(&v).unwrap()).unwrap();
        assert_eq!(out, r#"{"s":"a<b>&c"}"#);
    }

    #[test]
    fn content_hash_is_64_lowercase_hex() {
        let v = json!({ "a": 1 });
        let h = content_hash(&v).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn content_hash_independent_of_input_key_order() {
        // Same logical value, different insertion order -> identical hash,
        // because canonicalization sorts keys before hashing.
        let a = json!({ "b": 1, "a": 2, "c": { "z": 9, "y": 8 } });
        let b = json!({ "c": { "y": 8, "z": 9 }, "a": 2, "b": 1 });
        assert_eq!(content_hash(&a).unwrap(), content_hash(&b).unwrap());
    }
}
