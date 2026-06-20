//! Git object IDs: 64-char lowercase-hex SHA-256 digests.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::fmt;

/// A git object ID.
///
/// Invariant: the inner string is exactly 64 lowercase hex characters
/// (a SHA-256 digest). Construct via [`Id::new`] (validating) or
/// [`derive_id`] (from raw bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(String);

impl Id {
    /// Validate and wrap a hex string. Errors unless it is exactly 64
    /// characters, all in `[0-9a-f]` (lowercase only).
    pub fn new(s: impl Into<String>) -> Result<Id> {
        let s = s.into();
        if s.len() != 64 {
            bail!("invalid id: expected 64 chars, got {}", s.len());
        }
        if !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("invalid id: must be lowercase hex [0-9a-f]");
        }
        Ok(Id(s))
    }

    /// The full 64-char hex string.
    pub fn full(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    /// Git-short style: the first 7 characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0[..7])
    }
}

/// Derive an [`Id`] from raw bytes: lowercase `hex(sha256(bytes))`.
pub fn derive_id(bytes: &[u8]) -> Id {
    let digest = Sha256::digest(bytes);
    Id(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_id_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let id = derive_id(b"");
        assert_eq!(id.full(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let id = derive_id(b"abc");
        assert_eq!(id.full(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn display_truncates_to_seven() {
        let id = derive_id(b"abc");
        assert_eq!(id.to_string(), "ba7816b");
    }

    #[test]
    fn new_accepts_valid_64_hex() {
        let s = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(Id::new(s).unwrap().full(), s);
    }

    #[test]
    fn new_rejects_wrong_length() {
        assert!(Id::new("abc").is_err());
        // 63 chars (one short)
        assert!(Id::new("a".repeat(63)).is_err());
        // 65 chars (one long)
        assert!(Id::new("a".repeat(65)).is_err());
    }

    #[test]
    fn new_rejects_non_hex() {
        // 'g' is not a hex digit
        let s = format!("g{}", "a".repeat(63));
        assert!(Id::new(s).is_err());
    }

    #[test]
    fn new_rejects_uppercase() {
        // Uppercase hex is rejected; ids are canonical lowercase.
        let s = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        assert!(Id::new(s).is_err());
    }
}
