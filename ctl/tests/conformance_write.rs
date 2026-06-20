//! Bidirectional conformance: a bug written by cjp2p's native Rust layer
//! (gix + gobytes) is read by a vanilla `git-bug` binary, with matching id,
//! title, and status.
//!
//! SKIPPED (not failed) when no git-bug binary is found, so CI without the Go
//! tool still passes. Enable by putting `git-bug` on PATH, at
//! `~/go/bin/git-bug`, or via `GIT_BUG=/path/to/git-bug`. Pinned to v0.10.1
//! (see tests/conformance/README.md).

use cjp2p_ctl::gitbug::gobytes::{
    Author, CreateOp, IdentityVersion, Nonce, Operation, OperationPack,
};
use cjp2p_ctl::gitbug::store::Store;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn git_bug_bin() -> Option<String> {
    if let Ok(p) = std::env::var("GIT_BUG") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let c = format!("{home}/go/bin/git-bug");
        if Path::new(&c).exists() {
            return Some(c);
        }
    }
    Command::new("git-bug")
        .arg("version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "git-bug".to_string())
}

fn run(bin: &str, dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {bin} {args:?}: {e}"))
}

#[test]
fn git_bug_reads_a_bug_written_by_cjp2p() {
    let Some(gb) = git_bug_bin() else {
        eprintln!(
            "SKIP git_bug_reads_a_bug_written_by_cjp2p: no git-bug binary \
                   (PATH / ~/go/bin/git-bug / GIT_BUG=…)"
        );
        return;
    };

    let dir = std::env::temp_dir().join(format!("cjp2p-conf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Fresh repo + a git-bug identity.
    assert!(Command::new("git").args(["init", "-q"]).current_dir(&dir).status().unwrap().success());
    let out = run(
        &gb,
        &dir,
        &["user", "new", "-n", "Test User", "-e", "t@e.com", "-a", "", "--non-interactive"],
    );
    assert!(out.status.success(), "git-bug user new: {}", String::from_utf8_lossy(&out.stderr));

    // The identity id IS the ref name; read it from git directly so we don't
    // build a git-bug cache before our write exists.
    let idref = run("git", &dir, &["for-each-ref", "--format=%(refname)", "refs/identities/"]);
    let refname = String::from_utf8_lossy(&idref.stdout);
    let author_id = refname.trim().rsplit('/').next().unwrap_or_default().to_string();
    assert_eq!(author_id.len(), 64, "expected 64-hex identity id, got {refname:?}");

    // cjp2p writes a bug natively.
    let pack = OperationPack {
        author: Author {
            id: author_id,
        },
        ops: vec![Operation::Create(CreateOp::new(
            1781944244,
            Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80="),
            "Written by cjp2p".into(),
            "Body from cjp2p".into(),
        ))],
    };
    let bug_id = Store::open(&dir).unwrap().create_bug(&pack, 2, 1781944245).unwrap();

    // git-bug caches by ref-hash and won't auto-notice an out-of-band ref;
    // invalidate so it rebuilds, then it must read our bug.
    let _ = std::fs::remove_dir_all(dir.join(".git/git-bug"));
    let ls = run(&gb, &dir, &["bug"]);
    let stdout = String::from_utf8_lossy(&ls.stdout);
    assert!(ls.status.success(), "git-bug bug: {}", String::from_utf8_lossy(&ls.stderr));
    assert!(
        stdout.contains("Written by cjp2p"),
        "git-bug did not read our title; output: {stdout:?}"
    );
    assert!(
        stdout.contains(&bug_id.full()[..7]),
        "git-bug shows a different id; ours={}, output: {stdout:?}",
        bug_id.full()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The full from-scratch path: cjp2p builds an ENTIRE git-bug board (identity +
/// bug) in a bare repo with no git-bug involvement, then a vanilla git-bug reads
/// the bug AND resolves the author identity cjp2p wrote.
#[test]
fn git_bug_reads_a_board_cjp2p_built_from_scratch() {
    let Some(gb) = git_bug_bin() else {
        eprintln!("SKIP git_bug_reads_a_board_cjp2p_built_from_scratch: no git-bug binary");
        return;
    };

    let dir = std::env::temp_dir().join(format!("cjp2p-scratch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // cjp2p creates the repo + identity + bug entirely on its own.
    let store = Store::init(&dir).unwrap();
    let version = IdentityVersion {
        version: 2,
        times: BTreeMap::new(),
        unix_time: 1781944244,
        name: "Zach Norman".into(),
        email: "z@a-i.sh".into(),
        nonce: Nonce::from_b64("bmh5eWgSjaEJuPkGnt1lHGef4DQ="),
    };
    let author = store.write_identity(&version, 1781944244).unwrap();
    let pack = OperationPack {
        author: Author {
            id: author.full().to_string(),
        },
        ops: vec![Operation::Create(CreateOp::new(
            1781944244,
            Nonce::from_b64("2hAOiWL+W83dtXHZGYXAE5ZYh80="),
            "From scratch by cjp2p".into(),
            "Body from cjp2p".into(),
        ))],
    };
    let bug = store.create_bug(&pack, 2, 1781944245).unwrap();

    // Vanilla git-bug reads the bug...
    let _ = std::fs::remove_dir_all(dir.join(".git/git-bug"));
    let bugls = run(&gb, &dir, &["bug"]);
    let bugout = String::from_utf8_lossy(&bugls.stdout);
    assert!(bugls.status.success(), "git-bug bug: {}", String::from_utf8_lossy(&bugls.stderr));
    assert!(
        bugout.contains("From scratch by cjp2p") && bugout.contains(&bug.full()[..7]),
        "git-bug did not read our bug; output: {bugout:?}"
    );

    // ...and resolves the identity cjp2p wrote.
    let userls = run(&gb, &dir, &["user", "--format", "json"]);
    let userout = String::from_utf8_lossy(&userls.stdout);
    assert!(
        userout.contains("Zach Norman") && userout.contains(&author.full()[..]),
        "git-bug did not resolve our identity; output: {userout:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
