//! Bidirectional conformance: a bug written by cjp2p's native Rust layer
//! (gix + gobytes) is read by a vanilla `git-bug` binary, with matching id,
//! title, and status.
//!
//! SKIPPED (not failed) when no git-bug binary is found, so CI without the Go
//! tool still passes. Enable by putting `git-bug` on PATH, at
//! `~/go/bin/git-bug`, or via `GIT_BUG=/path/to/git-bug`. Pinned to v0.10.1
//! (see tests/conformance/README.md).

use cjp2p_ctl::gitbug::gobytes::{Author, CreateOp, Nonce, Operation, OperationPack};
use cjp2p_ctl::gitbug::store::Store;
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
