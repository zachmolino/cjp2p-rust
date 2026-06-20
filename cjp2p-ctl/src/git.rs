//! Git-over-LCDP: share a repo as a `git bundle`, clone/pull it back.
//!
//! Design goal: feel like native git sync, updatable by default (NOT an
//! immutable submodule-style pin). A repo is published as `repos/<name>.bundle`
//! under the node's key, so re-sharing pushes a new version and followers just
//! `pull`. Integrity comes from git's own commit SHAs + `git bundle verify`,
//! plus the node's signed `Latest` envelope binding the bundle to the publisher.
//!
//! Phase 2 (transparent `git clone lcdp://...`) is the `git-remote-lcdp` binary;
//! these subcommands deliver the full capability over the proven data path now.

use crate::client::NodeClient;
use crate::types::is_safe_relative_path;
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub struct RepoShare {
    pub name: String,
    pub public_key: String,
}

pub fn validate_repo_name(name: &str) -> Result<()> {
    let charset_ok =
        name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    // single path component, matching the node's is_safe_relative_path plus a
    // tight charset (the "repos/" prefix is added by us, not the user).
    if !name.is_empty() && charset_ok && is_safe_relative_path(name) {
        Ok(())
    } else {
        bail!("invalid repo name {name:?}: use [A-Za-z0-9._-], no leading dot, no slashes")
    }
}

fn bundle_server_path(pub_hex: &str, name: &str) -> String {
    format!("/latest/0x{}/repos/{}.bundle", pub_hex.trim_start_matches("0x"), name)
}

fn tmp_bundle(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    std::env::temp_dir().join(format!("cjp2p-{safe}-{}.bundle", std::process::id()))
}

fn run_git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("running: git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn share_repo(c: &NodeClient, dir: &Path, name: Option<&str>) -> Result<RepoShare> {
    let dir_s = dir.to_str().ok_or_else(|| anyhow!("non-UTF8 path"))?;
    if run_git(&["-C", dir_s, "rev-parse", "--git-dir"]).is_err() {
        bail!("{} is not a git repository", dir.display());
    }
    let derived = name.map(str::to_string).unwrap_or_else(|| {
        dir.canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "repo".to_string())
            .trim_end_matches(".git")
            .to_string()
    });
    validate_repo_name(&derived)?;

    let tmp = tmp_bundle(&derived);
    let tmp_s = tmp.to_str().ok_or_else(|| anyhow!("non-UTF8 temp path"))?;
    // --all: every branch + tag, full history (not the node's single-branch bundle).
    run_git(&["-C", dir_s, "bundle", "create", tmp_s, "--all"]).context("creating git bundle")?;

    let server_name = format!("repos/{derived}.bundle");
    let res = c.publish(&server_name, &tmp);
    std::fs::remove_file(&tmp).ok();
    res.context("publishing bundle to node")?;

    let public_key = c.status()?.public_key;
    Ok(RepoShare {
        name: derived,
        public_key,
    })
}

pub fn clone_repo(c: &NodeClient, url: &str, dest: Option<&Path>) -> Result<PathBuf> {
    let (pub_hex, name) = parse_lcdp_url(url)?;
    validate_repo_name(&name)?;

    let tmp = tmp_bundle(&name);
    let tmp_s = tmp.to_str().ok_or_else(|| anyhow!("non-UTF8 temp path"))?;
    let bytes = c
        .fetch_bytes(&bundle_server_path(&pub_hex, &name), Duration::from_secs(120))
        .context("fetching bundle (the publisher must be reachable as a peer)")?;
    std::fs::write(&tmp, &bytes)?;

    // No standalone `git bundle verify` here: it requires an existing repo, and a
    // fresh clone has none ("need a repository to verify a bundle"). `git clone`
    // below reads and validates the bundle, failing on corruption — which is the
    // integrity check that matters for a clone.

    let dest = dest.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&name));
    let dest_s = dest.to_str().ok_or_else(|| anyhow!("non-UTF8 dest"))?;
    let res = run_git(&["clone", tmp_s, dest_s]).context("git clone from bundle");
    if res.is_ok() {
        // git clone's default refspec only takes refs/heads/*; also pull the
        // git-bug board refs so a review board (refs/bugs, refs/identities)
        // rides the clone.
        run_git(&[
            "-C",
            dest_s,
            "fetch",
            tmp_s,
            "refs/bugs/*:refs/bugs/*",
            "refs/identities/*:refs/identities/*",
        ])
        .ok();
    }
    std::fs::remove_file(&tmp).ok();
    res?;

    // remember where this came from so `pull` works.
    run_git(&["-C", dest_s, "config", "lcdp.pub", pub_hex.trim_start_matches("0x")]).ok();
    run_git(&["-C", dest_s, "config", "lcdp.name", &name]).ok();
    run_git(&["-C", dest_s, "config", "lcdp.node", c.addr()]).ok();
    Ok(dest)
}

pub fn pull_repo(c: &NodeClient, dir: &Path) -> Result<String> {
    let dir_s = dir.to_str().ok_or_else(|| anyhow!("non-UTF8 path"))?;
    let pub_hex = run_git(&["-C", dir_s, "config", "lcdp.pub"])
        .context("not an lcdp clone (missing lcdp.pub git config)")?
        .trim()
        .to_string();
    let name = run_git(&["-C", dir_s, "config", "lcdp.name"])?.trim().to_string();

    let tmp = tmp_bundle(&name);
    let tmp_s = tmp.to_str().ok_or_else(|| anyhow!("non-UTF8 temp path"))?;
    let bytes = c.fetch_bytes(&bundle_server_path(&pub_hex, &name), Duration::from_secs(120))?;
    std::fs::write(&tmp, &bytes)?;
    // Verify against the existing repo (`-C dir`) so prerequisites are checked
    // and it works regardless of the caller's cwd.
    if let Err(e) = run_git(&["-C", dir_s, "bundle", "verify", tmp_s]) {
        std::fs::remove_file(&tmp).ok();
        return Err(e).context("bundle failed verification");
    }

    // multi-refspec fetch (not `git pull <bundle> HEAD`, which only moves one branch).
    let fetch = run_git(&[
        "-C",
        dir_s,
        "fetch",
        tmp_s,
        "refs/heads/*:refs/remotes/lcdp/*",
        "refs/tags/*:refs/tags/*",
        // git-bug board refs, fast-forward-only (no `+`) so concurrent edits are
        // rejected rather than clobbered — those need a `git bug` merge.
        "refs/bugs/*:refs/bugs/*",
        "refs/identities/*:refs/identities/*",
    ])
    .context("git fetch from bundle");
    std::fs::remove_file(&tmp).ok();
    fetch?;

    // try a fast-forward of the current branch from its lcdp tracking ref.
    let branch = run_git(&["-C", dir_s, "rev-parse", "--abbrev-ref", "HEAD"])
        .unwrap_or_default()
        .trim()
        .to_string();
    if !branch.is_empty()
        && branch != "HEAD"
        && run_git(&["-C", dir_s, "merge", "--ff-only", &format!("refs/remotes/lcdp/{branch}")])
            .is_ok()
    {
        return Ok(format!("updated {name}: fast-forwarded {branch}"));
    }
    Ok(format!(
        "fetched {name} into refs/remotes/lcdp/* — merge manually (e.g. `git merge lcdp/{}`)",
        if branch.is_empty() {
            "main"
        } else {
            &branch
        }
    ))
}

fn parse_lcdp_url(url: &str) -> Result<(String, String)> {
    let s = url
        .trim()
        .strip_prefix("lcdp://")
        .ok_or_else(|| anyhow!("url must start with lcdp:// (got {url})"))?;
    let mut parts = s.splitn(2, '/');
    let pub_hex = parts.next().unwrap_or_default().to_string();
    let name = parts
        .next()
        .unwrap_or_default()
        .trim_end_matches('/')
        .trim_end_matches(".bundle")
        .to_string();
    if pub_hex.is_empty() || name.is_empty() {
        bail!("url must be lcdp://<pubkey>/<name>");
    }
    Ok((pub_hex, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_validation() {
        assert!(validate_repo_name("my-repo").is_ok());
        assert!(validate_repo_name("my.repo_2").is_ok());
        assert!(validate_repo_name(".hidden").is_err());
        assert!(validate_repo_name("a/b").is_err());
        assert!(validate_repo_name("").is_err());
    }

    #[test]
    fn url_parsing() {
        let (p, n) = parse_lcdp_url("lcdp://deadbeef/myrepo").unwrap();
        assert_eq!(p, "deadbeef");
        assert_eq!(n, "myrepo");
        let (p, n) = parse_lcdp_url("lcdp://0xab/foo.bundle").unwrap();
        assert_eq!(p, "0xab");
        assert_eq!(n, "foo");
        assert!(parse_lcdp_url("https://x/y").is_err());
    }

    #[test]
    fn server_path_format() {
        assert_eq!(bundle_server_path("0xabc", "r"), "/latest/0xabc/repos/r.bundle");
        assert_eq!(bundle_server_path("abc", "r"), "/latest/0xabc/repos/r.bundle");
    }
}
