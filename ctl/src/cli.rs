//! clap CLI surface. Each subcommand is a thin wrapper over `actions`/`git`.

use crate::actions::{self, Algo};
use crate::client::NodeClient;
use crate::git;
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cjp2pctl", version, about = "control a local cjp2p / LCDP node")]
pub struct Cli {
    /// node HTTP address host:port (default 127.0.0.1:24255 or $CJP2P_NODE)
    #[arg(long, global = true)]
    pub node: Option<String>,
    /// emit JSON instead of human-readable output
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// node identity, peer counts, free disk
    Status,
    /// list active peers (<250ms)
    Peers,
    /// share a file immutably (hash-addressed)
    Share {
        path: PathBuf,
    },
    /// publish a file updatably (key-addressed, propagates)
    Publish {
        path: PathBuf,
        /// served name (default: the file's name)
        #[arg(long)]
        name: Option<String>,
    },
    /// fetch content by hash
    Get {
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long, conflicts_with = "sha256")]
        blake3: Option<String>,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
    /// list your shared content (origin + public)
    Ls,
    /// share a git repo so others can clone/pull it (bundle -> publish)
    #[command(name = "share-repo")]
    ShareRepo {
        dir: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// clone a repo: cjp2pctl clone lcdp://<pub>/<name> [dest]
    Clone {
        url: String,
        dest: Option<PathBuf>,
    },
    /// pull updates into an lcdp clone (default: current dir)
    Pull {
        dir: Option<PathBuf>,
    },
    /// live terminal dashboard (requires a --features tui build)
    Tui,
    /// local git-bug review board (read/post over a repo)
    Review {
        #[command(subcommand)]
        cmd: ReviewCmd,
    },
}

/// `cjp2pctl review …` — operate on a local git-bug board repo.
#[derive(Subcommand)]
pub enum ReviewCmd {
    /// list review items with status + labels
    List {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// show one item by id prefix
    Show {
        id: String,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// post a new review item (defaults to `type:change` + `review:open`)
    Post {
        #[arg(long)]
        title: String,
        #[arg(long)]
        message: Option<String>,
        /// repeatable, e.g. --label type:change --label review:open
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

pub fn run() -> Result<()> {
    dispatch(Cli::parse())
}

pub fn dispatch(cli: Cli) -> Result<()> {
    let c = NodeClient::resolve(cli.node.as_deref());
    match cli.cmd {
        Cmd::Status => {
            let s = actions::status(&c)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!("identity : {}", s.public_key);
                println!("version  : {}", s.version);
                println!(
                    "peers    : {} active / {} total  ({} unique IPs, {} fast)",
                    s.active_peer_count, s.total_peers, s.unique_ips, s.fast_peer_count
                );
                println!("free disk: {}", human_bytes(s.free_disk_bytes));
            }
        }
        Cmd::Peers => {
            let s = actions::status(&c)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&s.active_peers)?);
            } else if s.active_peers.is_empty() {
                println!("(no active peers)");
            } else {
                println!("{:<24} {:>8}  PUBKEY", "ADDR", "DELAY");
                for p in &s.active_peers {
                    println!("{:<24} {:>6}ms  {}", p.addr, p.delay_ms, p.pubkey);
                }
            }
        }
        Cmd::Share {
            path,
        } => {
            let up = actions::share(&c, &path)?;
            if cli.json {
                println!("{}", serde_json::json!({"sha256": up.sha256, "blake3": up.blake3}));
            } else {
                println!("shared {}", path.display());
                println!("  sha256 {}", up.sha256);
                println!("  blake3 {}", up.blake3);
                println!("  fetch  /{}   or   /blake3/{}", up.sha256, up.blake3);
            }
        }
        Cmd::Publish {
            path,
            name,
        } => {
            let name = name.unwrap_or_else(|| {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".to_string())
            });
            let fname = actions::publish(&c, &path, &name)?;
            let pubkey = actions::status(&c)?.public_key;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"filename": fname, "url": format!("/latest/{pubkey}/{fname}")})
                );
            } else {
                println!("published {fname}");
                println!("  url http://127.0.0.1:24255/latest/{pubkey}/{fname}  (re-publish to push updates)");
            }
        }
        Cmd::Get {
            sha256,
            blake3,
            out,
        } => {
            let (algo, hash) = match (sha256, blake3) {
                (Some(h), None) => (Algo::Sha256, h),
                (None, Some(h)) => (Algo::Blake3, h),
                _ => bail!("specify exactly one of --sha256 <h> or --blake3 <h>"),
            };
            let saved = actions::get(&c, algo, &hash, out.as_deref())?;
            println!("saved {}", saved.display());
        }
        Cmd::Ls => {
            let cj = actions::content(&c)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cj)?);
            } else {
                print_content(&cj);
            }
        }
        Cmd::ShareRepo {
            dir,
            name,
        } => {
            let rs = git::share_repo(&c, &dir, name.as_deref())?;
            let pub_short = rs.public_key.trim_start_matches("0x");
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"name": rs.name, "clone_url": format!("lcdp://{pub_short}/{}", rs.name)})
                );
            } else {
                println!("shared repo '{}'", rs.name);
                println!("  others clone with:");
                println!("    cjp2pctl clone lcdp://{pub_short}/{}", rs.name);
                println!("  re-run share-repo to push new commits; clones then `cjp2pctl pull`");
            }
        }
        Cmd::Clone {
            url,
            dest,
        } => {
            let dest = git::clone_repo(&c, &url, dest.as_deref())?;
            println!("cloned into {}", dest.display());
        }
        Cmd::Pull {
            dir,
        } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            println!("{}", git::pull_repo(&c, &dir)?);
        }
        Cmd::Tui => {
            #[cfg(feature = "tui")]
            {
                crate::tui::run(&c)?;
            }
            #[cfg(not(feature = "tui"))]
            {
                let _ = &c;
                bail!(
                    "this build has no TUI — rebuild with: cargo build -p cjp2p-ctl --features tui"
                );
            }
        }
        Cmd::Review {
            cmd,
        } => review_dispatch(cmd, cli.json)?,
    }
    Ok(())
}

fn review_dispatch(cmd: ReviewCmd, json: bool) -> Result<()> {
    match cmd {
        ReviewCmd::List {
            repo,
        } => {
            let items = crate::review::list(&repo)?;
            if json {
                let arr: Vec<_> = items
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "id": b.id.full(), "status": b.status.as_str(),
                            "review": b.review_state(), "type": b.kind(), "title": b.title,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else if items.is_empty() {
                println!("(no review items)");
            } else {
                println!("{:<9} {:<7} {:<13} {:<8} TITLE", "ID", "STATUS", "REVIEW", "TYPE");
                for b in &items {
                    println!(
                        "{:<9} {:<7} {:<13} {:<8} {}",
                        &b.id.full()[..7],
                        b.status.as_str(),
                        b.review_state().unwrap_or("-"),
                        b.kind().unwrap_or("-"),
                        b.title
                    );
                }
            }
        }
        ReviewCmd::Show {
            id,
            repo,
        } => {
            let b = crate::review::show(&repo, &id)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": b.id.full(), "title": b.title, "status": b.status.as_str(),
                        "review": b.review_state(), "type": b.kind(), "author": b.author,
                        "labels": b.labels, "comments": b.comments.len(),
                    })
                );
            } else {
                println!("item {}", &b.id.full()[..7]);
                println!("  title:  {}", b.title);
                println!(
                    "  status: {}  (review: {}, type: {})",
                    b.status.as_str(),
                    b.review_state().unwrap_or("-"),
                    b.kind().unwrap_or("-")
                );
                println!("  author: {}", b.author.get(..7).unwrap_or(&b.author));
                if !b.labels.is_empty() {
                    let labels: Vec<_> = b.labels.iter().cloned().collect();
                    println!("  labels: {}", labels.join(", "));
                }
                println!("  comments ({}):", b.comments.len());
                for c in &b.comments {
                    let who = c.author.get(..7).unwrap_or(&c.author);
                    println!("    [{who}] {}", c.message.lines().next().unwrap_or(""));
                }
            }
        }
        ReviewCmd::Post {
            title,
            message,
            labels,
            repo,
        } => {
            let labels = if labels.is_empty() {
                vec!["type:change".to_string(), "review:open".to_string()]
            } else {
                labels
            };
            let id = crate::review::post(&repo, &title, message.as_deref().unwrap_or(""), &labels)?;
            if json {
                println!("{}", serde_json::json!({"id": id.full()}));
            } else {
                println!("posted {} [{}]", &id.full()[..7], title);
            }
        }
    }
    Ok(())
}

fn print_content(cj: &crate::types::ContentJson) {
    println!("identity {}", cj.public_key);
    println!("\norigin (updatable, key-addressed):");
    if cj.origin.is_empty() {
        println!("  (none)");
    }
    for o in &cj.origin {
        println!("  {:<28} {:>10}  {}", o.name, human_bytes(o.size), o.url);
    }
    if !cj.directories.is_empty() {
        println!("\nshared directories:");
        for d in &cj.directories {
            println!("  {:<28} {}", d.name, d.url);
        }
    }
    println!("\npublic (immutable, hash-addressed):");
    if cj.public.is_empty() {
        println!("  (none)");
    }
    for p in &cj.public {
        let sha = p.sha256.as_deref().unwrap_or("-");
        let b3 = p.blake3.as_deref().unwrap_or("-");
        let tree = if p.tree {
            " [tree]"
        } else {
            ""
        };
        println!("  {:>10}{}  sha256:{}  blake3:{}", human_bytes(p.size), tree, sha, b3);
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    let mut i = 0;
    while f >= 1024.0 && i < UNITS.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{f:.1} {}", UNITS[i])
    }
}
