# ADR 0002 — blake3_tree_v2: what a tree id names, and what a reader checks

- **Status:** Proposed (implemented in this change; awaits kermit)
- **Author:** Zach Norman <zach@nor.mn>
- **Deciders:** Zach Norman, Christopher Pearson (kermit4)
- **Affects:** `src/main.rs` tree v2 code, `docs/blake3_tree_v2.md`

## Context

`blake3/<root>` downloads trust no peer: the node fetches
`blake3_tree_v2/<root>`, checks it, then checks every 4KB block against its leaf.
Completed downloads are not hashed again as a whole, so the tree check is the
whole integrity story. The format is written up in `docs/blake3_tree_v2.md`.
Before this change it had a five-line comment and no tests.

Three gaps on `master`:

1. **Leaves are not bound to the root.** `check_tree_v2_data` compares the header
   root with the id and each parent with its children, but never compares
   `merge_subtrees_root(top[0], top[1])` with the root, and never compares a
   copied-up odd entry with its copy. A peer can send a self-consistent tree for
   other content with the wanted root in its header, and the node keeps and
   republishes that content under the wanted id. In a tree whose block count is
   not a power of two, the last leaf can also be swapped.
2. **One-block trees never load.** `n_leaves_from_tree_v2_eof` rejects files under
   128 bytes, and a one-block tree is 96, so small `blake3/` content never
   completes through a tree.
3. **Header bytes 4..32 are covered by nothing.** Two tree files that differ only
   there both pass, and a node re-serves whichever it got. A peer can stamp each
   copy it serves (224 bits) to map who fetched from whom, one id stops naming one
   file, and honest nodes store and spread 28 bytes of arbitrary data.

## Decision

1. **Bind leaves to the root.** The check also requires
   `merge_subtrees_root(top[0], top[1]) == root` for 2 or more blocks, and every
   copied-up entry to equal its copy. Failures go through the existing retry path.
2. **Load one-block trees.** Leaf count is recovered from any length for 1 block
   and up. A one-block tree's leaf is not a merge input, so its single content
   block is checked against the root (`blake3::hash(block)`).
3. **Keep bytes 4..32 reserved, with a rule.** A tree id names the magic, root and
   levels. Bytes 4..32 are written as zero, never read, never a reason to reject
   a tree, and zeroed when a node stores a tree it received and in every piece of
   a tree file it sends.
4. **No format change, no new magic.** Trees built by existing nodes stay valid,
   and existing nodes still accept trees from updated ones.
5. **Pin the format with tests.** Test vectors (length, root, blake3 of the tree
   file), plus tests for forged trees, one-block trees, reserved bytes, and
   root == `blake3::hash(content)`.

## Options considered

- **Record block size and content length in bytes 4..32** (withdrawn #6). The id
  cannot cover them, so a length there is an unverified hint that a trusting
  reader would use to reject an honest last block. The last block already gives
  the exact length, and a different block size needs a new magic anyway.
- **Reject trees with nonzero bytes 4..32.** Stricter, but it would stop old
  nodes from fetching trees if a later format ever uses those bytes. Zeroing
  gives the same one-id-one-file result without that cost.
- **A v3 magic that hashes the header into the id.** Not possible while the id is
  `blake3::hash(content)`, which is what lets `blake3/<x>` and
  `blake3_tree_v2/<x>` share a digest.

## Consequences

- ✅ A tree that passes binds every leaf to the id, and a one-block download works.
- ✅ One tree id names one file on every updated node.
- ✅ The format has a description and tests outside the code.
- ⚠️ A one-block tree's leaf stays unvouched until its block arrives and matches
  the root. That is harmless, since nothing else reads that leaf.
- ⚠️ Old nodes keep the gaps above until they update. Updated nodes are safe
  against them.

## Open questions for kermit

1. OK to treat bytes 4..32 as reserved-and-zeroed rather than giving them fields?
2. For one-block content, check the block against the root (this change), or
   skip the tree fetch entirely for content of 4096 bytes or less?
3. Tests sit in a `#[cfg(test)]` module at the end of `main.rs`. Fine there, or
   somewhere else?
