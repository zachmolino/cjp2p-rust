# blake3_tree_v2 tree files

This describes the `blake3_tree_v2` tree file the node builds, and the checks a
reader needs to trust one. It was written from `src/main.rs` (functions named
below) so the format has a description outside the code.

It describes the node as of the commits that land with it, not the `master`
before them. On that `master`, one-block trees fail to load, the tree check does
not compare the root with the top level or copied-up entries with their copies,
and reserved header bytes are stored and served as received. The choices behind
those changes are in `docs/adr/0002-blake3-tree-v2-integrity.md`.

## Two ids, one digest

- `blake3/<root>` names content.
- `blake3_tree_v2/<root>` names a tree file for that content: one BLAKE3
  chaining value per 4KB block, plus the levels above them.

Both use the same 32-byte digest, because the tree's root is
`blake3::hash(content)` (see Root).

## What it is for

The node fetches content 4KB at a time over LCDP (`PleaseSendContent` /
`Content`) from peers it does not trust. For a `blake3/<root>` download it first
fetches `blake3_tree_v2/<root>` (`InboundState::new`), checks the tree against
the id when it completes (`check_tree_v2_data`), and then checks every content
block against its leaf as it arrives (`InboundState::receive_content`). That
gives:

- a bad block is rejected on arrival and re-requested, not discovered when the
  whole file fails a hash;
- blocks can arrive out of order from several peers, so downloads resume and
  ranged requests work;
- checking a block needs only that block.

Completed `blake3/` downloads are not hashed again as a whole, so the tree check
and the per-block check are the whole integrity story for them.

## Content blocks

Content is cut into blocks of `BLOCK_SIZE` = 4096 bytes. Every block is exactly
4096 bytes except the last, which is 1 to 4096 bytes. For content of `len`
bytes there are `n = ceil(len / 4096)` blocks. Empty content has no tree
(`create_tree_for_file`).

4096 has to be a power-of-two multiple of BLAKE3's 1024-byte chunk: that is what
lets a block be hashed as a BLAKE3 subtree.

## Leaves

Leaf `i` is block `i` hashed as a BLAKE3 subtree that starts at byte
`i * 4096` (`block_chaining_value`, using the blake3 crate's hazmat API):

    let mut h = blake3::Hasher::new();
    h.set_input_offset(i * 4096);   // where the block sits in the content
    h.update(block_i);
    h.finalize_non_root()           // a chaining value, not a final hash

**Offset hashing.** BLAKE3 mixes each 1024-byte chunk's position into its hash,
so the same bytes at byte 0 and at byte 4096 hash differently. Passing the offset
makes leaf `i` exactly the value BLAKE3 computes internally for those chunks when
it hashes the whole content. A block therefore verifies on its own, and a real
block cannot be replayed at a different index.

## Levels

Level 0 is the `n` leaves. While a level has more than 2 entries, the next level
up has `ceil(size / 2)` entries (`finalize_tree_mmap_v2`):

- entry `j` is `merge_subtrees_non_root(child[2j], child[2j+1], Mode::Hash)`;
- when the child level has an odd count, its last entry has no partner and is
  **copied up unchanged**.

**Pairing.** Merging left to right with the odd one copied up means the left side
of every split covers a power of two of blocks. That is BLAKE3's own tree shape,
which is why the root below equals a plain BLAKE3 hash.

For `n >= 2` the top stored level has exactly 2 entries. For `n <= 2` the leaves
are the only level. Example: 9 blocks give level sizes 9, 5, 3, 2.

## Root

- `n >= 2`: `merge_subtrees_root(top[0], top[1], Mode::Hash)`.
- `n = 1`: `blake3::hash(content)`. There is nothing to merge, so the root is not
  derived from the single leaf (`build_tree_from_mmap`).

Either way the root equals `blake3::hash(content)`.

## File layout

    offset 0    4 bytes    magic "B3T\x02"
    offset 4   28 bytes    reserved, written as zero
    offset 32  32 bytes    root
    offset 64              levels, top level first, 32 bytes per entry,
                           down to the n leaves, which end the file

Length is `64 + 32 * (sum of all level sizes)` (`tree_file_size_v2`): 96 bytes
for 1 block, 128 for 2, 224 for 3, 256 for 4, 416 for 6. The leaf count is not
stored; it is recovered from the length, which grows strictly with `n`
(`n_leaves_from_tree_v2_eof`). The content length is not stored either: the tree
only says it is in `((n-1) * 4096, n * 4096]`, and the last block fixes it
exactly, because its leaf (or, for one block, the root) binds its length.

## What a tree id names

A `blake3_tree_v2/<root>` id names the file's magic, root and levels. Bytes 4..32
are reserved: written as zero, never read, and never a reason to reject a tree.
The id cannot cover them (the root is `blake3::hash` of the content, so nothing
else in the file is bound to it), so two files that differ only there pass the
same check. If a node kept and served whatever it received:

- a peer could stamp each copy it serves with unique bytes (224 bits) and learn
  who fetched from whom by watching which stamp comes back;
- one id would name many files, which breaks comparing or deduplicating tree
  files byte for byte;
- honest nodes would store and spread 28 bytes of arbitrary data;
- if a later format gave those bytes a meaning, old trees in caches would carry
  garbage there.

So a node zeroes them (`zero_tree_v2_reserved_bytes`) when it stores a tree it
received, before the tree moves to `public/`, and again in every piece of a tree
file it sends to a peer (`Content::new_block`), so trees stored before that rule,
or written by other implementations, never go out doctored. The HTTP gateway
serves no tree files. Block size and content length are deliberately not recorded here:
a length the id cannot cover is an unverified hint, and a different block size
needs a new magic.

One gap remains: a one-block tree's single leaf is not bound to the root (there
is nothing to merge), so those 32 bytes are unvouched until the content block
arrives and is checked against the root.

## Checking a tree against its id

A tree file for `blake3_tree_v2/<root>` is good when:

1. its length is `64 + 32 * sum` for some `n >= 1`;
2. it starts with `B3T\x02`;
3. the header root equals `<root>`;
4. above the leaves, every entry equals the merge of its two children, and every
   copied-up odd entry equals the entry it copies;
5. for `n >= 2`, `merge_subtrees_root(top[0], top[1])` equals the header root.

4 and 5 are what tie every leaf to the id. Without 5, a self-consistent tree
built for other content passes with the wanted root written into the header;
without the copy comparison in 4, the last leaf of a tree whose block count is
not a power of two can be swapped. For `n = 1` only 1-3 apply, because the leaf
is not bound to the root. Bytes 4..32 are not checked.

## Checking a content block

- `n >= 2`: block `i` is good when `block_chaining_value(block, i * 4096)` equals
  leaf `i`. Every block but the last must be 4096 bytes.
- `n = 1`: the block is good when `blake3::hash(block)` equals the root.

## History

v1 (`67d79731`, reverted and replaced by v2 in `dbc69398` the next day) used ids
`blake3_trees/<root>` and had no magic and no root: a little-endian u32 leaf
count, then the same levels, leaves last. v2 drops the count (the length gives
it) and adds the 64-byte header with the magic and the root.

## Test vectors

Content is `(0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))`.
`tree_files_match_the_documented_vectors` in `src/main.rs` checks every row.

| len | blocks | tree bytes | root | blake3 of the tree file |
|---|---|---|---|---|
| 1 | 1 | 96 | `448bd8dd9624154a690f8e84dc52d6f633ba7cd545c4d3c9b4e0f6a2f6fa71f4` | `f9bdfcba1505cc664da89bd5df105be977f92897b086075d8f5a1f269b558617` |
| 4095 | 1 | 96 | `6efc183b62499b5310040ca725bb0a81a7c89cb3f163e92ea982da58aa7fea47` | `a01d7cd85bd5658ded393a72b4c29d08ff56c11051e909eb9c6b9cb7558d4c10` |
| 4096 | 1 | 96 | `d0c362f7235cbf7df3b8aabcefa9be7485c1c3c82983d42a519345929fb2fc1f` | `522ea88ecf2d1e1aac04999a7aedd94737f9fb7103845514a9e40e9debb3aaaa` |
| 4097 | 2 | 128 | `3000e690809e62e93e015f60ad2710797d6b3524c780b3bbb941154616c8a2e2` | `87f802b424302b94c4868dc06198717fdf4ab560e0222e4aad97a17cecbd5acd` |
| 12288 | 3 | 224 | `f086206b0b63bd77b988419f18edc36d195912da59c8168683cd2d02698d202a` | `5d48cc4c90539edbc02964d82e6afc66c488c64aa9e61c502d8cee2b7d626a4d` |
| 20487 | 6 | 416 | `02f8de9766f8783781e7e688a750cec3b5691614a8d8fc1ed005238b764095c9` | `12b0d11acc8d51874e79b02b88bde5245539cd838e4838dda0bfbe8d2a35a5c8` |
| 36864 | 9 | 672 | `2de1db0507feb1f2307d0dc411de1134b0ac4865637599a8f4e1bd6921840a6c` | `6e0289148cd873e7e767f59b3696b6f886731952599051b0e08fac2a8b2796dc` |
| 4096003 | 1001 | 64192 | `25b1cc95e2318ea600527d41f7586c06cebe37e88567b3b75efdb64eb41925cd` | `2889acac4c8013e2e03dbe27ea48675b9da9b61e904ffcceb39271bbe9a7f587` |

The 3-block tree file in full (224 bytes, hex, 32 bytes per line):

    4233540200000000000000000000000000000000000000000000000000000000
    f086206b0b63bd77b988419f18edc36d195912da59c8168683cd2d02698d202a
    b3b4f71ea4c00a22a4c9742446386530edb63c9f69438d4b0e94c96597bca83a
    39d029994cb50ec1d94e6248b5e1d8d8e737dd1ae21687f8b715bdb19638db91
    21037dd36783e18b6b63720b39f87e8cc2c470f2501a089528599f5d25b69425
    53f1be5e8b614d0dbd88806f45e90ba722d04d2bb42972b1394d2bb70129a18a
    39d029994cb50ec1d94e6248b5e1d8d8e737dd1ae21687f8b715bdb19638db91

Line 1 is the magic and reserved bytes, line 2 the root, lines 3-4 the top level
(the merge of leaves 0 and 1, then leaf 2 copied up), lines 5-7 the three leaves.
Content blocks 0 and 1 are identical bytes here (the pattern repeats every 256),
yet leaves 0 and 1 differ: that is the offset hashing.
