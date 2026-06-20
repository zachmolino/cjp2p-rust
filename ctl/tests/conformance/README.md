# git-bug conformance

cjp2p reproduces git-bug's on-disk objects **byte-for-byte** so that ids match
and a vanilla `git-bug` can read (and verify) what we write. This directory
pins the reference implementation and documents the serialization facts that
`src/gitbug/gobytes.rs` encodes.

## Pinned reference

- **git-bug `v0.10.1`** (bug `formatVersion=4`, identity `version=2`).
- Build from a clone (`git clone … && git checkout v0.10.1 && go build .`).
  `go install github.com/git-bug/git-bug@v0.10.1` **fails** — git-bug's
  `go.mod` uses `replace` directives, which `go install` rejects.

## On-disk model (observed)

Each entity (`refs/bugs/<id>`, `refs/identities/<id>`) is a chain of git
commits, one per operation pack. Each commit's tree carries:

- `ops` — a blob: the JSON operation pack `{"author":{"id":…},"ops":[…]}`.
- `edit-clock-N` / `create-clock-N` — **empty** blobs; the lamport value is the
  number in the *filename*.
- `version-4` — an **empty** blob; the format version is in the *filename*.

Commit `author`/`committer` are empty (` <> `); authorship lives in the pack.

## Serialization rules (Go `encoding/json`, byte-exact)

1. **Compact** — no whitespace.
2. **Field order = Go struct declaration order**, NOT sorted (this is why it
   differs from JCS / RFC 8785, which `jcs.rs` uses for cjp2p's *own* ids).
3. **HTML-escape** `<`→`<`, `>`→`>`, `&`→`&` (plus U+2028/U+2029).
   Standard escapes `\"`, `\\`, control chars otherwise.
4. **nil slice → `null`** (`"files":null`, `"removed":null`); non-empty →
   `[…]`. Empty **map** → `{}` (`"times":{}`).
5. `nonce` → standard base64; `author` → `{"id":<64-hex>}`; ints bare.

## Id derivation (verified)

- operation id = `hex(sha256(gobytes(single op)))`.
- a bug's id = its first (`Create`) operation's id.
- identity id = `hex(sha256(gobytes(identity version)))`.

## Write conformance (cjp2p → git-bug)

`tests/conformance_write.rs` writes a bug with cjp2p's native layer (`store.rs`
+ `gobytes.rs`) and asserts a real `git-bug` reads it back with matching id,
title, and status. It auto-skips when no git-bug binary is found (PATH /
`~/go/bin/git-bug` / `GIT_BUG=…`).

**git-bug cache caveat:** git-bug keeps a cache under `.git/git-bug/` keyed by
ref hashes and does **not** auto-notice a `refs/bugs/*` added out-of-band. After
writing bugs into a repo a git-bug user already touched, invalidate it
(`rm -rf .git/git-bug`); git-bug rebuilds on the next command. The objects are
valid either way — this is only about git-bug's read cache.

## Regenerate a sample

```sh
./gen_corpus.sh [git-bug-binary] [out-dir]
```

Nonces/timestamps are random per run, so output differs each time — this is for
fresh capture and live round-trip checks. The committed golden vectors are
inline in `gobytes.rs` tests.
