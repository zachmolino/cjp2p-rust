#!/usr/bin/env bash
# Generate a git-bug conformance corpus: drive a real `git-bug` binary, then
# dump the raw git objects it produced (the `ops` blobs and identity `version`)
# plus the ids it computed. Used to (re)capture/refresh the golden vectors that
# `src/gitbug/gobytes.rs` asserts against.
#
# NOTE: git-bug stamps each operation with a RANDOM nonce and a wall-clock
# timestamp, so every run yields different bytes/ids. This script is for
# capturing a fresh sample and for live round-trip checks against the pinned
# binary — the committed golden vectors live inline in gobytes.rs tests.
#
# Pinned git-bug: v0.10.1 (build from a clone: `go build` inside the repo;
# `go install ...@vX` fails because git-bug's go.mod uses replace directives).
#
# Usage: gen_corpus.sh [git-bug-binary] [out-dir]
set -euo pipefail

GB="${1:-$HOME/go/bin/git-bug}"
OUT="${2:-$(mktemp -d)}"
command -v "$GB" >/dev/null 2>&1 || { echo "git-bug not found at: $GB" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
git init -q

"$GB" user new -n "Test User" -e "test@example.com" -a "" --non-interactive >/dev/null
BUG="$("$GB" bug new -t "Test bug title" -m "Initial description" --non-interactive \
        | grep -oE '^[0-9a-f]+' | head -1)"
"$GB" bug comment new "$BUG" -m "A follow-up comment" --non-interactive >/dev/null
"$GB" bug label new "$BUG" "review:in-progress" >/dev/null
"$GB" bug status close "$BUG" >/dev/null

mkdir -p "$OUT"
BUGREF="$(git for-each-ref --format='%(refname)' refs/bugs | head -1)"
IDREF="$(git for-each-ref --format='%(refname)' refs/identities | head -1)"

# Dump each operation pack (oldest -> newest), named by index.
i=0
while read -r c; do
  git cat-file -p "$c:ops" > "$OUT/ops-$i.json"
  i=$((i + 1))
done < <(git log --reverse --format='%H' "$BUGREF")

git cat-file -p "$IDREF:version" > "$OUT/identity-version.json"

# Record the ids git-bug derived, for assertion (id = sha256(gobytes)).
{
  echo "git-bug:        $("$GB" version | head -1)"
  echo "bug-id:         ${BUGREF##*/}"
  echo "identity-id:    ${IDREF##*/}"
} > "$OUT/ids.txt"

echo "corpus written to: $OUT"
ls -1 "$OUT"
