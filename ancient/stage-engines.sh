#!/usr/bin/env bash
# Stage the pinned era engines next to the client. Fail-closed: a digest
# mismatch aborts before anything is unpacked. Downloads are resumable
# (curl -C -) and are kept under ./downloads so a re-run is cheap.
set -euo pipefail
cd "$(dirname "$0")"
LOCK=engines.lock
OUT=engines
DL=downloads
mkdir -p "$OUT" "$DL"
while read -r engine asset sha url; do
  case "$engine" in ''|'#'*) continue;; esac
  file="$DL/$(basename "$url")"
  echo "== $engine $asset"
  curl -fL -C - --retry 3 -o "$file" "$url"
  echo "$sha  $file" | sha256sum -c - || { echo "DIGEST MISMATCH for $file — refusing to stage" >&2; exit 1; }
  dest="$OUT/$asset"
  rm -rf "$dest"; mkdir -p "$dest"
  unzip -o -q "$file" -d "$dest"
  echo "staged -> $dest"
done < "$LOCK"
echo "All engines staged and digest-verified."
