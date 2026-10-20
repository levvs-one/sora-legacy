#!/usr/bin/env bash
# Builds tpws and nfqws of the zapret copy in third_party/zapret (bol-van,
# MIT, vendored unchanged) and lays them out next to the engines, with the
# fake handshakes nfqws sends. The build runs in a scratch copy, so the vendored
# tree is never modified. Needs a C compiler, zlib and, for nfqws,
# libnetfilter_queue, libnfnetlink and libmnl headers.
#
#   packaging/zapret/build.sh <engines directory>
set -euo pipefail

dest=${1:?engines directory}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp -r "$root/third_party/zapret" "$work/zapret"
make -C "$work/zapret/tpws" --no-print-directory
make -C "$work/zapret/nfq" --no-print-directory

mkdir -p "$dest/zapret/fake"
install -m 0755 "$work/zapret/tpws/tpws" "$dest/tpws"
install -m 0755 "$work/zapret/nfq/nfqws" "$dest/nfqws"
install -m 0644 "$work/zapret/files/fake/"*.bin "$dest/zapret/fake/"
# No LICENSE copy here: nfpm ships third_party/zapret/docs/LICENSE.txt
# directly to /usr/share/licenses/sora-core/ (packaging/linux/nfpm.yaml),
# and no other consumer reads $dest/zapret/LICENSE.txt.
# Record digests of the helpers next to the engines, in the same sha256sum
# format that packaging/engines/fetch.sh uses for SHA256SUMS. This runs
# after fetch.sh in the release pipeline, so it appends. The core's
# verifyTpws checks a listed tpws digest strictly (a mismatch disqualifies
# the binary); before this, SHA256SUMS never listed tpws, so the shipped
# tpws ran with no digest check at all. nfqws's digest is recorded for
# parity with the manifest format even though this core is tpws-only.
{
  sha256sum "$dest/tpws" | sed "s|$dest/tpws|tpws|"
  sha256sum "$dest/nfqws" | sed "s|$dest/nfqws|nfqws|"
} >>"$dest/SHA256SUMS"
echo "zapret: tpws and nfqws built"
