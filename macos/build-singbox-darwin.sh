#!/bin/sh
# Reproducible self-build of a darwin sing-box for the macOS tiers in
# TIERS.md, for the places upstream does not ship a usable binary
# (see engines-darwin.lock: the regular 1.14.3 darwin builds declare
# min macOS 26.0, and the legacy-macos-10.13 asset is amd64-only, so
# on Apple Silicon below macOS 26 upstream has no sing-box at all).
#
#   macos/build-singbox-darwin.sh 1.13.21 arm64 <dest>   # tier macOS 11
#   macos/build-singbox-darwin.sh 1.13.21 amd64 <dest>   # tier macOS 11
#   macos/build-singbox-darwin.sh 1.11.15 amd64 <dest>   # tier macOS 10.15 (Intel)
#   macos/build-singbox-darwin.sh 1.11.15 arm64 <dest>   # builds, but its floor is 11.0 (see below)
#
# Why these versions and toolchains (full protocols: TIERS.md §3):
#   - The service pin 1.14.3 cannot be built for a floor below 12:
#     its go.mod requires Go 1.25.5, and Go >= 1.25 requires
#     macOS 12. Upstream's own legacy asset is produced on a Mac
#     with a patched Go 1.26 toolchain and the Apple external
#     linker (.github/setup_go_for_macos1013.sh in the 1.14.3
#     tree) — not reproducible from this Linux cross-build
#     environment, and published for amd64 only.
#   - 1.13.21 is the newest upstream release the core catalog
#     honestly accepts (MinVersion 1.12.0, core/engine/catalog.go)
#     that a macOS-11 toolchain can build: Go 1.24.13 (the last Go
#     line that runs on macOS 11). Two measured caveats:
#       * With the release tag set the build fails in the pinned
#         Tailscale fork: its vendored json experiment calls
#         reflect.TypeAssert, a Go 1.25 API. The tag set below is
#         therefore release/DEFAULT_BUILD_TAGS_OTHERS minus
#         with_tailscale. The core catalog makes no Tailscale
#         claim for sing-box and no plan in this tree names one,
#         so the omission is invisible to engine selection; it is
#         a real difference from the upstream binary and is stated
#         wherever this build is pinned.
#       * Upstream's own 1.13.21 binaries were built with Go
#         1.25.12 (their `version` output) — the go.mod minimum
#         (go 1.24.7) is not the toolchain upstream used.
#   - 1.11.15 is the Catalina-tier pin (newest branch whose config
#     language the tier's DNS translation targets). It does NOT
#     build with the Go 1.20 line despite `go 1.20` in its go.mod:
#     its pinned QUIC fork refuses ECH builds below Go 1.21
#     (internal/qtls_ech/go_oldversion.go, `//go:build !go1.21` —
#     measured). The build uses Go 1.22.12, the last patch of the
#     last Go line whose macOS floor is 10.15.
#   - Floors are per-architecture facts, measured from the built
#     Mach-O: the 1.13.21 builds declare 11.0 on both arches; the
#     1.11.15 amd64 build declares 10.13 in its load command but
#     the Go 1.22 runtime requires 10.15, so its honest floor is
#     10.15; the 1.11.15 arm64 build declares 11.0 — no arm64 Mac
#     ever ran 10.15, so there is no arm64 Catalina engine and
#     this script does not pretend otherwise.
#
# Inputs are pinned and verified before anything is built:
#   - Go toolchains: official go.dev linux-amd64 archives, SHA-256
#     from the go.dev download JSON (mode=json&include=all).
#   - sing-box sources: GitHub release-tag archives; SHA-256
#     measured here and cross-checked against the main sora tree's
#     apple/Legacy/ENGINES.md §7, which measured the same archives.
# Toolchains and sources are cached under ${WS3_HOME:-$HOME/workspace/.legfull-ws3}
# (downloads are resumable); set WS3_HOME to relocate the cache.
# The build is deterministic (-trimpath, -buildid=, fixed version
# stamp): two runs produce byte-identical Mach-O binaries, which
# is what the digests in engines-darwin.lock record.
set -eu

version=${1:?sing-box version: 1.13.21 or 1.11.15}
arch=${2:?architecture: amd64 or arm64}
dest=${3:?destination file}

case "$version" in
    1.13.21)
        go_ver=1.24.13
        go_sha=1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730
        src_sha=c994018d7c2a8fc9fcf6080e4b9cc4f2f915e755342238b77e46fc0806fe96db
        # release/DEFAULT_BUILD_TAGS_OTHERS of the 1.13.21 tree,
        # minus with_tailscale (see header).
        tags="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"
        tags_note="release/DEFAULT_BUILD_TAGS_OTHERS minus with_tailscale"
        ;;
    1.11.15)
        go_ver=1.22.12
        go_sha=4fa4f869b0f7fc6bb1eb2660e74657fbf04cdd290b5aef905585c86051b34d43
        src_sha=97d58dd873d7cf9b5e4b4aca5516568f3b2e6f5c3dbc93241c82fff5e4a609fd
        # Makefile of the 1.11.15 tree: TAGS_GO120 + TAGS_GO121
        # (TAGS_GO118 is empty there); matches the tag set the
        # upstream linux-amd64 binary reports in `sing-box version`.
        tags="with_gvisor,with_dhcp,with_wireguard,with_reality_server,with_clash_api,with_quic,with_utls,with_acme,with_ech"
        tags_note="Makefile TAGS_GO120+TAGS_GO121 of the 1.11.15 tree"
        ;;
    *)
        echo "build-singbox-darwin: unsupported version $version (see TIERS.md)" >&2
        exit 2
        ;;
esac
case "$arch" in amd64|arm64) ;; *) echo "build-singbox-darwin: bad arch $arch" >&2; exit 2 ;; esac

ws=${WS3_HOME:-$HOME/workspace/.legfull-ws3}
mkdir -p "$ws/dl" "$ws/tc" "$ws/src"

fetch() { # url file sha256
    if [ ! -f "$2" ] || [ "$(shasum -a 256 "$2" | awk '{print $1}')" != "$3" ]; then
        curl --fail --location --silent --show-error --retry 3 -C - \
            --connect-timeout 20 --max-time 1200 --proto '=https' \
            --output "$2" "$1"
    fi
    actual=$(shasum -a 256 "$2" | awk '{print $1}')
    if [ "$actual" != "$3" ]; then
        echo "build-singbox-darwin: digest mismatch for $2: got $actual, want $3" >&2
        exit 1
    fi
}

# Toolchain (official go.dev archive).
tc_dir="$ws/tc/go$go_ver"
if [ ! -x "$tc_dir/bin/go" ]; then
    fetch "https://go.dev/dl/go$go_ver.linux-amd64.tar.gz" \
        "$ws/dl/go$go_ver.linux-amd64.tar.gz" "$go_sha"
    mkdir -p "$tc_dir"
    tar -xzf "$ws/dl/go$go_ver.linux-amd64.tar.gz" -C "$tc_dir" --strip-components=1
fi

# Sources (GitHub tag archive of the pinned release).
src_dir="$ws/src/sing-box-$version"
if [ ! -d "$src_dir" ]; then
    fetch "https://github.com/SagerNet/sing-box/archive/refs/tags/v$version.tar.gz" \
        "$ws/dl/sing-box-$version.tar.gz" "$src_sha"
    tar -xzf "$ws/dl/sing-box-$version.tar.gz" -C "$ws/src"
fi

echo "build-singbox-darwin: sing-box $version darwin/$arch, $($tc_dir/bin/go version), tags: $tags_note" >&2

# Heavy builds serialise on the shared lock when it exists.
exec 9>/tmp/legfull-build.lock
flock -w 2400 9 || { echo "build-singbox-darwin: build lock timeout" >&2; exit 1; }

cd "$src_dir"
CGO_ENABLED=0 GOOS=darwin GOARCH=$arch GOTOOLCHAIN=local \
    TMPDIR=${TMPDIR:-$HOME/workspace/.build-tmp} \
    "$tc_dir/bin/go" build -trimpath \
    -tags "$tags" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=$version -s -w -buildid=" \
    -o "$dest" ./cmd/sing-box

echo "build-singbox-darwin: built $dest"
shasum -a 256 "$dest"
