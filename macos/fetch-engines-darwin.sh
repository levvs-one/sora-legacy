#!/bin/sh
# Downloads the darwin engine builds of engines-darwin.lock for one
# architecture, refuses any file whose SHA-256 differs from the lock,
# and lays the binaries out as the core's engine discovery expects
# them (sing-box, xray, mihomo, geoip.dat, geosite.dat plus a
# SHA256SUMS manifest of the BINARIES — the manifest the core verifies
# before running an engine; install.sh refuses an engines directory
# without it).
#
#   macos/fetch-engines-darwin.sh amd64|arm64 <destination>
#
# Modeled on packaging/engines/fetch.sh (Linux); the asset shapes
# differ (tarballs / zips / bare gzip), so this is a sibling, not a
# copy. Xray digests are additionally cross-checked against the
# release's official .dgst, as the Linux fetcher does.
set -eu

arch=${1:?architecture: amd64 or arm64}
dest=${2:?destination directory}
lock="$(dirname "$0")/engines-darwin.lock"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$dest"

asset_for() { # engine -> "sha256 url" from the lock
    awk -v e="$1" -v a="$arch" '$1 == e && $2 == a {print $3, $4}' "$lock"
}

fetch() { # url file
    curl --fail --location --silent --show-error --retry 3 \
        --connect-timeout 20 --max-time 600 --proto '=https' \
        --output "$2" "$1"
}

check() { # file sha256 label
    actual=$(shasum -a 256 "$1" | awk '{print $1}')
    if [ "$actual" != "$2" ]; then
        echo "fetch-engines-darwin: $3 digest mismatch: got $actual, lock says $2" >&2
        exit 1
    fi
}

for engine in sing-box xray mihomo; do
    set -- $(asset_for "$engine") # shellcheck disable=SC2046
    sha=$1 url=$2 file="$work/$(basename "$url")"
    fetch "$url" "$file"
    check "$file" "$sha" "$engine"
    if [ "$engine" = "xray" ]; then
        fetch "$url.dgst" "$file.dgst"
        dgst=$(awk '/SHA2-256=/{print $2}' "$file.dgst")
        if [ "$dgst" != "$sha" ]; then
            echo "fetch-engines-darwin: xray .dgst disagrees with the lock" >&2
            exit 1
        fi
    fi
    case "$file" in
        *.tar.gz) tar --no-same-owner -xzf "$file" -C "$work" ;;
        *.zip)    unzip -o -q "$file" -d "$work/xray" ;;
        *.gz)     gzip -dc "$file" > "$work/mihomo" ;;
    esac
done

# Lay out binaries: sing-box from its tarball directory, xray (plus
# the geo databases the core ships from the Xray archive, as on
# Linux), mihomo from the bare gzip.
find "$work" -name sing-box -type f -exec install -m755 {} "$dest/sing-box" \;
install -m755 "$work/xray/xray" "$dest/xray"
install -m644 "$work/xray/geoip.dat" "$dest/geoip.dat"
install -m644 "$work/xray/geosite.dat" "$dest/geosite.dat"
install -m755 "$work/mihomo" "$dest/mihomo"

# The core verifies engine digests against SHA256SUMS in the engines
# directory and fails closed without it: write it from the binaries as
# installed, not from the archives.
(cd "$dest" && shasum -a 256 sing-box xray mihomo geoip.dat geosite.dat > SHA256SUMS)
echo "fetch-engines-darwin: engines for $arch in $dest (digests verified against engines-darwin.lock)"
