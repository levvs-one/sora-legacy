#!/usr/bin/env bash
# Downloads the engine builds of engines.lock for one architecture, refuses any
# file whose SHA-256 differs from the lock, and lays them out as the core looks
# for them: sing-box, xray, mihomo, geoip.dat and geosite.dat in one directory.
# The geo databases come from the Xray archive, which is pinned like the rest.
#
#   packaging/engines/fetch.sh amd64|arm64 <destination>
#
# tar uses --no-same-owner: chown can be forbidden in rootless containers
# and restricted sandboxes, and the extracted ownership is never used —
# every file is laid out afterwards through install -m.
set -euo pipefail

arch=${1:?architecture: amd64 or arm64}
dest=${2:?destination directory}
lock="$(dirname "$0")/engines.lock"
sigmanifest="$(dirname "$0")/engines.sig"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$dest"

# signature_method prints the engines.sig method for an engine, defaulting to
# "none" with a warning when the manifest has no entry.
signature_method() {
	awk -v e="$1" '$1 == e {print $2; found=1} END {if (!found) exit 1}' "$sigmanifest" 2>/dev/null || {
		echo "engines.sig: no entry for $1; treating as unsigned" >&2
		echo none
	}
}

# verify_upstream_signature enforces the engines.sig declaration for one
# downloaded asset. It fails closed: a declared signature that cannot be
# checked aborts the fetch.
verify_upstream_signature() {
	engine=$1 digest=$2 url=$3
	method=$(signature_method "$engine")
	case "$method" in
	none)
		echo "$engine: upstream publishes no signatures; lock digest is the only check (see engines.sig)" >&2
		;;
	dgst-crosscheck)
		dgst_file="$work/$(basename "$url").dgst"
		curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 600 --proto '=https' --output "$dgst_file" "$url.dgst" \
			|| { echo "engines.sig: could not download $url.dgst" >&2; exit 1; }
		published=$(awk '/^SHA2-256=/ {print $2}' "$dgst_file" | tr 'A-Z' 'a-z')
		if [ -z "$published" ]; then
			echo "engines.sig: no SHA2-256 in $url.dgst" >&2
			exit 1
		fi
		if [ "$published" != "$(printf '%s' "$digest" | tr 'A-Z' 'a-z')" ]; then
			echo "engines.sig: lock digest for $engine does not match the upstream .dgst" >&2
			exit 1
		fi
		echo "$engine: lock digest matches upstream .dgst"
		;;
	cosign)
		detail=$(awk -v e="$engine" '$1 == e {print $3}' "$sigmanifest")
		command -v cosign >/dev/null 2>&1 || { echo "engines.sig: cosign is required but not installed" >&2; exit 1; }
		[ -n "$detail" ] || { echo "engines.sig: no identity declared for $engine" >&2; exit 1; }
		asset="$work/$(basename "$url")"
		sig_file="$asset.sig"
		curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 600 --proto '=https' --output "$sig_file" "$url.sig" \
			|| { echo "engines.sig: could not download $url.sig" >&2; exit 1; }
		case "$detail" in
		keyless:*)
			identity=${detail#keyless:}
			cosign verify-blob --certificate-identity "$identity" \
				--certificate-oidc-issuer https://token.actions.githubusercontent.com \
				--signature "$sig_file" "$asset" >/dev/null \
				|| { echo "engines.sig: cosign keyless verification failed for $engine" >&2; exit 1; }
			;;
		pubkey:*)
			cosign verify-blob --key "${detail#pubkey:}" --signature "$sig_file" "$asset" >/dev/null \
				|| { echo "engines.sig: cosign verification failed for $engine" >&2; exit 1; }
			;;
		*)
			echo "engines.sig: bad cosign detail for $engine (want keyless:<id> or pubkey:<path>)" >&2
			exit 1
			;;
		esac
		echo "$engine: cosign signature verified ($detail)"
		;;
	*)
		echo "engines.sig: unknown method $method for $engine" >&2
		exit 1
		;;
	esac
}

found=0
while read -r engine line_arch digest url; do
	[[ -z "$engine" || "$engine" == \#* || "$line_arch" != "$arch" ]] && continue
	found=$((found + 1))
	file="$work/$(basename "$url")"
	curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 600 --proto '=https' --output "$file" "$url"
	echo "$digest  $file" | sha256sum --check --quiet --strict
	# Enforce the upstream-signature declaration from engines.sig.
	verify_upstream_signature "$engine" "$digest" "$url"
	case "$engine" in
	sing-box)
		tar --no-same-owner --extract --gzip --file "$file" --directory "$work" --wildcards '*/sing-box'
		install -m 0755 "$work"/sing-box-*/sing-box "$dest/sing-box"
		;;
	xray)
		unzip -o -q "$file" xray geoip.dat geosite.dat -d "$work/xray"
		install -m 0755 "$work/xray/xray" "$dest/xray"
		install -m 0644 "$work/xray/geoip.dat" "$work/xray/geosite.dat" "$dest/"
		;;
	mihomo)
		gunzip --stdout "$file" >"$work/mihomo"
		install -m 0755 "$work/mihomo" "$dest/mihomo"
		;;
	*)
		echo "engines.lock: unknown engine $engine" >&2
		exit 1
		;;
	esac
	echo "$engine $arch: verified"
done <"$lock"

if [[ "$found" -ne 3 ]]; then
	echo "engines.lock has $found engines for $arch, expected 3" >&2
	exit 1
fi

# Record the digests of the laid-out binaries. sora-core verifies enginesDir
# candidates against this manifest at discovery time (see supervise.LoadDigests);
# it is the binary-level counterpart of the archive digests in engines.lock.
(cd "$dest" && sha256sum sing-box xray mihomo geoip.dat geosite.dat >SHA256SUMS)
echo "wrote $dest/SHA256SUMS"
