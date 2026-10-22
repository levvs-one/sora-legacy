#!/usr/bin/env bash
# Loopback stand under Wine: a local HTTP server on the host, the era
# engine running in the prefix with a freedom outbound, and curl through
# the engine's SOCKS inbound. Proves data plane, not just process start.
# The engine listens on 127.0.0.1 inside the Wine prefix, which shares
# the host loopback under Wine — that sharing is itself part of what the
# Wine phase verifies; if a future Wine isolates it, this script failing
# is the signal, not a bug in the script.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="${ANCIENT_WINE_ROOT:-$HOME/.sora-ancient-wine}"
ENGINE="$PWD/engines/windows-32/v2ray-v3.36-windows-32/v2ray.exe"
PREFIX="${1:-winxp}"
WORK="$(mktemp -d)"
trap 'kill ${HTTP_PID:-} ${WINE_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT
echo "sora-ancient-loopback-ok" > "$WORK/hello.txt"
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
HTTP_PID=$!
cat > "$WORK/config.json" << 'JSON'
{"log":{"loglevel":"error"},"inbound":{"port":10808,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":true}},"outbound":{"protocol":"freedom","settings":{}}}
JSON
cp "$WORK/config.json" "$ROOT/$PREFIX/drive_c/loopback.json"
WINEPREFIX="$ROOT/$PREFIX" WINEARCH=win32 wine "$ENGINE" -config 'C:\loopback.json' >/dev/null 2>&1 &
WINE_PID=$!
sleep 3
BODY="$(curl -s --max-time 10 --socks5-hostname 127.0.0.1:10808 http://127.0.0.1:18081/hello.txt)"
[ "$BODY" = "sora-ancient-loopback-ok" ] || { echo "Loopback FAILED in prefix $PREFIX (body: $BODY)" >&2; exit 1; }
echo "Loopback OK in prefix $PREFIX: HTTP 200 body through era SOCKS inbound."
