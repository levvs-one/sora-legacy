#!/usr/bin/env bash
# Engine smoke under Wine: the pinned windows-32 engine must answer
# -version and accept an era config with -test inside EACH prefix.
# Run after ../stage-engines.sh and setup-prefixes.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="${ANCIENT_WINE_ROOT:-$HOME/.sora-ancient-wine}"
ENGINE="engines/windows-32/v2ray-v3.36-windows-32/v2ray.exe"
[ -f "$ENGINE" ] || { echo "Engine not staged. Run ../stage-engines.sh first." >&2; exit 1; }
cat > /tmp/sora-ancient-smoke.json << 'JSON'
{"log":{"loglevel":"error"},"inbound":{"port":10808,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":true}},"outbound":{"protocol":"freedom","settings":{}}}
JSON
for name in winxp winvista; do
  prefix="$ROOT/$name"
  echo "== prefix $name"
  WINEPREFIX="$prefix" WINEARCH=win32 wine "$ENGINE" -version
  cp /tmp/sora-ancient-smoke.json "$prefix/drive_c/smoke.json"
  WINEPREFIX="$prefix" WINEARCH=win32 wine "$ENGINE" -test -config 'C:\smoke.json'
done
echo "Engine smoke OK in both prefixes."
