#!/usr/bin/env bash
# Client smoke under Wine: the WinForms client must start in the prefix
# and stay alive (no startup crash) for the observation window, then be
# closed cleanly by killing the Wine session. A GUI has no exit code to
# assert on while it correctly waits for input, so aliveness + the
# WineCheck harness (import/config on the same runtime) are the pair
# of proofs: this script = start, WineCheck = import/config generation.
# Usage: client-smoke.sh <winxp|winvista> <path-to-Sora.Ancient.exe> [seconds]
set -uo pipefail
ROOT="${ANCIENT_WINE_ROOT:-$HOME/.sora-ancient-wine}"
PREFIX="${1:?prefix name required}"; EXE="${2:?client exe path required}"; SECS="${3:-20}"
[ -f "$EXE" ] || { echo "CLIENT SMOKE FAIL: exe not found: $EXE" >&2; exit 1; }
export WINEPREFIX="$ROOT/$PREFIX" WINEARCH=win32 WINEDEBUG=-all
wine "$EXE" >/tmp/sora-ancient-client-$$.log 2>&1 &
WPID=$!
alive=0
for i in $(seq 1 "$SECS"); do
  sleep 1
  if pgrep -f "Sora.Ancient.exe" >/dev/null 2>&1; then alive=1; fi
  if ! kill -0 $WPID 2>/dev/null && [ $alive -eq 0 ]; then break; fi
done
if [ $alive -eq 1 ]; then echo "CLIENT SMOKE PASS prefix=$PREFIX exe=$EXE alive_after=${SECS}s"; else echo "CLIENT SMOKE FAIL prefix=$PREFIX (never alive; log follows)"; cat /tmp/sora-ancient-client-$$.log; fi
wineserver -k >/dev/null 2>&1 || true
sleep 2; pkill -f "Sora.Ancient.exe$" >/dev/null 2>&1 || true
rm -f /tmp/sora-ancient-client-$$.log
[ $alive -eq 1 ]
