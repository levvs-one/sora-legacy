#!/usr/bin/env bash
# Wine phase (separate follow-up task): create the two era prefixes.
# Idempotent — an existing prefix is left untouched. 32-bit prefixes are
# mandatory: the era .NET installers and the windows-32 engine are x86,
# and WOW64 prefixes add variables this track does not need.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="${ANCIENT_WINE_ROOT:-$HOME/.sora-ancient-wine}"
for name in winxp winvista; do
  prefix="$ROOT/$name"
  if [ -d "$prefix/drive_c" ]; then
    echo "prefix exists, skipping: $prefix"
    continue
  fi
  echo "creating $prefix (WINEARCH=win32)"
  mkdir -p "$prefix"
  WINEARCH=win32 WINEPREFIX="$prefix" wineboot --init
  # Pin the reported Windows version per prefix.
  case "$name" in
    winxp)    WINEPREFIX="$prefix" winecfg -v winxp >/dev/null 2>&1 || true ;;
    winvista) WINEPREFIX="$prefix" winecfg -v winvista >/dev/null 2>&1 || true ;;
  esac
done
echo "Prefixes ready under $ROOT (winxp, winvista)."
