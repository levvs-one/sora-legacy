#!/usr/bin/env bash
# Install the era .NET runtimes into the prefixes with winetricks.
#   winxp    -> dotnet40   (XP ceiling is .NET Framework 4.0.3; winetricks
#                           verb dotnet40 installs the 4.0 runtime line)
#   winvista -> dotnet46   (winetricks verb for the 4.6 line; Vista
#                           ceiling — 4.6.1+ dropped Vista)
# Idempotent: winetricks verbs no-op when already installed.
set -euo pipefail
ROOT="${ANCIENT_WINE_ROOT:-$HOME/.sora-ancient-wine}"
command -v winetricks >/dev/null || { echo "winetricks not found — install it first (Wine phase prerequisite)." >&2; exit 1; }
WINEPREFIX="$ROOT/winxp"    WINEARCH=win32 winetricks -q dotnet40
WINEPREFIX="$ROOT/winvista" WINEARCH=win32 winetricks -q dotnet462 || \
  WINEPREFIX="$ROOT/winvista" WINEARCH=win32 winetricks -q dotnet46
echo "Era .NET runtimes installed (winxp: 4.0 line, winvista: 4.6 line)."
echo "NOTE: if the vista prefix only accepts dotnet462, treat that as a"
echo "winetricks modelling gap, not an OS fact: real Vista stops at 4.6."
