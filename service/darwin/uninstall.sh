#!/bin/sh
# Remove the sora-legacy core service from macOS.
#
#   sudo sh service/darwin/uninstall.sh [--purge]
#
# Stops and unregisters the daemon, removes the plist and the binaries.
# Without --purge the data directory (/Library/SoraLegacy/core: token,
# encrypted secret store, engine state) and logs are kept, matching the
# Linux packages' postremove behaviour; --purge deletes them too. The
# "sora" group is left in place: removing a group other tools may have
# adopted is not this script's call (delete it with
# `sudo dseditgroup -o delete sora` if nothing else uses it).
# If a session was connected, disconnect first
# (/usr/local/lib/sora-legacy/sora-ctl disconnect) so routes and the
# system proxy are restored by the core's own shutdown path.
set -eu

LABEL=io.github.levvs-one.sora-legacy.core
LIBDIR=/usr/local/lib/sora-legacy
DATADIR=/Library/SoraLegacy/core
LOGDIR=/Library/Logs/SoraLegacy
PLIST=/Library/LaunchDaemons/$LABEL.plist

if [ "$(id -u)" != "0" ]; then
    echo "uninstall.sh: run with sudo" >&2
    exit 1
fi

launchctl bootout system "$PLIST" 2>/dev/null || \
    launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
rm -rf "$LIBDIR"
echo "uninstall.sh: service and binaries removed"
if [ "${1:-}" = "--purge" ]; then
    rm -rf "$DATADIR" "$LOGDIR" /Library/SoraLegacy
    echo "uninstall.sh: data and logs purged"
else
    echo "uninstall.sh: data kept at $DATADIR (rerun with --purge to delete)"
fi
