#!/bin/sh
# Install the sora-legacy core service on macOS.
#
# Usage (from a checkout of this repository, as an administrator):
#   sudo sh service/darwin/install.sh [path-to-binaries-dir]
#
# The binaries directory must contain the darwin builds:
#   sora-core            (core/cmd/sora-core, GOOS=darwin)
#   sora-ctl             (macos/helper, GOOS=darwin)
#   engines/             (engine binaries per macos/engines-darwin.lock,
#                         plus their SHA256SUMS manifest — the core
#                         verifies digests and fails closed without it)
# When no directory is given, binaries are looked up next to this
# script's repository root under build/darwin/.
#
# What this does, and nothing else:
#   * validates the kit first (engines/ present, SHA256SUMS present,
#     every listed digest matching) — a kit that fails validation
#     changes nothing on the system;
#   * creates the group "sora" (the control socket's group boundary)
#     and adds the console user to it;
#   * installs binaries under /usr/local/lib/sora-legacy (root:wheel);
#   * creates the root-owned data dir /Library/SoraLegacy/core (0700)
#     and the log dir /Library/Logs/SoraLegacy;
#   * installs the LaunchDaemon plist and bootstraps it.
set -eu

LABEL=io.github.levvs-one.sora-legacy.core
LIBDIR=/usr/local/lib/sora-legacy
DATADIR=/Library/SoraLegacy/core
LOGDIR=/Library/Logs/SoraLegacy
PLIST=/Library/LaunchDaemons/$LABEL.plist

if [ "$(id -u)" != "0" ]; then
    echo "install.sh: run with sudo (the daemon needs root for TUN/routes)" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")")
SRC=${1:-"$SCRIPT_DIR/../../build/darwin"}
for f in "$SRC/sora-core" "$SRC/sora-ctl"; do
    if [ ! -f "$f" ]; then
        echo "install.sh: $f not found — build the darwin binaries first (macos/README.md)" >&2
        exit 1
    fi
done

# Validate the engine payload BEFORE anything on the system is
# changed (group, binaries, data dir): the core verifies engine
# digests against SHA256SUMS and fails closed, so an engines
# directory that is missing, has no manifest, or whose digests do
# not all match is an install error — and refusing here leaves no
# partial install behind, where refusing after the group and the
# binaries were already in place would.
if [ ! -d "$SRC/engines" ]; then
    echo "install.sh: $SRC/engines not found — the kit is incomplete (fetch the engines first: macos/fetch-engines-darwin.sh)" >&2
    exit 1
fi
if [ ! -f "$SRC/engines/SHA256SUMS" ]; then
    echo "install.sh: $SRC/engines has no SHA256SUMS manifest — the core would refuse these engines" >&2
    exit 1
fi
if ! (cd "$SRC/engines" && shasum -a 256 -c SHA256SUMS); then
    echo "install.sh: engine digests in $SRC/engines do not match SHA256SUMS — refusing to install unverified engines" >&2
    exit 1
fi

# The console user is who will drive the client; the socket admits the
# core's own uid (root) and members of this group (core/ipc defaultAllow,
# peer verified by the kernel via LOCAL_PEERCRED).
CONSOLE_USER=$(stat -f %Su /dev/console)
if ! dseditgroup -o read sora >/dev/null 2>&1; then
    dseditgroup -o create sora
    echo "install.sh: created group sora"
fi
if ! dseditgroup -o checkmember -m "$CONSOLE_USER" sora >/dev/null 2>&1; then
    dseditgroup -o edit -a "$CONSOLE_USER" -t user sora
    echo "install.sh: added $CONSOLE_USER to group sora (takes effect at next login for group checks)"
fi

install -d -o root -g wheel -m 0755 "$LIBDIR" "$LIBDIR/engines"
install -o root -g wheel -m 0755 "$SRC/sora-core" "$LIBDIR/sora-core"
install -o root -g wheel -m 0755 "$SRC/sora-ctl" "$LIBDIR/sora-ctl"
# Engine payload + digest manifest — presence and digests were
# validated above, before anything on the system was changed.
cp -R "$SRC/engines/." "$LIBDIR/engines/"
chmod 0755 "$LIBDIR/engines"/* 2>/dev/null || true
chmod 0644 "$LIBDIR/engines/SHA256SUMS"

install -d -o root -g wheel -m 0700 "$DATADIR"
install -d -o root -g wheel -m 0755 "$LOGDIR"
install -o root -g wheel -m 0644 "$SCRIPT_DIR/$LABEL.plist" "$PLIST"

# (Re)load: bootout is best-effort (absent on first install).
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL" || true
echo "install.sh: $LABEL bootstrapped; socket: /var/run/sora/core.sock"
echo "install.sh: check with: $LIBDIR/sora-ctl status"
