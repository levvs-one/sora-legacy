#!/bin/sh
# The core removes its nftables table when it stops; a core that was killed
# could not, so the table is removed here as well. Nothing else of the system
# was changed by the package.
case "${1:-remove}" in
upgrade | 1) exit 0 ;;
esac
nft delete table inet sora 2>/dev/null || true
# Purge removes the secret store, the control token, and engine state from
# /var/lib/sora: secrets must not survive uninstallation. A plain remove
# keeps them so reinstalling does not lose subscriptions. RPM has no purge
# step — there "$1" is the number of packages remaining, and 0 (final erase)
# is the equivalent point.
if [ "${1:-remove}" = purge ] || [ "${1:-remove}" = 0 ]; then
	rm -rf /var/lib/sora
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi
