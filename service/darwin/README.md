# service/darwin

Integration of the `sora-core` daemon with macOS (launchd). The daemon
code lives in `core/cmd/sora-core`; the client tree that drives it is
[`macos/`](../../macos/README.md). System files only here, following
the layout of `service/linux` and `service/windows`.

| File | Installed to | What it does |
| --- | --- | --- |
| `io.github.levvs-one.sora-legacy.core.plist` | `/Library/LaunchDaemons/` | root LaunchDaemon running the core |
| `install.sh` | — | group, binaries, data dir, bootstrap |
| `uninstall.sh` | — | bootout, remove binaries; `--purge` also data |

## How it is put together

- **The daemon runs as root.** On macOS, creating a utun interface and
  changing system routes (TUN mode) requires privilege, and there is
  no launchd middle ground: a LaunchAgent in the user session cannot
  do either. The engines are the daemon's children and inherit the
  privilege. What bounds it: the control plane is a unix socket only —
  no network port — at `/var/run/sora/core.sock`.
- **Socket access.** The socket is mode 0666 and the boundary is
  kernel-verified peer identity: `core/ipc` on darwin reads
  `LOCAL_PEERCRED` (`ipc_peer_darwin.go`), and the default allow-list
  admits the daemon's own uid (root) and members of the group `sora`,
  which `install.sh` creates and adds the console user to. Every
  admitted peer receives the control token from Handshake; the token
  distinguishes fresh clients, it is not a second boundary (same model
  as Linux, minus polkit, which macOS does not have).
- **Data.** Token, encrypted secret store and engine state live in
  `/Library/SoraLegacy/core`, root-owned, mode 0700 — the core's data
  directory convention, named explicitly in the plist because a root
  daemon must not derive it from an inherited environment.
- **Binaries and engines.** `/usr/local/lib/sora-legacy/` holds
  `sora-core`, the `sora-ctl` helper the client drives, and
  `engines/` — the engine builds pinned for darwin in
  [`macos/engines-darwin.lock`](../../macos/engines-darwin.lock)
  (sing-box 1.14.3 / Xray 26.3.27 / mihomo 1.19.32, the service pins of
  `packaging/engines/engines.lock`, not the Windows payload pins),
  with the `SHA256SUMS` manifest the core verifies before running any
  engine.
- **Logs** go to `/Library/Logs/SoraLegacy/` via the plist's
  StandardOut/Err paths.
- **Shutdown.** `ExitTimeOut` is 20 s: on stop the core restores the
  session's routes; `uninstall.sh` asks for a disconnect first so the
  restore is the core's own, not a kill's side effect.

## Honest limits on this platform

- The kill switch is **not enforced** on darwin: `core/guard` returns
  `NoopFirewall` there. The core records the request; the client shows
  it as requested-but-not-enforced. A pf-based implementation is
  future work, not a hidden gap.
- Host routing into an external TUN adapter (`core/engine/tunroute`)
  is Linux-only. macOS TUN means the engine's own utun with
  `auto_route`, created by the engine running as this root daemon —
  verify-on-mac, see the checklist in `macos/README.md`.
- No NetworkExtension, no system extension, no notarized installer in
  this tree: the client is a plain AppKit app plus this daemon (see
  the capability matrix in `macos/README.md`).

## Manual install

Usually installed by the scripts above; the equivalent by hand:

```sh
sudo dseditgroup -o create sora
sudo dseditgroup -o edit -a "$USER" -t user sora
sudo install -d -m0700 /Library/SoraLegacy/core
sudo install -m755 sora-core sora-ctl /usr/local/lib/sora-legacy/
sudo install -m644 service/darwin/io.github.levvs-one.sora-legacy.core.plist \
  /Library/LaunchDaemons/
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/io.github.levvs-one.sora-legacy.core.plist
/usr/local/lib/sora-legacy/sora-ctl status
```
