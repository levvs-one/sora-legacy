# Sora Legacy — macOS client

A native macOS client for the sora-legacy core: a root launchd
service running the existing Go daemon, a thin Go helper, and an
AppKit app. Nothing in the product logic is reimplemented — imports,
plan validation, engine selection and the control contract are the
daemon's own (`sora.core.v1`, contract 1.7).

**Honest status.** This tree was written and verified on Linux. The
Go parts are fully built and tested here (daemon and helper as real
darwin Mach-O binaries, helper integration tests against a real
daemon stack). The Swift core (App/Core) is type-checked and
unit-tested on the Linux Swift 6.0.3 toolchain; the AppKit layer is
parse-checked only — it has never been compiled by Xcode, and nothing
in this tree has run on a Mac. Everything that needs one is the
verify-on-mac checklist at the bottom.

## Architecture

```
┌─ user session ──────────────────────────────────────────────┐
│  SoraLegacy.app (AppKit, floor 10.13)                        │
│    status · servers · import · settings · capability matrix  │
│         │ runs, reads one JSON document per command          │
│  sora-ctl  (Go helper, macos/helper)                         │
│         │ JSON-RPC 2.0 / protojson payloads, NDJSON framing  │
└─────────┼────────────────────────────────────────────────────┘
          │ unix socket /var/run/sora/core.sock
          │ peer verified by kernel: LOCAL_PEERCRED (core/ipc)
┌─ root LaunchDaemon (service/darwin) ────────────────────────┐
│  sora-core  (core/cmd/sora-core, default legacycontrol mode) │
│    vault · sessions · engines (sing-box / Xray / mihomo)     │
│    TUN (engine utun, auto_route) or loopback local proxy      │
└──────────────────────────────────────────────────────────────┘
```

### Why the helper speaks JSON-RPC, not gRPC-Swift (choice (a), with the (b) transport)

Two options were evaluated against the code as it is:

- **(b) Direct unix-socket protocol.** Reading `core/ipc` and
  `core/control` shows there is no simpler message protocol above the
  socket: `core/ipc` is transport only (listen/dial + peer checks).
  Above it exactly two protocols exist — gRPC, and the daemon's
  **default** mode. So "direct socket" does not avoid a protocol; it
  means picking one of those two.
- **gRPC to the daemon** would require `-legacy-control=false` in the
  service (a daemon mode no other legacy client uses) **and** a Swift
  gRPC stack (grpc-swift + swift-protobuf: a heavy dependency chain,
  hostile to a 10.13 floor and to offline verification here).
- **The daemon's default wire protocol** is `core/legacycontrol`:
  JSON-RPC 2.0, one JSON object per line, method payloads are the
  protojson of the same `sora.core.v1` messages, results are protojson
  strings. It is what the shipping .NET client speaks
  (`legacy/Control/CoreConnection.cs`) and what `core/legacycontrol`'s
  Go tests drive with a jrpc2 client over `channel.Line`.

Chosen: **the helper is a Go control client over the default
JSON-RPC protocol** (`macos/helper/client.go`), plus `core/mobileapi`
for the two jobs that are better daemonless: the static engine
catalog (`engineinfo`) and offline import preview (`import --local`).
The Swift app therefore needs no protocol code at all — it runs the
helper and decodes its JSON (`App/Core/HelperClient.swift`). The
control token from Handshake lives only in the helper process's
memory; its state file holds the imported plan with credential
*references* only (the material is in the daemon's vault — a test in
`macos/helper` asserts the password never reaches the file).

### The service (service/darwin)

Root `LaunchDaemon` (`io.github.levvs-one.sora-legacy.core.plist`):
root because utun creation and route changes need privilege and a
user LaunchAgent can do neither. Data in `/Library/SoraLegacy/core`
(0700, root), binaries + engines in `/usr/local/lib/sora-legacy/`,
logs in `/Library/Logs/SoraLegacy/`. `install.sh` creates the group
`sora` (the socket's allow-list group, peer kernel-verified) and adds
the console user; `uninstall.sh` boots the daemon out and removes the
binaries, keeping data unless `--purge`. Full rationale:
[service/darwin/README.md](../service/darwin/README.md).

**darwin support added to the core for this client** (additive,
`core/ipc`): `ipc_peer_darwin.go` implements peer verification via
`LOCAL_PEERCRED`/`LOCAL_PEERPID` (the old `!linux` stub left darwin
unverified), and the socket address moved per-platform —
`/var/run/sora/core.sock` on darwin (macOS has no writable `/run`),
unchanged on Linux/Windows. Cross-checked: linux build+test,
darwin amd64/arm64 build+vet+test-compile, windows build.

## Capability matrix (also in code: App/Core/Capabilities.swift)

Floors are **measured** from the Mach-O load commands of the real
binaries, not guessed:

| Piece | Measured minimum macOS |
| --- | --- |
| AppKit client | 10.13 (design floor; AppKit APIs ≤ 10.13 in the common path) |
| `sora-core` daemon, `sora-ctl` helper | **12.0** (Go toolchain darwin floor, both arches) |
| Xray 26.3.27 | 12.0 / 12.0 |
| mihomo 1.19.32 | 10.13 (amd64) / 11.0 (arm64) |
| sing-box 1.14.3 | legacy-10.13 asset (amd64) / **26.0** regular (arm64) |
| sing-box 1.13.21, self-built (TIERS.md §3.2) | **11.0 / 11.0** |
| sing-box 1.11.15, self-built (TIERS.md §3.3) | **10.15** honest floor (amd64) / 11.0 (arm64) |

Modes:

| Mode | State | Notes |
| --- | --- | --- |
| TUN via the service | implemented, **verify-on-mac** | Engine utun + auto_route as root. Kill switch is **not enforced** on darwin (core/guard is NoopFirewall) — the UI says "requested, NOT enforced", never "protected". Host route helper (tunroute) is Linux-only; TUN here is the engine's own. |
| System proxy | implemented, **verify-on-mac** | Daemon in application mode opens its loopback local proxy; the app points the macOS system proxy at it via `networksetup` with snapshot-before-change, restore-on-stop, crash-guard recovery at launch, and honest authorization-denial state. Proxy-aware apps only. |
| NetworkExtension | **not implemented — prospect** | Needs Developer ID, NE entitlement, system-extension approval, notarization. Spec only; no code pretends otherwise. |

Below macOS 12 the client launches and explains (the service cannot
run — the attempts to build the daemon for macOS 11 and for a
10.15-limited tier are recorded in [TIERS.md](TIERS.md) §§1–2:
the dependency graph requires Go ≥ 1.25/1.26, so those tiers are
engine tiers, not service tiers). For the shipped service on Apple
Silicon below macOS 26 there is still no sing-box build that
launches — Xray and mihomo carry what they can, and the daemon's own
engine selection reports the rest; at the engine level the gap is
now closed by reproducible self-builds (sing-box 1.13.21 at an
11.0 floor for both architectures, 1.11.15 at 10.15 for Intel —
[TIERS.md](TIERS.md) §3, pins in `engines-darwin.lock`,
recipe `build-singbox-darwin.sh`), which no shipped driver drives
below 12.0 yet. Engine features and obfuscation
capabilities reach the UI only as data: the helper's `engineinfo`
(core catalog via `core/mobileapi`) and the daemon's `GetAbout`
(installed/version per engine). No feature strings are hardcoded in
the Swift UI.

## Layout

| Path | What |
| --- | --- |
| `helper/` | Go module: `sora-ctl` (status/about/engineinfo/servers/import/import-url/select/connect/disconnect), tests |
| `App/Core/` | Foundation-only Swift (capabilities, models, helper client, system proxy, settings) — SPM package target, Linux-testable |
| `App/UI/` | AppKit (menu bar + one window), parse-checked here, Xcode-compiled on a Mac |
| `App/Info.plist` | bundle metadata (no entitlements claimed) |
| `project.yml` | XcodeGen spec: one macOS app target, deployment target 10.13 |
| `Package.swift` | SPM package for App/Core + Tests/CoreTests |
| `engines-darwin.lock` | darwin engine pins (URL + sha256, digests cross-checked vs upstream .dgst / GitHub API) plus the self-built sing-box pins of TIERS.md §3 |
| `TIERS.md` | macOS 11 / 10.15-limited tiers: daemon build-attempt protocols, self-built sing-box, gates, per-tier client divergence |
| `build-singbox-darwin.sh` | reproducible self-build of the tier sing-box pins (pinned toolchains + sources, SHA-256 verified) |
| `fetch-engines-darwin.sh` | downloads + verifies + lays out engines with the SHA256SUMS manifest the core requires |

## Building

Here (Linux, this machine) — all of it done and measured:

```sh
export PATH=$HOME/workspace/go/bin:$PATH
# daemon (both arches)
cd core && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ./cmd/sora-core
# helper: tests on Linux, then darwin builds
cd macos/helper && go test ./... && \
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath .
# engines
sh macos/fetch-engines-darwin.sh amd64 build/darwin/engines
# Swift core checks (Linux Swift toolchain)
cd macos && swift test        # App/Core + Tests/CoreTests
```

Built artifacts of this delivery (outside the repo, `~/workspace/.legplat/`):

| Binary | sha256 |
| --- | --- |
| sora-core darwin amd64 | `97d4ef4b91528593605f5003c67a1967c9d0a508c5c3e521e300032e65151b09` |
| sora-core darwin arm64 | `94f456c1a99e150c4e67fb06d554d03e8df1d8479e7a7614d36aab7b368ff79a` |
| sora-ctl darwin amd64 | `af18aa0798df996509f4d6eaead494a7c6c8cf7b676065760bfa1b798601d3c8` |
| sora-ctl darwin arm64 | `1137b988f7edf6252376f334229fa68fec8bb61801753fe89f7c1bff194ad73d` |

On a Mac (the client app):

```sh
brew install xcodegen
cd macos && xcodegen generate --spec project.yml
open SoraLegacy.xcodeproj   # build SoraLegacy (10.13 deployment target)
sudo sh ../service/darwin/install.sh <dir with sora-core, sora-ctl, engines/>
/usr/local/lib/sora-legacy/sora-ctl status
```

## Verify-on-mac checklist

Nothing below has been executed on real hardware; each item names
what would prove it.

1. `go test ./core/ipc/` on macOS — `TestPeerOfDarwin` must see a
   kernel-verified peer with the test process's UID (LOCAL_PEERCRED).
2. Install the service; `sora-ctl status` as the console user (group
   `sora`) answers; as a user outside the group it is refused.
3. Import a real subscription; connect in **proxy** mode; system
   proxy points at the core's loopback port; traffic flows; disconnect
   restores the previous proxy settings byte-for-byte; kill the app
   mid-session and relaunch — the crash guard restores the proxy.
4. Connect in **TUN** mode on macOS 12+: utun appears, routes change,
   disconnect restores them. Record which engine carried it
   (GetAbout / status).
5. Proxy-mode authorization denial (non-admin user) shows the honest
   state and disconnects the session.
6. On Apple Silicon below macOS 26: status shows sing-box not usable;
   an Xray/mihomo-carried plan still connects.
7. Xcode build of the app on the oldest available system (ideally
   10.13–12): first build will find issues; App/Core is unit-tested,
   App/UI is not — expect the fixes to land there.
8. `networksetup` proxy changes on a multi-service machine (Wi-Fi +
   Ethernet + a disabled service) restore every service verbatim.
