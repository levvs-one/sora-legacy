# Sora Legacy for iOS

> Part of [Sora Legacy](../README.md). This tree is the iOS client; it has never been compiled with Xcode from this environment — the verify-on-mac status is stated below and in [platforms](../legacy/docs/platforms.md). Full documentation index: [docs/README.md](../docs/README.md).


Native iOS client for sora-legacy: the desktop core's control plane
(`core/mobileapi`) plus upstream **sing-box 1.12.12** libbox, in a
packet-tunnel extension. Sibling of `android/` — same pipeline, same
TunConfig constants, same honest-state model.

## Honest status

**Written on Linux; never compiled with Xcode.** There is no Xcode
or Apple SDK on the producing machine, so framework binds and the
app build are Mac work, specified exactly in
[BUILD-MAC.md](BUILD-MAC.md) with a verify-on-mac checklist (§7).
What *was* verified here: every Swift file passes `swiftc -parse`;
the pure-Swift core (`SoraLegacyCore`) builds and its tests pass on
Linux Swift 6.0.3 (`swift test`, 35/35 — the original 19: TunConfig
injection, store/secrets split, mobileapi JSON shapes, TunOptions
snapshot shape and route-range selection, netmask parsing; plus 16
tests of the additive iOS 12 tier: pins, DNS translation, gates).

## Deployment target: iOS 13.0

Established from the pin's sources, not assumed — BUILD-MAC.md §1
has the file:line chain: `build_libbox` passes no `-iosversion`,
the pin contains no `IPHONEOS_DEPLOYMENT_TARGET` and no SFI tree,
and its pinned sagernet/gomobile v0.1.8 defaults `-iosversion` to
**13.0**. So the legacy iOS client covers iOS 13–14 itself (the
main sora tree's iOS 15 floor is its lx fork's fact, a different
pin). UI is UIKit by decision: at a 13.0 floor SwiftUI lacks the
scene lifecycle and this product's other mobile client is native
views too (see AppDelegate.swift).

## Architecture

```
App (UIKit)                          PacketTunnel extension
  Status / Servers / Settings          NEPacketTunnelProvider
        │                                     │
  mobileapi (Mobileapi.xcframework)    libbox (Libbox.xcframework)
  ImportLinks / ParseSubscription      BoxService (service.go)
  BuildPlan / RenderSingBoxConfig      PlatformInterface (18 methods,
        │                              LibboxBridgeImpl.swift)
        ▼                                     ▲
  TunConfig.injectTunInbound ──► TunnelConfigExchange
        (App Group suite + providerConfiguration)
```

Flow (mirrors Android's `SoraVpnService.startEngine`): selected
server → plan document → BuildPlan → RenderSingBoxConfig →
TunConfig injects exactly one tun inbound
(`172.19.0.1/30` + `fdfe:dcba:9876::1/126`; the /30 is a libbox
contract — `GetDNSServerAddress` throws on a /32) → exchange saved
→ `NETunnelProviderManager.startVPNTunnel`. In the extension:
`Libbox.Setup` → `NewService(config, platformInterface)` → `Start`;
the tun inbound calls `OpenTun(TunOptions)`, the provider installs
`NEPacketTunnelNetworkSettings` built from those options and
returns the fd from the pin's own `GetTunnelFileDescriptor()`
(tun_darwin.go).

Secrets: server credentials live in the Keychain (shared access
group, resolved at runtime from the Models constant — the
`$(AppIdentifierPrefix)` prefix is expanded by Xcode only in
entitlements, never in Swift sources; see App/KeychainSecrets.swift).
The App Group suite holds credential-stripped server metadata and
settings — plus the tunnel exchange, which by design carries the
full rendered config, outbound credentials inside: the extension
cannot run the tunnel without the complete config (Android writes
the same rendered config to its private filesDir, and the exchange
is mirrored into providerConfiguration for the same reason). The
suite is not a credential store, but the exchange is not
credential-free either.

Per-app filtering: TunOptions' include/exclude package lists are
drained into the snapshot in full, but cannot be applied on iOS —
per-app VPN is an MDM-only capability and a non-MDM provider has
no API for it. The provider logs an explicit refusal when the
lists are non-empty (BUILD-MAC.md §6); nothing is silently
dropped.

## Tree map

| Path | What |
|---|---|
| `project.yml` | XcodeGen spec: app + PacketTunnel, iOS 13.0 |
| `BUILD-MAC.md` | Floor evidence, framework binds, signing, verify checklist |
| `SoraLegacyCore/` | SPM package (Foundation only): models, TunConfig, mobileapi seam, App Group store, tests |
| `App/` | UIKit app: status, servers+import (paste / URLSession fetch), settings (EngineInfo), Keychain, TunnelManager |
| `PacketTunnel/` | Provider + the one file that touches Libbox types (`LibboxBridgeImpl.swift`: BoxService lifecycle, all 18 PlatformInterface methods, local-DNS transport, iterators) |

Generated-framework spellings that only a Mac header can settle are
behind seams and marked `TODO(verify-on-mac)` at each generated
spelling's site in LibboxBridgeImpl.swift (MobileAPIGenerated.swift
carries one file-level TODO covering all of its calls) — the Go
side of every call is cited from the pin's sources in the file
headers.
