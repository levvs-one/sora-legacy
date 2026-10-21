# Sora Legacy for iOS

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
Linux Swift 6.0.3 (`swift test`, 10/10 — TunConfig injection,
store/secrets split, mobileapi JSON shapes).

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
group); the App Group suite holds only credential-stripped server
metadata, settings and the tunnel exchange.

## Tree map

| Path | What |
|---|---|
| `project.yml` | XcodeGen spec: app + PacketTunnel, iOS 13.0 |
| `BUILD-MAC.md` | Floor evidence, framework binds, signing, verify checklist |
| `SoraLegacyCore/` | SPM package (Foundation only): models, TunConfig, mobileapi seam, App Group store, tests |
| `App/` | UIKit app: status, servers+import (paste / URLSession fetch), settings (EngineInfo), Keychain, TunnelManager |
| `PacketTunnel/` | Provider + the one file that touches Libbox types (`LibboxBridgeImpl.swift`: BoxService lifecycle, all 18 PlatformInterface methods, local-DNS transport, iterators) |

Generated-framework spellings that only a Mac header can settle are
behind seams and marked `TODO(verify-on-mac)` at the call site —
the Go side of every call is cited from the pin's sources in the
file headers.
