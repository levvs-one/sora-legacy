# Sora Legacy — Android client

A full Android client for the sora-legacy core, in one tree:

- **Core logic is not reimplemented.** Imports, plan validation and
  sing-box rendering are the desktop core's own pipeline, reached
  through the gomobile facade `core/mobileapi`
  (`importLinks` / `parseSubscription` / `buildPlan` /
  `renderSingBoxConfig` / `engineInfo`, verified by `javap` against
  the shipped `mobileapi.aar`).
- **The engine is sing-box 1.12.12's libbox**, driven through
  `Libbox.newService(config, platformInterface)` /
  `BoxService.start()` / `close()` exactly as its Go sources
  (`experimental/libbox/service.go`) define.
- **The platform side is ours**: `SoraVpnService` (an Android
  `VpnService`) implements libbox's `PlatformInterface`
  (`experimental/libbox/platform.go`, 18 methods) against real
  Android APIs.

## Architecture and data flow

```
ServersActivity ──paste links──────────────► Mobileapi.importLinks
                ──paste document───────────► Mobileapi.parseSubscription
                ──URL (HttpURLConnection)──► body ─► parseSubscription
                              │  JSON array of servers (with credential
                              │  documents — stored like passwords)
                              ▼
                     ServerStore: filesDir/servers.json (merged by id)
                              │  selection in SharedPreferences
MainActivity ──Connect──► VpnService.prepare() consent ──► SoraVpnService
                              │
   SoraVpnService (worker thread):
     plan document {local_port, servers:[selected]}
       -> Mobileapi.buildPlan -> Mobileapi.renderSingBoxConfig
       -> TunConfig.injectTunInbound (adds the tun inbound, see below)
       -> filesDir/config.json
       -> Libbox.setup (once) -> Libbox.newService(config, this)
       -> BoxService.start()
                              │
   libbox calls back PlatformInterface.openTun(TunOptions):
     VpnService.Builder with the engine's own addresses / routes /
     route exclusions / DNS hijack address / package filters /
     HTTP proxy -> establish() -> detachFd() -> engine owns the TUN
```

Status and errors travel through the process-local `VpnState` holder
(service and activities share a process; nothing is persisted, so a
dead process can never leave a stale "connected" flag). The UI shows
the engine's own error message — never a raw stack trace (stacks go
to logcat only).

### Why the client injects a `tun` inbound

`mobileapi` renders an *application-mode* plan — its doc comment is
explicit: "Mobile clients own the TUN", and the render contains only
the loopback mixed inbound. On Android the TUN is created by
sing-box's tun inbound asking `PlatformInterface.openTun()` for a
file descriptor. `TunConfig.injectTunInbound` therefore adds exactly
one inbound to the rendered document — `type: tun`, addresses
`172.19.0.1/30` + `fdfe:dcba:9876::1/126` (a /30, because libbox's
`GetDNSServerAddress()` derives the hijack DNS address as the second
address of the first IPv4 prefix and refuses a /32), `auto_route`,
and the user's `mtu` / `strict_route` settings. If a future render
ships its own tun inbound, it is left untouched.

### PlatformInterface implementation notes (18 methods)

| Method (platform.go) | Implementation |
|---|---|
| `OpenTun` | `VpnService.Builder` from `TunOptions` verbatim (see flow above); route exclusions via `Builder.excludeRoute` (API 33+), HTTP proxy via `setHttpProxy` (API 29+) |
| `AutoDetectInterfaceControl` | `VpnService.protect(fd)`, throws on failure |
| `UsePlatformAutoDetectInterfaceControl` | `true` |
| `LocalDNSTransport` | Lookup-only transport (`raw()==false`): system resolver via `InetAddress`; `Exchange` throws by contract (libbox never calls it when `raw()` is false) |
| `UseProcFS` | `false` |
| `FindConnectionOwner` | `ConnectivityManager.getConnectionOwnerUid` (API 29+); below 29 throws `UnsupportedOperationException` — no honest answer exists there with procfs off |
| `PackageNameByUid` / `UIDByPackageName` | `PackageManager` |
| `Start/CloseDefaultInterfaceMonitor` | `ConnectivityManager` default-network callback (API 28+; `registerNetworkCallback` fallback below), reports name/index/metered |
| `GetInterfaces` | `java.net.NetworkInterface` (up interfaces, CIDR addresses, IFF flags as `link_flags_unix.go` maps them) merged with `ConnectivityManager` type/DNS/metered per interface name; IPv6 zones (`%scope`) are stripped from every address and DNS server handed to libbox — its Go side parses them with `netip.MustParsePrefix`, which rejects zones with a panic |
| `ReadWIFIState` | `WifiManager`; returns null when the SSID is unknown/redacted instead of inventing one |
| `SystemCertificates` | PEM encodings of the platform trust store's accepted issuers |
| `ClearDNSCache` | No-op — Android has no per-app DNS-cache flush API; the contract is void and upstream clients no-op too |
| `SendNotification` | Real notification on the alerts channel |
| `WriteLog` | logcat + in-memory ring shown on the main screen |
| `UnderNetworkExtension` / `IncludeAllNetworks` | `false` / `false` (Android is not NetworkExtension; all-networks inclusion is an Apple concept) |

### Two gomobile AARs, one `go.Seq`

Both AARs embed the gomobile `go.*` proxy classes; a dex can hold a
class once. The manual pipeline drops `go/**` from the mobileapi jar
and keeps libbox's copy: `javap` shows the two `go.Seq` APIs are
identical except libbox's `destroyRef` is `public` (a superset).
Whether the two native libraries (libgojni.so, libbox.so) cooperate
with a single shared `go.Seq` at runtime is a **device-only**
question — see "Not verified" below.

## Why minSdk 21

Facts, not taste:

- The AARs are bound with `gomobile bind -androidapi 21`; their
  native code and `AndroidManifest` assume API 21 as the floor.
- `VpnService` exists since API 14, but the Builder surface this
  client relies on without reflection — per-app allow/disallow
  (`addAllowedApplication`/`addDisallowedApplication`, API 21),
  `setMtu`, DNS and route control in one establish — is complete
  from API 21. The legacy-Windows floor work in this repo settled on
  the same "oldest platform whose stack is complete, nothing older"
  rule.
- Below API 21 the platform TLS stack has no reliable TLS 1.2-by-
  default / SNI behaviour (pre-Conscrypt-updatable era), which the
  protocols the core renders (REALITY, uTLS-shaped ClientHellos,
  Hysteria2/TUIC over QUIC) presuppose.
- Newer APIs are used only behind runtime gates, never as a floor
  raise: connection-owner (29+), HTTP proxy on the Builder (29+),
  excluded routes (33+), notification permission (33+), the typed
  `startForeground` (34).

## Why no AndroidX / Compose

Dependencies are Kotlin stdlib + the framework Android API +
`org.json` (in `android.jar`), full stop. This is deliberate:

- minSdk 21 plus fully offline builds: every AndroidX artifact is
  one more network fetch that this tree's sandbox cannot make and a
  2014-era device does not need.
- The UI is three small screens of status/lists/forms; framework
  Views express them completely. Compose would add a compiler
  plugin, a runtime, and a minimum practical API well above 21 for
  zero user-visible gain here.

## Building

### Developer machine (canonical)

```sh
cp /path/to/mobileapi.aar /path/to/libbox.aar app/libs/
./gradlew assembleDebug
```

AGP 8.5.2 + Kotlin 2.0.21, Gradle 8.7 (wrapper properties in
`gradle/wrapper/`). The AARs are git-ignored and never committed.

In this sandbox Gradle cannot run at all: the Gradle daemon talks
to its client over a loopback TCP socket, and this sandbox
intercepts Java TCP (the toolchain department proved raw Java TCP is
answered by the sandbox proxy, see
`reports/LEGACY-PLAT-ANDROID-TOOLCHAIN.md`). Three attempts
(daemon, `--offline`, `--no-daemon` with a single-use daemon) all
fail identically before any plugin resolution:

```
FAILURE: Build failed with an exception.
* What went wrong:
Could not receive a message from the daemon.
```

Plugin resolution would be the next wall for the same reason (JVM
HTTPS is intercepted), which is why the manual pipeline exists.

### This sandbox (manual pipeline)

```sh
bash tools/build-manual.sh
```

Repeatable, documented in the script: standalone `kotlinc` 2.0.21
(curl-fetched, sha256 pinned in the script and re-verified on every
run, not only at download time) compiles the Kotlin sources against
`android.jar` + both AAR jars; `aapt2` compiles/links resources and
the manifest; `d8` dexes our classes + AAR classes (de-duplicated,
above) + kotlin-stdlib; the APK is assembled with `classes.dex`,
`resources.arsc` and `lib/<abi>/*.so` from both AARs, `zipalign`-ed
and signed with a locally generated **debug** key (keytool, password
and alias written in the script — debug only, not a release
identity). Output and proof logs land in
`~/workspace/.legplat/apk/` (`app-debug.apk`, `aapt2-badging.txt`,
`apksigner-verify.txt`).

Known manual-pipeline wart: d8 from build-tools 34 predates Kotlin
2.0 metadata and prints "malformed kotlin.Metadata" warnings for our
classes. Dexing still succeeds and the app uses no Kotlin
reflection; AGP builds on a dev machine (newer R8 via AGP 8.5) do
not have this warning.

The universal APK is large (~267 MiB): both engines' `.so` for all
four ABIs, stored uncompressed for direct mmap loading. Per-ABI
splits are a packaging step for distribution, not a client concern.

## Not verified (verify on device)

No device or emulator exists in this sandbox; the APK was never
installed or run. Before trusting a build, verify on real hardware:

1. Install + first launch; VPN consent flow (`VpnService.prepare`
   dialog -> `RESULT_OK` -> service start).
2. Connect end-to-end: engine start, `openTun` callback, traffic
   through the tunnel, DNS behaviour of the injected tun inbound
   (the rendered route has no explicit `hijack-dns` rule — check
   whether system DNS leaks or fails and whether a rule is needed).
3. The shared `go.Seq` question above: both native libraries in one
   process, mobileapi rendering + libbox running concurrently.
4. Disconnect (service `close()`), reconnect, server switch.
5. `onRevoke` path (another VPN app taking over / always-on VPN
   settings), always-on and lockdown behaviour in system settings.
6. Per-app include/exclude from a rendered config that actually
   carries package filters; excluded-route behaviour on API 33+ vs
   below (below 33 exclusions are dropped — see code).
7. Foreground-service behaviour on API 34 (specialUse type +
   subtype property + `FOREGROUND_SERVICE_SPECIAL_USE`).
8. Subscription fetch over the device network (the sandbox's JVM
   network is dead; this code path is compile-checked only), incl.
   the honest failure for `http://` URLs (`usesCleartextTraffic`
   is `false`).
9. `findConnectionOwner`-driven process rules on API 29+, and the
   refused path below 29.
10. Notification permission denial on API 33+ (app must still work,
    only notifications are lost).
11. Start on a network with scoped IPv6 (link-local fe80::/64 on
    Wi-Fi/cellular, `::1` loopback): the engine must come up — the
    interface/DNS addresses handed to libbox are zone-stripped
    (libbox's `netip.MustParsePrefix` panics on a `%scope` suffix).

## Layout

```
settings.gradle.kts, build.gradle.kts, gradle.properties,
gradle/wrapper/gradle-wrapper.properties   canonical Gradle form
app/build.gradle.kts                      app module (minSdk 21 / target 34)
app/src/main/AndroidManifest.xml          VpnService, FGS type, permissions
app/src/main/java/one/levvs/sora/legacy/
  SoraVpnService.kt    VpnService + PlatformInterface + engine lifecycle
  MainActivity.kt      status / connect / disconnect
  ServersActivity.kt   list, selection, three import paths
  SettingsActivity.kt  local_port / MTU / strict_route + engine info
  ServerStore.kt       servers.json + SharedPreferences
  TunConfig.kt         tun-inbound injection into the rendered config
  LocalDnsTransport.kt libbox local DNS (lookup-only)
  LibboxHelpers.kt     iterator implementations + TunOptions plan
  VpnState.kt          process-local state + engine log ring
  Ui.kt                framework-View builders (UI is code, no layouts)
app/src/main/res/values/                  strings + framework theme
tools/build-manual.sh                     the sandbox pipeline above
```
