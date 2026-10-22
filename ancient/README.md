# Sora Ancient — Windows XP / Vista / 8.0 track

> Part of [Sora Legacy](../README.md). This tree is the ancient-Windows track (XP SP3 / Vista SP2 / Windows 8.0); its honest status and floors are stated below and in [platforms](../legacy/docs/platforms.md). Full documentation index: [docs/README.md](../docs/README.md).


A separate, **additive** track for Windows versions the main legacy
stack cannot reach. It does not modify, reuse at runtime, or weaken the
main client (`legacy/`), the Go core (`core/`), or the installer: those
stand on .NET Framework 4.8, a modern-Go core and Wintun, whose floors
are NT 6.1+. This track exists because the owner ordered the earlier
"XP/Vista unreachable" verdict re-tested by building, not by reasoning
about the main stack's floors. The verdict for the **main** stack
stands; this track reaches the old systems with era-correct parts.

## Framework floors — primary sources

Source: Microsoft Learn, *Install .NET Framework on Windows*
(`learn.microsoft.com/en-us/dotnet/framework/install/on-windows-and-server`,
table "Windows 8.1, 8, 7, Vista, XP" — included vs latest supported),
cross-checked against the per-version installer pages.

| OS | Included | Latest .NET Framework supported | Track target |
| --- | --- | --- | --- |
| Windows XP SP3 | — | **4.0.3** | `net40` build |
| Windows XP SP2 | — | 3.5 | out of scope (SP3 required) |
| Windows Vista | 3.0 | **4.6** (requires SP2) | `net46` build |
| Windows 8.0 | 4.5 | **4.6.1** | `net46` build (shared with Vista) |
| Windows 8.1 | 4.5.1 | 4.8 | main legacy client |

Why not newer:
- XP: .NET 4.5+ never supported XP; 4.0.3 (on top of 4.0) is the last
  line — see also Learn, *Install the .NET Framework on Windows XP*
  ("The .NET Framework 4.0.3 is the latest supported .NET Framework
  version on Windows XP").
- Vista: 4.6 is the ceiling. The 4.6 installer itself is titled
  "for Windows Vista SP2, …" (Microsoft Support), and 4.6.1 dropped
  Vista (its floor is Windows 7 SP1).
- Windows 8.0: 4.6.1 is the ceiling — 4.6.2 dropped Windows 8.0 (its
  supported list is Windows 7 SP1 / 8.1 / 10). That is also why the
  main client's net48 cannot cover 8.0: the 4.7+ line starts at 8.1.
- One client, two TFMs: the sources are a single tree multi-targeted
  `net40;net46`. `net462` was considered and rejected on the facts
  above: no Vista *and* no 8.0 machine can install it. `net46` is the
  newest runtime Vista and 8.0 share, so they share one build; XP gets
  the `net40` build of the same sources (C# 7.3, no post-4.0 APIs on
  the shared path).

## Engine — pinned by measurement, not by release notes

Go's own release notes set the hard boundary (go.dev/doc/go1.10,
Ports: "Go 1.10 is the last release that will run on Windows XP or
Windows Vista. Go 1.11 will require Windows 7 or later."). Every
candidate binary was downloaded and its embedded Go version read from
the binary itself:

| v2ray-core release | Date | Embedded Go (measured) | XP/Vista |
| --- | --- | --- | --- |
| **v3.36** | 2018-08-23 | **go1.10.2** (win + linux builds), PE subsystem 4.0 | **yes — pinned** |
| v3.37 | 2018-08-30 | go1.11 | no (Win7 floor) |
| v4.19.1 | 2019-06-03 | go1.12 | no |
| v4.45.2 (last v4) | 2022-05-21 | go1.18.3, PE subsystem 6.1 | no |

Xray was rejected without a download matrix: the project starts in
2020 on Go ≥ 1.15 — there is no Xray build from the Go 1.10 era at all.

Pin: **v2ray-core v3.36**, assets in `engines.lock` (SHA-256 measured
on the official downloads 2026-10-22 and cross-checked against the
SHA-1 digests upstream published in that release's `metadata.txt` —
all three assets match). `stage-engines.sh` downloads resumably and
verifies SHA-256 fail-closed before unpacking.

## Protocol surface — proven on the pinned binary

Probes ran the Linux build of the *same* release with
`v2ray -test -config` (config grammar is platform-independent) plus a
live loopback run (SOCKS inbound → freedom outbound → local HTTP
server: body received). One methodological trap is recorded honestly:
v2ctl's JSON converter is **lenient about unknown
`streamSettings.security` values** — it answered "Configuration OK"
for `security:"reality"`, a feature whose name appears **zero** times
in the binary. PASS below therefore means config-test PASS *and*, for
post-era features, a binary string scan:

| Feature | Verdict | Evidence |
| --- | --- | --- |
| VMess (tcp / ws+tls / kcp / http2+tls) | works | `-test` PASS ×4 |
| VMess alterId 0 (AEAD-shaped config) | config accepted | `-test` PASS; wire interop with AEAD servers is *not* claimed — era servers are the target |
| Shadowsocks aes-256-gcm / aes-128-gcm / chacha20-poly1305 / chacha20-ietf-poly1305 / aes-128-cfb | works | `-test` PASS |
| Shadowsocks 2022-blake3-* | **absent** | `-test` FAIL |
| aes-192-gcm, xchacha20-poly1305, ss "none" | **absent** | `-test` FAIL |
| SOCKS outbound, SOCKS + HTTP inbounds, dokodemo-door | works | `-test` PASS |
| HTTP outbound | **absent** | `-test` FAIL: "unknown config id: http" |
| VLESS, Trojan | **absent** | `-test` FAIL; 0 occurrences in binary |
| REALITY, XTLS | **absent** | 0 occurrences in binary (config test is lenient — not trusted) |
| QUIC transport | **absent** | `-test` FAIL: "unknown transport protocol: quic" |
| WireGuard, Hysteria, TUIC | **absent** | postdate the engine; 0 occurrences |
| MTProto outbound | present | `-test` PASS, `mtproto.*` types in binary — not wired into the client UI (era niche; listed for completeness) |

Config grammar is era-shaped: singular `"inbound"` / `"outbound"`
objects (+ `inboundDetour` for the HTTP inbound). The plural 4.x arrays
fail this engine's own test ("no inbound config specified") —
`ConfigBuilder` renders the era shape, and ParserCheck pins that.

The client refuses what the engine cannot do, by name, at import time
(`EraGate`): VLESS / Trojan / Hysteria / TUIC / WireGuard links,
SS-2022 methods, SIP003 plugins, REALITY/XTLS stream security, QUIC /
XHTTP transports. A refusal is a sentence about the era limit, never a
raw engine error and never a silently degraded connection.

## TUN — refused, with reasons

There is no honest TUN in this track:
- The pinned engine has no TUN mode at all (v2ray is a proxy core;
  TUN would need an external tun2socks-style shim).
- Wintun targets Windows 7+ (its driver project sets
  `TargetVersion=Windows7` for x86/x64) — no XP/Vista build exists.
- The era TAP driver (tap-windows 9.9.2, NDIS 5) is the last XP line —
  later tap-windows6 (NDIS 6) requires Vista+ (OpenVPN's own split:
  "win6" installers need Vista or later, "XP" installers carry 9.9.2).
  A TAP + tun2socks chain on XP is *conceivable*, but it means shipping
  a kernel driver and a shim neither of which this track has built or
  tested; pretending otherwise would be a fake feature.

Scope is therefore: **local SOCKS (10808) + HTTP (10809) inbounds,
system proxy (HKCU Internet Settings, snapshot/restore) while
connected**. The UI says "proxy mode; TUN is not part of this track"
on the connected state itself.

TLS caveat, stated plainly: subscription fetch and VMess TLS run on
the era OS SChannel. Hosts that require TLS 1.3 (or cipher suites the
era stack lacks) will fail; the client reports a named TLS/network
failure and never falls back to plaintext or `allowInsecure`.

## Client

`src/Sora.Ancient` — one WinForms source tree, `net40` + `net46`
builds, zero third-party dependencies (own link parser / JSON /
config renderer, so the era machines need nothing but the framework).
Server list with import of a single link or a subscription URL,
connect/disconnect driving the staged engine, system-proxy
snapshot/restore following the shipped client's contract
(record before first change → replay exactly → delete snapshot;
damaged snapshot = named error, proxy untouched).

Build (Linux, as with the toolchain department's net48 precedent):

```bash
~/workspace/dotnet/dotnet build ancient/src/Sora.Ancient/Sora.Ancient.csproj
~/workspace/dotnet/dotnet run --project ancient/tools/ParserCheck
./ancient/stage-engines.sh   # digest-verified engine staging
```

## Status

Client and engine are **built and proven at build/config level**
(client: both TFMs compile; parser/config: ParserCheck green; engine:
config probes + Linux loopback run), and **runtime under Wine is now
proven** (phase WS1-C, 2026-10-22, report `LEGACY-FULL-1C-WINE.md` in
the programme reports): in both prefixes (winxp + net40, winvista +
net46) the pinned engine answers `-version` and passes `-test`, the
client starts without crashing and enters its message loop, vmess
import + era config generation executed on the prefixes' own era
runtimes (WineCheck harness on the client's exact sources; framework
4.0.30319.1 / 4.0.30319.17929), and loopback traffic passed through
the engine's SOCKS inbound in both prefixes. What Wine does **not**
prove is listed point-by-point in the phase report (drivers/TAP, real
Internet Settings semantics, performance, the era OSes' own network
stacks). A real XP/Vista/8.0 device check remains the final gate. No
status in this track claims more than that.
