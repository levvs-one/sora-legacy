<p align="center">
  <img src="docs/images/logo-512.png" width="96" alt="Sora Legacy logo">
</p>
<h1 align="center">Sora Legacy</h1>

[Русский](README.md)

[![Release](https://img.shields.io/github/v/release/levvs-one/sora-legacy)](https://github.com/levvs-one/sora-legacy/releases)
[![Downloads](https://img.shields.io/github/downloads/levvs-one/sora-legacy/total)](https://github.com/levvs-one/sora-legacy/releases)
[![License](https://img.shields.io/github/license/levvs-one/sora-legacy)](LICENSE)

The Sora client for older Windows: Windows 7 SP1, 8.1, 10 and 11 on x86 (on x64 it runs through WoW64). A separate repository and a separate generation; the regular client for current systems is [sora](https://github.com/levvs-one/sora).

## Installation

Requirements in one line: Windows 7 SP1 or newer and .NET Framework 4.8; the installer checks .NET and the required Windows 7 updates itself and installs what is missing where it can. Installation is per-user, needs no administrator rights, and goes to `%LOCALAPPDATA%\Programs\Sora`.

There is no finished public release yet: the installer is built from this repository following the development recipe. The full guide, including update and uninstall behaviour, is [docs/install.md](docs/install.md) (in Russian).

## Quick start

1. Start the client.
2. Add a subscription link or a single server link — the format is detected automatically.
3. Pick a server and connect: system proxy mode or TUN.

## Status: there is no finished release yet

This is the plain state today, without exceptions:

- **The executable that ships today is the v2rayN-based client** (`sora_<target>.exe`, for example `sora_win7.exe`). It is the one built in CI, covered by regression checks and staged by `legacy/build/Stage-Release.ps1`.
- **The new client** (`legacy/Client`, .NET Framework 4.8, WinForms) is built, lives in this repository and is covered by interop tests against the real core service, but it is **not in the delivery stage yet**. Switching the stage is separate work; until it is done, the new client is not shipped to users.
- **The installer already registers `sora://` links**, but the registered handler today is the shipped v2rayN-based client, which does not handle a `sora://…` argument: a click on such a link is silently dropped for now. The handler that imports a subscription from a link is the new client; the registration takes effect unchanged when the stage switches to it.
- Compatibility with Windows 7 SP1 and 8.1 **has not been verified by running on those systems yet**. Support is by construction (.NET Framework 4.8 client, Windows 7 engine builds, core built with the Windows 7 Go SDK); all checks ran on Linux and on modern Windows in CI.

- [Current checks and builds](https://github.com/levvs-one/sora-legacy/actions/workflows/legacy.yml)
- [What is verified and what remains](legacy/PLANS.md)
- [Telegram](https://t.me/sora_client)

## Features

The shipped client:

- Subscriptions as separate collapsible sections on the servers screen: name, description, traffic limit, expiry, update and latency check all belong to a specific subscription.
- One-line import: HTTPS subscriptions, VMess, VLESS, Trojan, Shadowsocks, SOCKS, Base64, SIP008 and Xray JSON; the format is detected automatically.
- Latency check by a direct TCP connection to the server address.
- Connection modes: system proxy and TUN.
- Logs saved as UTF-8 and a separate safe diagnostic archive without configurations or credentials.

The core and the new client (not shipped):

- The core is a Go service (`core/`), contract `sora.core.v1` version 1.7; on Windows the service registers as `SoraLegacyCore`. The new client uses the core; the shipped client runs the engines itself.
- Three engines: sing-box, Xray, mihomo. The service picks an engine for each connection plan; a crashed engine is restarted by a supervisor with a limited retry budget.
- Link and subscription protocols: VLESS, VMess (including the classic base64 format), Trojan, Shadowsocks, SOCKS, HTTP(S) proxies, Hysteria2, TUIC, WireGuard. Transports: TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, XHTTP — including the `extra` field (split delivery, xmux, padding) within what a given engine supports.
- REALITY, uTLS fingerprints, ECH. REALITY KeyShare is rendered only for the lx variant of sing-box; this capability is not claimed on upstream sing-box builds.
- Hysteria2: up/down in megabits and port hopping. TUIC: congestion control, BBR by default.
- Subscriptions: HTTPS-only fetching; a fallback link; server list overrides — renames, hidden servers, pinned order. The honest limit: the core reads and applies the overrides file on every subscription update, but this generation's contract has no RPC to write it, so the interface does not offer writing overrides yet.
- Connection-level obfuscation of the subscription fetcher: ClientHello fragmentation, SNI substitution (FakeSNI), write-delay jitter.
- Kill switch (WFP on Windows, nftables on Linux), TUN, system proxy.

What this generation does not have, and the documentation does not promise: 13 RPCs of the main client — among them `CheckDnsLeaks`, `BenchmarkServers` and `SelectServer`, network profiles, proxy chains, subscription overrides over RPC and device sync. This repository's contract is `proto/sora/core/v1/core_control.proto`.

## Security

- Engines are checked fail-closed: the service verifies engine binaries against the digests in the shipped `SHA256SUMS`; a mismatch means a refusal to start, not a warning. Core updates from the shipped client verify the archive's SHA-256 against the release's `.dgst` manifest before unpacking only for the v2fly, v2fly_v5 and Xray cores. For SagerNet (v2ray-core), clash and clash_meta there is no such check: upstream does not publish a `.dgst` in a predictable form, the hash check is skipped, and only the downgrade ban applies to those cores. The sing_box core is not updated from the interface at all.
- The client has no self-update: the interface's update-check item simply opens the releases page in a browser. Updating means installing a new version over the old one by hand.
- The core keeps subscriptions and secrets in encrypted storage (AES-256-GCM; on Windows the key is protected by DPAPI). The core keeps its log in memory; secrets never reach the log or diagnostic archives — masking is applied.
- There is no telemetry in the core. Network calls: fetching subscriptions from your provider and — only by your own action in the shipped client's interface — checking core and geo-database updates at the official GitHub releases.
- Installer release signatures are not issued yet: the signing key is the owner's step, and until the key ceremony the installer is unsigned.

Details — [docs/security.md](docs/security.md) (in Russian). How to report a vulnerability — [SECURITY.md](SECURITY.md).

## Documentation

Full documentation is in Russian: installation, usage, FAQ, troubleshooting, building from source, core architecture, engines, platforms and security notes are all written in Russian.

- Users: [installation, updates and uninstall](docs/install.md), [usage](docs/usage.md), [FAQ](docs/faq.md), [troubleshooting](docs/troubleshooting.md).
- Developers: [building from source](docs/development.md), [core architecture](docs/architecture/core.md), [engines](docs/architecture/engines.md), [platforms](legacy/docs/platforms.md).
- Work and verification status: [legacy/PLANS.md](legacy/PLANS.md).
- Security: [data storage and checks](docs/security.md), [vulnerability reporting policy](SECURITY.md).

The full documentation index is in [docs/](docs/README.md).

## License

[GPL-3.0](LICENSE). [Third-party notices](THIRD-PARTY-NOTICES.md).
