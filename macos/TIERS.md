# macOS tiers below the service floor — TARGET-NOTES

Measured 2026-10-22 on this Linux machine (cross-builds only; nothing
here has run on a Mac — every runtime statement is a Mach-O load
command or a config-`check` result, and says so). Companion to
[README.md](README.md) (the shipped 12.0 service) and
[engines-darwin.lock](engines-darwin.lock) (pins). The main sora
tree's `apple/Legacy/ENGINES.md` is the methodological model; all
pins, builds and verdicts below are this repository's own.

## 0. Toolchain floors (primary sources: go.dev release notes)

| Go line | macOS floor of its binaries | Source |
| --- | --- | --- |
| 1.20 | 10.13 (last line for 10.13/10.14) | go1.20 notes, Ports/Darwin |
| 1.21, 1.22 | 10.15 | go1.20 notes ("Go 1.21 will require macOS 10.15"); go1.23 notes ("Go 1.23 requires macOS 11", announced in the 1.22 notes) |
| 1.23, 1.24 | 11 | go1.23 notes; go1.24 notes ("Go 1.24 is the last release that will run on macOS 11") |
| 1.25+ | 12 | go1.24 notes ("Go 1.25 will require macOS 12 Monterey") |

Toolchains used here, official `go.dev/dl` linux-amd64 archives,
SHA-256 taken from the go.dev download JSON (`?mode=json&include=all`)
and verified against the downloaded archives before use:

| Toolchain | SHA-256 |
| --- | --- |
| go1.24.13 | `1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730` |
| go1.22.12 | `4fa4f869b0f7fc6bb1eb2660e74657fbf04cdd290b5aef905585c86051b34d43` |
| go1.20.14 | `ff445e48af27f93f66bd949ae060d97991c83e11289009d311f25426258f9c44` |

(The go1.20.14 archive happens to be the toolchain already present
on this machine at `~/workspace/go` — its version output and digest
were re-verified against the go.dev JSON, not trusted from disk.)

Mach-O floors below were read by parsing the load commands
(`LC_BUILD_VERSION` / `LC_VERSION_MIN_MACOSX`) of the produced
binaries directly (no `otool` on this machine) — the same method the
original macOS delivery used.

## 1. Tier macOS 11 — daemon attempt: NOT buildable (protocol)

Question: can `core/cmd/sora-core` (`service/darwin`) and
`macos/helper` be built with the last macOS-11 toolchain,
Go 1.24.13, so their Mach-O floor drops from 12.0 to 11.0?

Attempts (scratch copies of the tree, `go` directive lowered to
1.24.0, `GOTOOLCHAIN=local`, darwin/arm64 and darwin/amd64):

1. **As-is.** Fails before any compilation, at module-graph load:
   ```
   go: golang.org/x/sys@v0.48.0 requires go >= 1.26.0 (running go 1.24.13; GOTOOLCHAIN=local)
   ```
   The core's own `go.mod` says `go 1.26.9`, and its pinned
   dependencies declare their own floors: `golang.org/x/sys v0.48.0`
   and `x/net v0.60.0` require Go ≥ 1.26, `github.com/creachadair/jrpc2
   v1.3.5` and `github.com/gopacket/gopacket v1.7.4` require Go ≥ 1.25
   (read from their `go.mod` files and from the errors below).
2. **Coordinated downgrade round 1** (`go get` x/sys v0.30.0,
   x/net v0.35.0, x/crypto v0.33.0, x/text v0.22.0, x/sync v0.11.0,
   grpc v1.71.0, protobuf v1.36.6). The `go get` itself fails:
   ```
   go: github.com/creachadair/jrpc2@v1.3.5: module github.com/creachadair/jrpc2@v1.3.5 requires go >= 1.25.0 (running go 1.24.13; GOTOOLCHAIN=local)
   ```
   i.e. under Go 1.24 the module graph of the current pins cannot
   even be *resolved* — a downgrade has to move every offending pin
   atomically, by hand.
3. **Round 2** (round 1 set + jrpc2 v1.3.1, gopacket v1.6.0). Fails
   identically on the jrpc2 pin's declared floor (the graph load
   precedes the requested downgrade).

Verdict, by attempt: **the macOS 11 daemon tier is not a build
recipe; it is a dependency fork.** Every current pin that matters
(x/*, grpc, jrpc2, gopacket, utls) sits on Go ≥ 1.25/1.26, several
mid-2026 versions have no Go-1.24-era counterpart on their release
lines, and source compatibility after such a downgrade is untested
by construction (the code was written against the new APIs — e.g.
the core itself uses `crypto/mlkem`-era utls). Nobody should claim
an 11.0 daemon for this tree until that fork exists and is tested
as a fork. `Capabilities.serviceAvailable` in the client therefore
stays at 12.0 — it was not edited to match a hope.

What tier 11 *does* get is engines (§3): on macOS 11 an Apple-Silicon
or Intel machine can run mihomo (11.0 arm64 / 10.13 amd64) and the
self-built sing-box of §3 — but with no legacy daemon to drive them,
that is an engine fact, not a service tier. The client (design floor
10.13) launches on 11 and explains exactly this.

## 2. Tier macOS 10.15-limited — daemon attempt: NOT buildable (protocol)

Same attempt with the Go 1.20 line (go1.20.14, `go` directive
lowered to 1.20), as assigned. It fails earlier and more
instructively — on standard-library packages that did not exist in
Go 1.20, named by the compiler (first errors, daemon):

```
google.golang.org/grpc@v1.83.2/balancer/pickfirst/pickfirst.go:24:2: package cmp is not in GOROOT (…/go1.20.14/src/cmp)        [module requires go 1.25]
github.com/refraction-networking/utls@v1.8.2/internal/hkdf/hkdf.go:4:2: package crypto/hkdf is not in GOROOT                     [go 1.24]
github.com/refraction-networking/utls@v1.8.2/handshake_client.go:13:2: package crypto/mlkem is not in GOROOT                   [go 1.24]
golang.org/x/crypto@v0.57.0/sha3/hashes.go:13:2: package crypto/sha3 is not in GOROOT                                          [go 1.26]
google.golang.org/grpc@v1.83.2/attributes/attributes.go:30:2: package iter is not in GOROOT                                     [go 1.25]
logs/slog.go:5:2: package log/slog is not in GOROOT                          ← the core's own code (core/logs)
engine/catalog.go:6:2: package maps is not in GOROOT                        ← the core's own code (core/engine)
engine/catalog.go:7:2: package slices is not in GOROOT                      ← the core's own code (core/engine)
```

The helper fails with the same set (`cmp`, `iter`, `maps`,
`slices`, `crypto/hkdf`, `crypto/mlkem`, `crypto/sha3`,
`log/slog`). Even a hypothetical dependency downgrade cannot fix
the core's own use of `log/slog`/`maps`/`slices` (Go 1.21) under a
Go 1.20 toolchain — and no 10.15-floor toolchain (1.21/1.22 lines
included) reaches the Go ≥ 1.25 floors of the pinned graph (§1),
so the conclusion is toolchain-independent within the tier.

**What "10.15-limited" therefore honestly means for legacy** —
narrower than the main sora tree's Catalina tier, and the
difference is structural, not effort: the main tree's limited mode
runs libbox *inside the app process*; the legacy client has no
in-process engine — its only driver is the daemon, via the helper.
So for legacy, 10.15 is:

- **Engines: real — on Intel.** Upstream sing-box 1.14.3
  `legacy-macos-10.13` (amd64, already pinned), mihomo amd64
  (10.13), and the self-built sing-box 1.11.15 of §3.3 (amd64,
  honest floor 10.15). On Apple Silicon this tier does not exist
  and cannot: no arm64 Mac ever ran 10.15 (the first is Big Sur),
  and the arm64 build of §3.3 duly declares an 11.0 floor. Any
  "10.15 arm64" claim, from anyone, is a category error.
- **Configs: real, with a mandatory translation.** The 1.11.15
  binary rejects the current render format (`dns.servers[0].path:
  unknown field` — 0/12 on the untranslated corpus). After the
  mechanical DNS translation of the main tree's method (legacy
  `address` strings + `dns.fakeip` block, `route.default_domain_resolver`
  dropped) the same corpus passes **11/12**; the single refusal is
  AmneziaWG (`endpoints[0].h1: unknown field`) — an lx-fork feature,
  gated out of this tier, never silently degraded. Also gated out
  on 1.11.15 (measured in the main tree's delta table and not
  re-claimed here): AnyTLS, XHTTP, TLS `fragment`, ECH
  `query_server_name`. The legacy core's renderer does not perform
  the DNS translation today — the corpus files are the main tree's
  translated set — so a 10.15 *session* is not wired; see next point.
- **Service / connect path: not wired.** No daemon (§ above), no
  in-process engine in the legacy client, and the client's
  system-proxy mode points at the daemon's loopback proxy — there
  is no daemon. A standalone sing-box process with a `mixed`
  inbound plus a manually-set system proxy would work as an OS
  fact, but no code in this tree drives it, so it is **not**
  presented as a mode. The AppKit client on 10.15 launches
  (design floor 10.13) and explains; TUN is out of the question
  for this tier by construction (no root daemon).

## 3. Self-built sing-box for darwin — the Apple Silicon gap, closed for engines

### 3.1 Why not the service pin 1.14.3

- Its `go.mod` requires **Go 1.25.5**; the attempt with Go 1.24.13
  fails verbatim: `go: go.mod requires go >= 1.25.5 (running go
  1.24.13; GOTOOLCHAIN=local)`. Go ≥ 1.25 binaries have a macOS 12
  floor (§0) — the very thing this tier must get below.
- Upstream's own `legacy-macos-10.13` asset shows the only other
  route: `.github/setup_go_for_macos1013.sh` in the 1.14.3 tree
  patches a Go 1.26.8 toolchain (reverting the linker's 12.0
  min-version and an x509 chain change) and builds with
  `CGO_ENABLED=1` so the **Apple external linker** stamps
  `MACOSX_DEPLOYMENT_TARGET` — a build that runs on a Mac, for a
  binary whose runtime was never designed for 10.13. It is also
  published for amd64 only. Neither reproducible here nor
  available for arm64; recorded, not imitated.

### 3.2 Tier-11 engine: sing-box 1.13.21, self-built (darwin arm64 + amd64)

Why this version: it is the newest upstream release that is both
(a) honestly accepted by the core catalog (MinVersion 1.12.0) and
(b) actually buildable by the macOS-11 toolchain — two properties
that had to be measured separately, because the first candidate
failed the second in an instructive way:

- With its release tag set (`release/DEFAULT_BUILD_TAGS_OTHERS`,
  which includes `with_tailscale`), Go 1.24.13 fails in the pinned
  Tailscale fork `github.com/sagernet/tailscale
  v1.92.4-sing-box-1.13-mod.10`: ten
  `undefined: reflect.TypeAssert` errors in
  `internal/godown/github.com/go-json-experiment/json`
  (`arshal_funcs.go`, `arshal_inlined.go`, `arshal_methods.go`).
  `reflect.TypeAssert` is a Go 1.25 API — and indeed upstream's
  own 1.13.21 binaries report `Environment: go1.25.12` in
  `sing-box version`: upstream builds this branch with Go 1.25
  despite the `go 1.24.7` line in its go.mod.
- The fork alternative, sing-box-lx `v1.13.13-lx.15` (the main
  tree's tier-1 pin for libbox), was also attempted and rejected
  on facts, not taste: its GitHub archive tree cannot build the
  CLI at all here (the Tailscale fork's replace directive points
  at a git submodule, `submodules/wireguard-go`, that release
  archives do not contain — the build dies reading its go.mod),
  and the lx CLI release tag sets do not include `with_xhttp` /
  `with_awg` (only the fork's libbox build adds them), so an lx
  CLI from the archive would be an older upstream with its two
  features compiled out.
- Dropping the single tag `with_tailscale` removes the only
  Go-1.25-API consumer in the graph. The core catalog makes no
  Tailscale claim for sing-box and no plan in this tree names a
  Tailscale outbound, so engine selection is unaffected; the
  omission is nevertheless a real difference from the upstream
  binary and is stated in the pin (§3.4) and the recipe.

Result (recipe: [build-singbox-darwin.sh](build-singbox-darwin.sh)):

| Build | Result | Mach-O floor (LC_BUILD_VERSION) |
| --- | --- | --- |
| darwin/arm64 | exit 0 | **11.0** |
| darwin/amd64 | exit 0 | **11.0** |
| linux/amd64 (same source/toolchain/tags, for `check`) | exit 0 | — |

Config corpus, run with the linux build of this very source and
tag set against the shared 12-config corpus (the main tree's
renders for the 1.14 pin): **11/12 PASS**. The single refusal is
`amneziaWG.json` — `endpoints[0].h1: json: unknown field "h1"`:
AmneziaWG is an lx-fork feature, upstream sing-box has no such
fields at any version in this tier, and the catalog only ever
claims it for lx builds ≥ 1.14.3 — consistent, gated, not a
surprise. Everything else passes, including REALITY/Vision,
Hysteria2 (port hopping + salamander), TUIC, AnyTLS, ECH with
`query_server_name` (a 1.13 feature — present here), TLS
fragmentation and WireGuard endpoints. The identical corpus run
against upstream's own linux-amd64 1.13.21 binary gives the same
11/12, so the self-build is behaviourally the pinned version,
not a variant.

### 3.3 Catalina engine: sing-box 1.11.15, self-built (darwin amd64; arm64 measured)

First, a correction the attempt forced: 1.11.15 does **not** build
with the Go 1.20 line, despite its `go.mod` saying `go 1.20` (the
main tree's ENGINES.md §8 already flagged this as unverified; it is
now measured). With go1.20.14 the build fails in its pinned
QUIC fork:

```
github.com/sagernet/quic-go@v0.49.0-beta.1/internal/qtls_ech/go_oldversion.go:5:13: cannot use "ECH can't be built using outdated Go versions." (untyped string constant) as int value in variable declaration
```

That file is a deliberate guard (`//go:build !go1.21`): the fork's
ECH stack needs Go ≥ 1.21. The build therefore uses **Go 1.22.12**
— the last patch of the last Go line whose floor is still 10.15
(§0) — which changes nothing about the tier's floor and is the
maximal toolchain the tier allows.

Result (same recipe):

| Build (Go 1.22.12) | Result | Mach-O floor |
| --- | --- | --- |
| darwin/amd64 | exit 0 | load command **10.13**, honest floor **10.15** (the Go 1.22 runtime requires 10.15, §0 — the stamp is the linker's, the floor is the runtime's; the tier target is 10.15, so nothing is lost, but this binary must not be sold as a 10.13/10.14 engine) |
| darwin/arm64 | exit 0 | **11.0** (no arm64 Mac predates Big Sur — see §2) |
| linux/amd64 (for `check`) | exit 0 | — |

Config corpus with the linux build of this source/toolchain/tags:
the DNS-translated corpus passes **11/12** (the refusal is again
AmneziaWG's `h1`); the untranslated corpus passes **0/12** — every
file dies on `dns.servers[0].path`. Both numbers are identical to
the runs against upstream's own linux-amd64 1.11.15 binary, which
were re-run here as a control.

### 3.4 Digests and reproducibility

The self-builds are deterministic (`-trimpath`, `-buildid=`, fixed
version stamp, pinned toolchain + sources): for both pins a
second arm64 build is **byte-identical** to the first (`cmp`
clean, equal SHA-256). The produced binaries' SHA-256:

| Binary | SHA-256 |
| --- | --- |
| sing-box 1.13.21 (no-tailscale tags) darwin/arm64 | `7434c00fc5edfd9e56512f733d75d39bc6b0a8298fc1cf7af7779d13d618f35b` |
| sing-box 1.13.21 (no-tailscale tags) darwin/amd64 | `7996de37a7faf96b93c5d9c8348e056550d06f2ae3619333333ed166be396a32` |
| sing-box 1.11.15 darwin/arm64 (floor 11.0) | `6220cf5facb14d8d43fa51901fb6e61110b1f2e0f8bec80809a426f3a2669aac` |
| sing-box 1.11.15 darwin/amd64 (floor 10.15) | `ca9dd6b0d32ee3ef99ba80acd9a4d20664dd5fe6d82aacac9dafc518e1a7ccbc` |

These digests are also recorded additively in
[engines-darwin.lock](engines-darwin.lock) as `sing-box-selfbuilt`
lines (the digest of the raw Mach-O binary, not of an archive —
there is no archive; [build-singbox-darwin.sh](build-singbox-darwin.sh)
is the recipe, and re-running it is the verification). Source
archives, measured here and identical to the main tree's
independent measurement in `apple/Legacy/ENGINES.md` §7:

| Source | SHA-256 |
| --- | --- |
| sing-box v1.14.3 (attempted, §3.1) | `9a8e3712a5f611ad95f1d16874bbdcdffbd3b8eed16dae2d71ce7042a33c3386` |
| sing-box v1.13.21 | `c994018d7c2a8fc9fcf6080e4b9cc4f2f915e755342238b77e46fc0806fe96db` |
| sing-box v1.11.15 | `97d58dd873d7cf9b5e4b4aca5516568f3b2e6f5c3dbc93241c82fff5e4a609fd` |

### 3.5 What the self-builds do NOT fix (gates, stated once)

- The sing-box-1.14-only fields — `hop_interval_max`, `bbr_profile`,
  Hysteria2 obfs `gecko` — are gated by the catalog
 : on the §3.2/§3.3 self-built engines
  (1.13.21/1.11.15) plans setting them are refused by SelectEngine
  by name, not at engine config load. They are listed here as tier
  gates.
- On the §3.2 engine additionally: no Tailscale outbound (tag
  dropped, §3.2 — no catalog claim exists for it), no AmneziaWG
  and no XHTTP (upstream sing-box features that do not exist;
  the catalog claims both only for lx builds, correctly).
  On the §3.3 engine additionally: no AnyTLS, no XHTTP, no TLS
  `fragment`, no ECH `query_server_name` (all post-1.11 — the
  main tree's delta table, re-verified here only where the
  corpus touches it).
- Xray remains 12.0 on every tier below 12 (its own Mach-O floor) —
  on macOS 11 / 10.15, plans only sing-box and mihomo can carry are
  the reachable ones, subject to their gates.

## 4. Client divergence by tier (no client code was changed)

| System | Client (design floor 10.13) | Service | Engines that launch |
| --- | --- | --- | --- |
| 12+ | full | daemon 12.0 (shipped) | all pinned (sing-box arm64 only ≥ 26 for the upstream 1.14.3 build; the §3.2 self-build also runs here) |
| 11 | launches, explains | **none** (§1) | self-built sing-box 1.13.21 §3.2 (both arch), mihomo (11.0 arm64 / 10.13 amd64); the §3.3 arm64 build also launches here (floor 11.0) but is not the tier pin |
| 10.15 | launches, explains | **none** (§2) | self-built sing-box 1.11.15 **amd64 only**, upstream legacy sing-box amd64, mihomo amd64 — Intel only; the tier does not exist on Apple Silicon |
| 10.13–10.14 | launches, explains | none | upstream legacy sing-box amd64 (10.13), mihomo amd64 (10.13); the §3.3 binary's honest floor is 10.15 (its load command says 10.13 — §3.3 explains why the stamp does not extend the tier), so it does **not** extend to 10.13/10.14 |

## 5. Verify-on-mac (added items)

1. Run each self-built binary on the oldest real system of its
   tier (`sing-box version`, then `sing-box check` on a tier
   corpus config, then a real mixed-inbound session): a Mach-O
   floor is a launch promise, not a runtime test.
2. Tier 11: a plan carried by the self-built sing-box through any
   driver the owner chooses (there is no legacy daemon for it —
   §1); record which driver was used, do not back-port the claim
   to the client.
3. Tier 10.15: `sing-box check` via the self-built 1.11.15 on the
   translated corpus on real hardware (here: the linux build of
   the same source/toolchain/tags — §3.3).
