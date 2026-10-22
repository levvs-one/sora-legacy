# Wine phase — EXECUTED 2026-10-22 (WS1-C), exit criteria met in both prefixes

Status: **executed**, not just prepared. Full protocol with verbatim
command output: `LEGACY-FULL-1C-WINE.md` in the programme reports
(`~/workspace/bug-hunt/reports/`). Verdicts per prefix:

| Check | winxp (net40) | winvista (net46) |
| --- | --- | --- |
| Engine `v2ray.exe -version` + `-test` era config | PASS | PASS |
| Era .NET runtime functional (WineCheck) | PASS — framework 4.0.30319.1 | PASS — framework 4.0.30319.17929 |
| Client import (vmess) + era config generation | PASS (WineCheck, client sources) | PASS (WineCheck, client sources) |
| Client GUI start, no crash, message loop | PASS (`client-smoke.sh`, alive 20 s; `.NET-BroadcastEventWindow.4.0.0.0` present) | PASS (`client-smoke.sh`, alive 20 s) |
| Loopback traffic via engine SOCKS | PASS | PASS |

## How the phase had to be run in this sandbox (measured, not assumed)

- **Wine install**: `apt-get update` with the stock dual-URI sources
  (azure + a broken mirror) ran ~40 min and was OOM-killed (exit 137);
  a minimal azure-only source list with `Acquire::Languages=none`
  updated in 18 s. `wine64`+`wine32` together do not resolve here: the
  base image carries a local `libheif1:amd64 1.23.3-1` while the repo
  offers i386 only up to 1.17.6 — a Multi-Arch:same version skew that
  breaks the `libgd3:i386 → libheif1:i386` coinage. **`wine32` alone
  resolves and is sufficient**: every binary in this track is PE32 and
  both prefixes are `WINEARCH=win32`. Installed: wine 9.0~repack-4build3,
  winetricks 20240105-2.
- **32-bit execution**: the agent exec sandbox's seccomp filter returns
  EPERM for *every* syscall of a 32-bit process (measured with strace:
  `brk`/`mmap2`/`openat`/`exit_group` all EPERM, then SIGSEGV), so Wine
  cannot run as a child of the exec shell at all. The phase therefore
  ran as **systemd oneshot services** (children of PID 1, outside that
  filter): there `wine-9.0` runs and all steps below executed.
- **winetricks exit codes are not the verdict**: both .NET verbs ended
  noisily (XP `dotnet40` killed by an outer timeout while winetricks
  waited on `wineserver -w`; Vista chain rc=143) because a wine-session
  process crash-loops (`wine: Unhandled division by zero at address
  0040CC9F ... starting debugger...`, ~126 stuck `winedbg --auto` in
  minutes, X client exhaustion). The frameworks nevertheless landed
  and are **functionally** proven by WineCheck executing on them
  (framework versions above) — that execution, not the verb's exit
  code, is the recorded evidence. A `pkill -9 -x winedbg` janitor kept
  long sessions usable.
- `setup-prefixes.sh` originally set the Vista prefix version with
  `winecfg -v winvista` under `|| true`: measured on wine 9.0 that
  value exits 1 (silently swallowed); the correct value is `vista`
  (rc=0). Fixed in the script.

## Scripts

1. `./setup-prefixes.sh` — creates `winxp` / `winvista` prefixes
   (`WINEARCH=win32`) under `$ANCIENT_WINE_ROOT` (default
   `~/.sora-ancient-wine`) and pins the reported Windows version
   (winxp / vista).
2. `./install-dotnet.sh` — winetricks `dotnet40` into winxp, the 4.6
   line into winvista (modelling gap unchanged: real Vista stops at
   .NET 4.6; winetricks' verb chain goes through 4.6).
3. `../stage-engines.sh` — digest-verified engine staging.
4. `./smoke-engine.sh` — `v2ray.exe -version` + `-test` era config in
   both prefixes.
5. `./loopback-test.sh winxp|winvista` — host HTTP server → engine
   SOCKS (in prefix) → curl body check.
6. `../tools/WineCheck` — the client's UI-free sources (link parser,
   era gate, config builder, store) built for net40/net46 and run in
   the prefixes: proves import + config generation on the era runtime
   itself, which the modal GUI prompt cannot show headlessly.
7. `./client-smoke.sh <prefix> <exe>` — GUI start proof: the client
   process must be alive after the observation window (paired with
   WineCheck for the import/config half of the client criteria).

What Wine does **not** prove (drivers/TAP, real Internet Settings
semantics, performance, the era OSes' own network stacks, pixel-level
GUI rendering) is listed point-by-point in the phase report. The final
gate remains a real XP/Vista/8.0 device run.
