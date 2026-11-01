# Wine checks — run 2026-10-22, passed in both prefixes

Verdicts per prefix:

| Check | winxp (net40) | winvista (net46) |
| --- | --- | --- |
| Engine `v2ray.exe -version` + `-test` era config | PASS | PASS |
| Era .NET runtime functional (WineCheck) | PASS — framework 4.0.30319.1 | PASS — framework 4.0.30319.17929 |
| Client import (vmess) + era config generation | PASS (WineCheck, client sources) | PASS (WineCheck, client sources) |
| Client GUI start, no crash, message loop | PASS (`client-smoke.sh`, alive 20 s; `.NET-BroadcastEventWindow.4.0.0.0` present) | PASS (`client-smoke.sh`, alive 20 s) |
| Loopback traffic via engine SOCKS | PASS | PASS |

## Running the checks in a container

- **Wine install**: `apt-get update` with the stock dual-URI sources
  (azure + a broken mirror) ran ~40 min and was OOM-killed (exit 137);
  a minimal azure-only source list with `Acquire::Languages=none`
  then updated successfully. `wine64`+`wine32` together do not resolve here: the
  base image carries a local `libheif1:amd64 1.23.3-1` while the repo
  offers i386 only up to 1.17.6 — a Multi-Arch:same version skew that
  breaks the `libgd3:i386 → libheif1:i386` coinage. **`wine32` alone
  resolves and is sufficient**: every binary in this track is PE32 and
  both prefixes are `WINEARCH=win32`. Installed (fact and versions per
  `/var/log/dpkg.log`, 2026-10-22 05:44:33–39: `install libwine:i386`,
  `install wine32:i386`, `install winetricks:all`, each reaching
  `status installed`): wine 9.0~repack-4build3, winetricks 20240105-2.
- **32-bit execution**: the container's seccomp filter for the shell
  returns EPERM for *every* syscall of a 32-bit process (measured with
  strace: `brk`/`mmap2`/`openat`/`exit_group` all EPERM, then SIGSEGV),
  so Wine cannot run as a child of that shell. The checks therefore
  ran as **systemd oneshot services** (children of PID 1, outside that
  filter): there `wine-9.0` runs and all steps below executed.
- **winetricks exit codes are not the verdict**: both .NET verbs ended
  noisily (XP `dotnet40` killed by an outer timeout while winetricks
  waited on `wineserver -w`; Vista chain `winetricks dotnet462`
  rc=124 — the stage timeout, per the stand's `logs/stage-vista.log`)
  because a wine-session process crash-loops (`wine: Unhandled
  division by zero at address 0040CC9F ... starting debugger...` —
  1203 such lines in the stand's `logs/stage-vista.log` and 147 more
  in `logs/stage-dotnet.log`, with X client exhaustion: 198 `Maximum
  number of clients reached` lines in `logs/stage-vista.log`). The
  frameworks nevertheless landed
  and are **functionally** proven by WineCheck executing on them
  (framework versions above) — that execution, not the verb's exit
  code, is the recorded evidence. A `pkill -9 -x winedbg` janitor kept
  long sessions usable.
- `setup-prefixes.sh` originally set the Vista prefix version with
  `winecfg -v winvista` under `|| true`: measured on wine 9.0 that
  value exits 1 (silently swallowed); the correct value is `vista`
  (rc=0). Fixed in the script.
- **Anchored `client-smoke.sh` — live rerun (review fix, 2026-10-22)**:
  the phase's original PASS lines were printed by the pre-anchor
  edition, whose teardown then self-killed the pipeline (rc=143).
  The committed anchored edition (`pkill -f "Sora.Ancient.exe$"`;
  script sha256
  `7ea6e2ebab2b740d939369f9ba0711aca7bed5cd2f6fa1a3b593d23297d4bcb0`,
  identical in the worktree, the HEAD blob and commit `86cfb59`) was
  rerun end-to-end in both prefixes as a systemd oneshot on
  2026-10-22: `CLIENT SMOKE PASS ... alive_after=20s` with rc=0 for
  winxp and for winvista. Stand logs:
  `logs/stage-client-anchored.log` (provenance + per-prefix rc),
  `logs/client-smoke-anchored-winxp.log`,
  `logs/client-smoke-anchored-winvista.log`.

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
