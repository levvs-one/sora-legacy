# Wine phase — prepared artifacts (run is a separate task)

Wine is **not installed in the build sandbox**, so nothing in this folder
has been executed yet. These scripts are the complete, idempotent
preparation for the Wine phase; their status is "prepared", never
"verified". The Wine phase itself must:

1. Install `wine` + `winetricks` on the runner.
2. `./setup-prefixes.sh` — creates `winxp` / `winvista` prefixes
   (`WINEARCH=win32`) under `$ANCIENT_WINE_ROOT` (default
   `~/.sora-ancient-wine`).
3. `./install-dotnet.sh` — winetricks `dotnet40` into winxp,
   the 4.6 line into winvista (see the modelling-gap note in the script:
   real Vista stops at .NET 4.6; 4.6.1 dropped it).
4. `../stage-engines.sh` — digest-verified engine staging.
5. `./smoke-engine.sh` — `v2ray.exe -version` + `-test` era config in
   both prefixes.
6. `./loopback-test.sh winxp` and `./loopback-test.sh winvista` —
   host HTTP server → engine SOCKS (in prefix) → curl body check.
7. Client run: `wine …/Sora.Ancient.exe` (net40 build in winxp,
   net46 build in winvista), add a vmess link pointing at a host-side
   test server, connect, repeat the loopback check with the system
   proxy step skipped (Wine's HKCU proxy is not the host's).

Exit criteria for the phase: steps 5–7 green in **both** prefixes, with
output pasted into the phase report. Until then, `docs/platforms.md`
keeps the ancient track at "built; runtime — Wine phase / device".
