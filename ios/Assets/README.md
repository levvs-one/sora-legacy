# Assets — iOS client

## AppIcon.appiconset

- Source artwork: `docs/images/logo-512.png` of the repository root (black Sora mark on transparency, 512×512), composited onto the design light surface `#FFFFFF`, following the recipe of the main sora tree's `apple/Assets`.
- 15 entries: iPhone (20/29/40/60 pt), iPad (20/29/40/76/83.5 pt), plus the 1024×1024 marketing icon.
- Verify any time: `python3 verify_icons.py` — checks every PNG's real pixel size against `Contents.json`.
- **Honest limit:** the master is 512 px, so the 1024 px files are Lanczos **upscales** — correct dimensions, no extra detail.
- **Verify-on-mac:** the catalog is wired into `project.yml` and `project-ios12.yml` (`ASSETCATALOG_COMPILER_APPICON_NAME`), but no Xcode build has compiled it from this environment; compiling the catalog and checking the icon on a device is Mac work.
