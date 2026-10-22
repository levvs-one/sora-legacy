# Assets — macOS client

## AppIcon.appiconset

- Source artwork: `docs/images/logo-512.png` of the repository root (black Sora mark on transparency, 512×512), composited onto the design light surface `#FFFFFF`, following the recipe of the main sora tree's `apple/Assets`.
- 10 entries: macOS 16/32/128/256/512 pt at 1x and 2x.
- Verify any time: `python3 verify_icons.py` — checks every PNG's real pixel size against `Contents.json`.
- **Honest limit:** the master is 512 px, so the 1024 px file (`Icon-512x512@2x.png`) is a Lanczos **upscale** — correct dimensions, no extra detail.
- **Verify-on-mac:** the catalog is wired into `project.yml` (`ASSETCATALOG_COMPILER_APPICON_NAME`), but no Xcode build has compiled it from this environment; compiling the catalog and checking the icon in Finder/Dock is Mac work.
