#!/usr/bin/env python3
"""Sync-check: payload engine pins vs the core catalog floors.

Two version sources must never drift apart silently:

- packaging/engines/engines.lock — the payload builds the packages
  ship (one line per engine and architecture; the version lives in
  the download URL);
- core/engine/catalog.go — the Catalog MinVersion floor the core
  enforces when it accepts an installed engine.

Rule: for every engine, the payload version must be >= the catalog
floor, compared semantically (numeric tuples, never strings:
"1.9.0" < "1.12.0"). All architectures of one engine must pin the
same version. An engine missing on either side is a failure.

Run from anywhere; paths resolve relative to this script. Exit 0
with one OK line per engine on success; exit 1 with the drift named
on failure.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "packaging" / "engines" / "engines.lock"
CATALOG = ROOT / "core" / "engine" / "catalog.go"

KIND_TO_ENGINE = {
    "KindMihomo": "mihomo",
    "KindSingBox": "sing-box",
    "KindXray": "xray",
}


def fail(message):
    print(f"check-engine-pins: {message}", file=sys.stderr)
    sys.exit(1)


def parse_version(text):
    return tuple(int(part) for part in text.split("."))


def payload_versions():
    versions = {}
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        engine, url = fields[0], fields[-1]
        match = re.search(r"/download/v?(\d+\.\d+\.\d+)/", url)
        if not match:
            fail(f"engines.lock: no version in the URL for {engine}: {url}")
        versions.setdefault(engine, set()).add(match.group(1))
    result = {}
    for engine, found in versions.items():
        if len(found) != 1:
            fail(
                f"engines.lock: {engine} pins differ per architecture: "
                f"{sorted(found)}"
            )
        result[engine] = found.pop()
    return result


def catalog_floors():
    text = CATALOG.read_text(encoding="utf-8")
    floors = {}
    for kind, engine in KIND_TO_ENGINE.items():
        start = text.find(kind + ": {")
        if start < 0:
            fail(f"catalog.go: catalog entry {kind} not found")
        match = re.search(r'MinVersion:\s*"(\d+\.\d+\.\d+)"', text[start:])
        if not match:
            fail(f"catalog.go: {kind} has no MinVersion")
        floors[engine] = match.group(1)
    return floors


def main():
    payload = payload_versions()
    floors = catalog_floors()
    for engine in sorted(set(payload) | set(floors)):
        if engine not in payload:
            fail(f"{engine}: in the catalog but not in engines.lock")
        if engine not in floors:
            fail(f"{engine}: in engines.lock but not in the catalog")
        if parse_version(payload[engine]) < parse_version(floors[engine]):
            fail(
                f"{engine}: payload {payload[engine]} is below the "
                f"catalog floor {floors[engine]}"
            )
        print(f"{engine}: payload {payload[engine]} >= catalog floor {floors[engine]}")
    print("check-engine-pins: payload pins and catalog floors are in sync")


if __name__ == "__main__":
    main()
