#!/usr/bin/env python3
"""Verify a directory of bare ring key release assets against the pinned lockfile."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "prover/ring/proving-keys.lock"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--allow-extra",
        action="store_true",
        help="allow other .key files in a preparation directory",
    )
    args = parser.parse_args()
    directory = args.directory.resolve()
    keys = json.loads(LOCK.read_text())["keys"]
    actual = {path.name for path in directory.glob("*.key")}
    expected = set(keys)
    if expected - actual or (actual - expected and not args.allow_extra):
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SystemExit(f"release asset names differ: missing={missing}, extra={extra}")

    for name, entry in sorted(keys.items()):
        path = directory / name
        size = path.stat().st_size
        if size != entry["size"]:
            raise SystemExit(f"{name}: {size} bytes, lockfile pins {entry['size']}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(f"{name}: SHA-256 {digest}, lockfile pins {entry['sha256']}")
    print(f"Verified {len(keys)} bare .key assets against {LOCK.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
