#!/usr/bin/env python3
"""Check that all external actions invoked by a composite use Node 24 or non-JS runtimes."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_runtime_dependencies import find_legacy_runtimes, load_metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", type=Path, default=ROOT / "action.yml")
    parser.add_argument(
        "--metadata",
        type=Path,
        default=ROOT / "scripts/fixtures/action-runtime-metadata.json",
        help="offline exact-SHA runtime metadata fixture",
    )
    args = parser.parse_args()

    errors = find_legacy_runtimes(args.action, load_metadata(args.metadata))
    if errors:
        print("Legacy GitHub Action runtime dependencies found:", file=sys.stderr)
        print(*errors, sep="\n", file=sys.stderr)
        return 1
    print(f"All action runtime dependencies invoked by {args.action} are Node 24-safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
