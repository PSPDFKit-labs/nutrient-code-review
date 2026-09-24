#!/usr/bin/env python3
"""Check or refresh scripts/fixtures/action-runtime-metadata.json against upstream manifests.

Each fixture key is an exact owner/repo[/path]@sha reference. This fetches the
action manifest at that SHA from raw.githubusercontent.com and compares runs.using
with the recorded runtime. --check exits 1 on any difference; --write rewrites the
runtime fields and keeps other fields. Needs network access.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from action_runtime_metadata import compare, render_fixture  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--fixture", type=Path, default=ROOT / "scripts/fixtures/action-runtime-metadata.json"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report differences and exit 1 if any")
    mode.add_argument("--write", action="store_true", help="rewrite runtime fields from upstream")
    args = parser.parse_args()

    try:
        metadata = json.loads(args.fixture.read_text())
        differences, refreshed = compare(metadata)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for uses, (recorded, upstream) in differences.items():
        print(f"{uses}: recorded {recorded!r}, upstream {upstream!r}", file=sys.stderr)
    if args.write:
        args.fixture.write_text(render_fixture(refreshed))
        print(f"Updated {len(differences)} of {len(refreshed)} records in {args.fixture}.")
        return 0
    if differences:
        print(f"{len(differences)} of {len(refreshed)} records differ from upstream.", file=sys.stderr)
        return 1
    print(f"All {len(refreshed)} recorded runtimes match upstream manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
