"""Compare recorded action runtimes with the upstream manifest at each pinned SHA."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

import yaml

RAW_BASE = "https://raw.githubusercontent.com"

Fetcher = Callable[[str], "str | None"]


def manifest_urls(uses: str) -> list[str]:
    """Candidate manifest URLs for an exact ``owner/repo[/path]@sha`` reference."""
    ref, sha = uses.rsplit("@", 1)
    owner, repo, *subpath = ref.split("/")
    base = "/".join([RAW_BASE, owner, repo, sha, *subpath])
    return [f"{base}/action.yml", f"{base}/action.yaml"]


def fetch_text(url: str) -> str | None:
    """Return the body at ``url``, or None when it does not exist."""
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https host
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def upstream_runtime(uses: str, fetch: Fetcher = fetch_text) -> str:
    """Return ``runs.using`` from the upstream manifest for ``uses``."""
    for url in manifest_urls(uses):
        text = fetch(url)
        if text is None:
            continue
        data = yaml.safe_load(text)
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict) or "using" not in runs:
            raise ValueError(f"{url}: no runs.using declaration")
        return str(runs["using"])
    raise ValueError(f"{uses}: no action.yml or action.yaml at that SHA")


def compare(
    metadata: dict[str, dict[str, object]], fetch: Fetcher = fetch_text
) -> tuple[dict[str, tuple[object, str]], dict[str, dict[str, object]]]:
    """Return (differences, refreshed).

    ``differences`` maps a reference to ``(recorded, upstream)`` runtime for every
    mismatch. ``refreshed`` is the metadata with runtimes replaced by upstream
    values and every other field (such as ``dependencies``) preserved.
    """
    differences: dict[str, tuple[object, str]] = {}
    refreshed: dict[str, dict[str, object]] = {}
    for uses, record in metadata.items():
        upstream = upstream_runtime(uses, fetch)
        refreshed[uses] = {**record, "runtime": upstream}
        if record.get("runtime") != upstream:
            differences[uses] = (record.get("runtime"), upstream)
    return differences, refreshed


def render_fixture(metadata: dict[str, dict[str, object]]) -> str:
    """Serialize one record per line, matching the checked-in fixture layout."""
    lines = [f"  {json.dumps(uses)}: {json.dumps(record)}" for uses, record in metadata.items()]
    return "{\n" + ",\n".join(lines) + "\n}\n"
