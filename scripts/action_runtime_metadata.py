"""Compare recorded action runtimes (and composite dependencies) with the upstream manifest at each pinned SHA."""

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


def _upstream_runs(uses: str, fetch: Fetcher) -> dict[str, object]:
    for url in manifest_urls(uses):
        text = fetch(url)
        if text is None:
            continue
        data = yaml.safe_load(text)
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict) or "using" not in runs:
            raise ValueError(f"{url}: no runs.using declaration")
        return runs
    raise ValueError(f"{uses}: no action.yml or action.yaml at that SHA")


def upstream_runtime(uses: str, fetch: Fetcher = fetch_text) -> str:
    """Return ``runs.using`` from the upstream manifest for ``uses``."""
    return str(_upstream_runs(uses, fetch)["using"])


def upstream_record(uses: str, fetch: Fetcher = fetch_text) -> dict[str, object]:
    """Return the derived fixture record for ``uses``.

    Composite actions also get ``dependencies``: the external ``uses`` of their
    steps, with the composite's own local ``./path`` steps mapped to
    ``owner/repo/path@sha`` so they can be recorded and checked like any other
    reference. ``docker://`` steps carry no JavaScript runtime and are omitted.
    """
    runs = _upstream_runs(uses, fetch)
    record: dict[str, object] = {"runtime": str(runs["using"])}
    if record["runtime"] != "composite":
        return record
    ref, sha = uses.rsplit("@", 1)
    owner, repo, *_ = ref.split("/")
    dependencies: list[str] = []
    for step in runs.get("steps") or []:
        step_uses = step.get("uses") if isinstance(step, dict) else None
        if not step_uses or step_uses.startswith("docker://"):
            continue
        if step_uses.startswith("./"):
            step_uses = f"{owner}/{repo}/{step_uses[2:].strip('/')}@{sha}"
        if step_uses not in dependencies:
            dependencies.append(step_uses)
    record["dependencies"] = dependencies
    return record


def compare(
    metadata: dict[str, dict[str, object]], fetch: Fetcher = fetch_text
) -> tuple[dict[str, tuple[object, object]], dict[str, dict[str, object]]]:
    """Return (differences, refreshed).

    ``differences`` maps a reference to ``(recorded, upstream)`` for every field the
    upstream manifest derives (``runtime``, and ``dependencies`` for composites)
    whose recorded value differs. ``refreshed`` is the metadata with those fields
    replaced by upstream values and every other field preserved.
    """
    differences: dict[str, tuple[object, object]] = {}
    refreshed: dict[str, dict[str, object]] = {}
    for uses, record in metadata.items():
        derived = upstream_record(uses, fetch)
        refreshed[uses] = {**record, **derived}
        recorded = {field: record.get(field) for field in derived}
        if recorded != derived:
            differences[uses] = (recorded, derived)
    return differences, refreshed


def render_fixture(metadata: dict[str, dict[str, object]]) -> str:
    """Serialize one record per line, matching the checked-in fixture layout."""
    lines = [f"  {json.dumps(uses)}: {json.dumps(record)}" for uses, record in metadata.items()]
    return "{\n" + ",\n".join(lines) + "\n}\n"
