"""Specimen-pinned recovery accounting, separate from verification and playability."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from .evidence import sha256_file


RECOVERY_KINDS = {"unrecovered", "partial", "reconstructed", "stub", "original-fallback"}
REGION_KINDS = {"code", "unknown", "excluded"}
RESULT_STATUS = {"pass": "passing", "fail": "failing", "not_run": "not_run",
                 "unsupported": "unsupported"}


def _keys(value, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        raise ValueError(f"invalid keys: missing={sorted(missing)}, unknown={sorted(extra)}")


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected a nonempty string")
    return value


def _note(value):
    if not isinstance(value, str):
        raise ValueError("expected a string")


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"expected an integer >= {minimum}")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("expected a boolean")
    return value


def _choice(value, choices):
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"expected one of {sorted(choices)}")
    return value


def _list(value):
    if not isinstance(value, list):
        raise ValueError("expected a list")
    return value


def _records(value):
    records = _list(value)
    ids = [_text(row.get("id")) if isinstance(row, dict) else _text(None) for row in records]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate id")
    return sorted(records, key=lambda row: row["id"])


def _freshness(bindings):
    if not bindings or any(row["status"] == "missing" for row in bindings):
        return "missing"
    if any(row["status"] == "stale" for row in bindings):
        return "stale"
    return "current"


def _disjoint(ranges, label):
    previous_end = -1
    for start, end in sorted(ranges):
        if start < previous_end:
            raise ValueError(f"overlap in {label}")
        previous_end = end


def build_report(path: Path) -> dict:
    """Read declarations and check their pinned files; never run or infer acceptance."""
    path = Path(path).resolve()
    inventory_bytes = path.read_bytes()
    document = json.loads(inventory_bytes.decode("utf-8-sig"))
    _keys(document, {"format_version", "id", "specimen", "inventory_complete",
                     "scope_description", "spaces", "regions", "units", "verification",
                     "milestones"}, {"notes"})
    if type(document["format_version"]) is not int or document["format_version"] != 1:
        raise ValueError("unsupported format_version")
    _text(document["id"])
    _text(document["scope_description"])
    _note(document.get("notes", ""))
    declared_complete = _boolean(document["inventory_complete"])
    observed = {}

    def binding(value):
        _keys(value, {"path", "sha256"}, {"bytes"})
        filename = _text(value["path"])
        expected = _text(value["sha256"]).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("sha256 must contain 64 hexadecimal characters")
        if "bytes" in value:
            _integer(value["bytes"])
        resolved = (path.parent / filename).resolve()
        if resolved not in observed:
            observed[resolved] = (
                {"sha256": sha256_file(resolved), "bytes": resolved.stat().st_size}
                if resolved.is_file() else None)
        actual = observed[resolved]
        status = "missing" if actual is None else (
            "current" if actual["sha256"] == expected
            and ("bytes" not in value or value["bytes"] == actual["bytes"]) else "stale")
        return {"path": filename, "sha256": expected, "status": status, "actual": actual}

    def bindings(values):
        return sorted((binding(value) for value in _list(values)),
                      key=lambda row: (row["path"], row["sha256"]))

    specimen = binding(document["specimen"])
    spaces = {}
    artifact_paths = set()
    artifact_hashes = set()
    for row in _records(document["spaces"]):
        _keys(row, {"id", "size", "artifact", "description"})
        size = _integer(row["size"], 1)
        _text(row["description"])
        artifact = binding(row["artifact"])
        resolved = (path.parent / artifact["path"]).resolve()
        if resolved in artifact_paths or artifact["sha256"] in artifact_hashes:
            raise ValueError("address spaces alias the same artifact")
        artifact_paths.add(resolved)
        artifact_hashes.add(artifact["sha256"])
        if artifact["status"] == "current" and artifact["actual"]["bytes"] != size:
            raise ValueError("address space size differs from pinned artifact")
        spaces[row["id"]] = {**row, "artifact": artifact}
    if not spaces:
        raise ValueError("at least one address space is required")

    def interval(value, space):
        if space not in spaces:
            raise ValueError(f"unknown address space {space!r}")
        start, end = _integer(value["start"]), _integer(value["end"], 1)
        if start >= end or end > spaces[space]["size"]:
            raise ValueError("invalid or out-of-bounds range")
        return start, end

    regions = []
    for row in _records(document["regions"]):
        _keys(row, {"id", "space", "start", "end", "kind", "reason"})
        _text(row["space"])
        _choice(row["kind"], REGION_KINDS)
        _note(row["reason"])
        if row["id"].startswith("gap:"):
            raise ValueError("region ids starting with gap: are reserved")
        if row["kind"] != "code":
            _text(row["reason"])
        interval(row, row["space"])
        regions.append({**row, "origin": "explicit"})
    for space, spec in spaces.items():
        ranges = [(r["start"], r["end"]) for r in regions if r["space"] == space]
        _disjoint(ranges, f"regions in {space}")
        cursor = 0
        for start, end in sorted(ranges) + [(spec["size"], spec["size"])]:
            if start > cursor:
                regions.append({"id": f"gap:{space}:{cursor}", "space": space,
                                "start": cursor, "end": start, "kind": "unknown",
                                "reason": "No declared classification", "origin": "implicit"})
            cursor = end
    regions.sort(key=lambda row: (row["space"], row["start"]))

    units = []
    occupied = {space: [] for space in spaces}
    for row in _records(document["units"]):
        _keys(row, {"id", "kind", "space", "ranges", "extent_complete", "recovery",
                    "integrated", "implementation", "evidence", "notes"})
        _choice(row["kind"], {"function", "range"})
        _choice(row["recovery"], RECOVERY_KINDS)
        _boolean(row["extent_complete"])
        _boolean(row["integrated"])
        _note(row["notes"])
        space = _text(row["space"])
        if space not in spaces:
            raise ValueError(f"unknown address space {space!r}")
        size = 0
        for fragment in _list(row["ranges"]):
            _keys(fragment, {"start", "end"})
            start, end = interval(fragment, space)
            if not any(r["space"] == space and r["kind"] == "code"
                       and r["start"] <= start and end <= r["end"] for r in regions):
                raise ValueError("unit range must be contained in a code region")
            occupied[space].append((start, end))
            size += end - start
        implementation, evidence = bindings(row["implementation"]), bindings(row["evidence"])
        if row["recovery"] == "reconstructed" and (
                not row["extent_complete"] or not size or not implementation or not evidence):
            raise ValueError("reconstructed unit requires complete extent and pinned implementation/evidence")
        deps = [specimen, spaces[space]["artifact"], *implementation, *evidence]
        freshness = _freshness(deps)
        credit = size if row["recovery"] == "reconstructed" and freshness == "current" else 0
        units.append({**row, "bytes": size, "implementation": implementation,
                      "evidence": evidence, "binding_status": freshness,
                      "credited_reconstructed_bytes": credit})
    for space, ranges in occupied.items():
        _disjoint(ranges, f"units in {space}")

    scope = sum(s["size"] for s in spaces.values())
    totals = {kind: sum(r["end"] - r["start"] for r in regions if r["kind"] == kind)
              for kind in REGION_KINDS}
    included = scope - totals["excluded"]
    recovered = sum(u["credited_reconstructed_bytes"] for u in units)
    unassigned = totals["code"] - sum(u["bytes"] for u in units)
    functions = [u for u in units if u["kind"] == "function"]
    complete = (declared_complete and totals["unknown"] == 0 and unassigned == 0
                and all(u["extent_complete"] and u["bytes"] for u in units))
    recovery = {
        "inventory_complete": complete, "declared_complete": declared_complete,
        "scope_description": document["scope_description"], "scope_bytes": scope,
        "excluded_bytes": totals["excluded"], "included_bytes": included,
        "known_code_bytes": totals["code"], "unknown_bytes": totals["unknown"],
        "unassigned_code_bytes": unassigned, "reconstructed_bytes": recovered,
        "reconstructed_percent_of_included": round(100 * recovered / included, 4) if included else None,
        "functions": {"identified": len(functions),
                      "known_extent": sum(bool(u["bytes"]) and u["extent_complete"] for u in functions),
                      "reconstructed": sum(u["credited_reconstructed_bytes"] > 0 for u in functions)},
        "range_units": sum(u["kind"] == "range" for u in units),
        "integrated_units": sum(u["integrated"] for u in units),
        "spaces": list(spaces.values()), "regions": regions, "units": units,
    }

    verification = []
    for row in _records(document["verification"]):
        _keys(row, {"id", "scenario", "observable", "execution", "reference", "result",
                    "evidence", "inputs", "notes"})
        _text(row["scenario"])
        _text(row["observable"])
        _choice(row["execution"], {"natural", "controlled", "component"})
        _choice(row["reference"], {"original", "portable"})
        _choice(row["result"], RESULT_STATUS)
        _note(row["notes"])
        evidence, inputs = bindings(row["evidence"]), bindings(row["inputs"])
        deps = [specimen, *evidence, *inputs]
        freshness = _freshness(deps) if evidence and inputs else "missing"
        verification.append({
            **{k: row[k] for k in ("id", "scenario", "observable", "execution", "reference", "notes")},
            "recorded_result": row["result"], "evidence_status": freshness,
            "status": RESULT_STATUS[row["result"]] if freshness == "current" else freshness,
            "bindings": deps,
        })
    checks = {row["id"]: row for row in verification}
    playability = []
    for row in _records(document["milestones"]):
        _keys(row, {"id", "description", "status", "checks"})
        _text(row["description"])
        _choice(row["status"], {"not_implemented", "partial", "implemented"})
        requested = [_text(value) for value in _list(row["checks"])]
        if len(requested) != len(set(requested)) or any(value not in checks for value in requested):
            raise ValueError("duplicate or unknown milestone check")
        satisfied = row["status"] == "implemented" and bool(requested) and all(
            checks[value]["status"] == "passing" and checks[value]["execution"] == "natural"
            for value in requested)
        playability.append({"id": row["id"], "description": row["description"],
                            "declared_status": row["status"], "checks": sorted(requested),
                            "satisfied": satisfied})
    return {"format_version": 1, "id": document["id"],
            "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            "specimen": specimen, "recovery": recovery, "verification": verification,
            "playability": playability, "notes": document.get("notes", "")}


def format_markdown(report: dict) -> str:
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")

    recovery = report["recovery"]
    lines = [f"# Progress: {cell(report['id'])}", "", "## Recovery", "",
             f"Inventory complete: **{str(recovery['inventory_complete']).lower()}**. "
             f"Specimen binding: **{report['specimen']['status']}**.", "",
             cell(recovery["scope_description"]), "", "| Measure | Count |", "| --- | ---: |"]
    for name in ("scope_bytes", "excluded_bytes", "included_bytes", "known_code_bytes",
                 "unknown_bytes", "unassigned_code_bytes", "reconstructed_bytes"):
        lines.append(f"| {name.replace('_', ' ')} | {recovery[name]} |")
    lines += ["", f"Functions in this inventory: {recovery['functions']['identified']}; "
              f"complete extents: {recovery['functions']['known_extent']}; "
              f"currently reconstructed: {recovery['functions']['reconstructed']}.", "",
              "Byte coverage is limited to the declared scope; it is not percent faithful or tasks complete.",
              "", "## Verification", "", "| Scenario / observable | Recorded | Evidence | Status |",
              "| --- | --- | --- | --- |"]
    for row in report["verification"]:
        lines.append(f"| {cell(row['scenario'])} / {cell(row['observable'])} | "
                     f"{row['recorded_result']} | {row['evidence_status']} | {row['status']} |")
    lines += ["", "Freshness checks only declared file bindings; it does not rerun checks or traverse manifests.",
              "", "## Natural playability", "", "| Milestone | Implementation | Supported by current natural checks |",
              "| --- | --- | --- |"]
    for row in report["playability"]:
        lines.append(f"| {cell(row['description'])} | {row['declared_status']} | {str(row['satisfied']).lower()} |")
    lines += ["", cell(report["notes"]), ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.out and args.out.resolve() == args.inventory.resolve():
            raise ValueError("output must not replace the inventory")
        report = build_report(args.inventory)
        if args.out:
            pending = [report]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if "path" in value and "sha256" in value:
                        bound = (args.inventory.resolve().parent / value["path"]).resolve()
                        if args.out.resolve() == bound or (
                                args.out.exists() and bound.exists() and args.out.samefile(bound)):
                            raise ValueError("output must not replace a bound input")
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
        encoded = (format_markdown(report) if args.format == "markdown" else
                   json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
    except (ValueError, OSError) as error:
        print(f"progress: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
