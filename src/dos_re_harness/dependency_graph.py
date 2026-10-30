"""Transitive evidence freshness and scoped cache identities; no test execution."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import hashlib
import json

from .bindings import inspect_bindings

_STAGES = {"mapped", "specified", "implemented", "integrated", "validated"}
_RESULTS = {"pass", "fail", "not_run", "unsupported"}
_EXECUTIONS = {"component", "controlled", "natural"}


def inspect_graph(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if (not isinstance(document, dict) or set(document) != {"format_version", "artifacts", "records"}
            or type(document["format_version"]) is not int or document["format_version"] != 1):
        raise ValueError("invalid dependency graph version or fields")
    nodes, files = {}, {}
    for field in ("artifacts", "records"):
        if not isinstance(document[field], list):
            raise ValueError(field + " must be a list")
        for node in document[field]:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"] or node["id"] in nodes:
                raise ValueError("graph ids must be nonempty and unique")
            nodes[node["id"]] = node
            if field == "artifacts":
                if set(node) != {"id", "path", "sha256"}:
                    raise ValueError("invalid artifact fields")
                files[node["id"]] = inspect_bindings([dict(path=node["path"], sha256=node["sha256"])], path.parent)[0]
                continue
            if set(node) != {"id", "dependencies", "dependencies_complete", "stage", "execution", "recorded_result", "scope"}:
                raise ValueError("invalid evidence record fields")
            deps = node["dependencies"]
            if (not isinstance(deps, list) or any(not isinstance(item, str) for item in deps)
                    or len(set(deps)) != len(deps) or type(node["dependencies_complete"]) is not bool
                    or node["stage"] not in _STAGES or node["recorded_result"] not in _RESULTS
                    or node["execution"] not in _EXECUTIONS or not isinstance(node["scope"], str) or not node["scope"]):
                raise ValueError("invalid evidence record domain or dependencies")
    complete, visiting = {}, set()

    def visit(identity):
        if identity in complete:
            return complete[identity]
        if identity not in nodes:
            raise ValueError("unknown dependency: " + identity)
        if identity in visiting:
            raise ValueError("cyclic evidence dependencies: " + identity)
        visiting.add(identity)
        node = nodes[identity]
        if identity in files:
            status = files[identity]["status"]
            contract = dict(id=identity, sha256=node["sha256"])
            result = dict(id=identity, freshness=status, file=files[identity])
        else:
            children = [visit(child) for child in node["dependencies"]]
            states = {child["freshness"] for child in children}
            status = next((state for state in ("missing", "stale", "incomplete") if state in states), "current")
            if status == "current" and (not node["dependencies_complete"] or not children):
                status = "incomplete"
            contract = {key: value for key, value in node.items() if key not in ("recorded_result", "dependencies_complete")}
            contract["dependencies"] = [child["fingerprint"] for child in children]
            result = dict(node, freshness=status)
        fingerprint = hashlib.sha256(json.dumps(["dos-re-evidence-v1", contract], sort_keys=True).encode()).hexdigest()
        result.update(fingerprint=fingerprint, cache_key=fingerprint if status == "current" else None)
        complete[identity] = result
        visiting.remove(identity)
        return result

    records = [visit(node["id"]) for node in document["records"]]
    return dict(format_version=1, records=records, artifacts=[dict(id=key, **value) for key, value in files.items()],
                counts=dict(Counter(row["freshness"] for row in records)),
                scope="Declared transitive file identities only; recorded outcomes and stages are not rerun or inferred.")


def command_evidence_status(args) -> int:
    report = inspect_graph(args.graph)
    if args.format == "markdown":
        rows = ["| Record | Stage | Execution | Recorded result | Freshness |", "|---|---|---|---|---|"]
        for row in report["records"]:
            values = [str(row[key]).replace('|', '\\|').replace('\n', ' ') for key in
                      ('id', 'stage', 'execution', 'recorded_result', 'freshness')]
            rows.append('| ' + ' | '.join(values) + ' |')
        text = '\n'.join(rows) + '\n'
    else:
        text = json.dumps(report, indent=2) + '\n'
    if args.out:
        with args.out.open('x', encoding='utf-8') as stream:
            stream.write(text)
    else:
        print(text, end='')
    return 0 if all(row['freshness'] == 'current' for row in report['records']) else 1
