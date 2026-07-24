"""Command-line interface for the portable DOS reverse-engineering harness."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .audit import audit_public_tree
from .backend import diagnose
from .evidence import write_evidence_manifest
from .frames import write_raw_diff
from .movie import scenario_actions
from .project import load_project, load_scenarios, validate_project
from .schema import load_schema
from .screens import ScreenClassifier
from .state import diff_states, load_state, parse_dump_file
from .traces import first_trace_difference, load_jsonl


def command_validate(args: argparse.Namespace) -> int:
    project = load_project(args.project)
    errors = validate_project(project)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        return 1
    scenarios = load_scenarios(project)
    fields = load_schema(project.referenced_path("runtime.state_schema"))
    print(
        f"VALID project={project.data['id']} "
        f"fields={len(fields)} scenarios={len(scenarios)}"
    )
    return 0


def command_parse_state(args: argparse.Namespace) -> int:
    fields = load_schema(args.schema)
    document = parse_dump_file(args.dump, fields, args.base)
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(encoded, end="")
    return 0


def command_diff_state(args: argparse.Namespace) -> int:
    fields = load_schema(args.schema)
    differences, matches, skipped = diff_states(
        load_state(args.original),
        load_state(args.reimplementation),
        fields,
        args.strict,
    )
    for field, left, right in differences:
        print(f"DIFF {field.name} original={left!r} reimplementation={right!r}")
    print(f"{matches} match, {len(differences)} diff, {skipped} skipped")
    return 1 if differences else 0


def command_classify_screen(args: argparse.Namespace) -> int:
    classifier = ScreenClassifier.load(args.signatures)
    print(classifier.classify(args.frame.read_bytes()))
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    project = load_project(args.project)
    diagnostics = diagnose(project)
    errors = validate_project(project)
    if args.json:
        print(
            json.dumps(
                {
                    "project": project.data["id"],
                    "diagnostics": [item.__dict__ for item in diagnostics],
                    "validation_errors": errors,
                },
                indent=2,
            )
        )
    else:
        for item in diagnostics:
            print(f"{item.status.upper():8} {item.name}: {item.detail}")
        for error in errors:
            print(f"ERROR    project: {error}")
    return 1 if errors or any(item.status == "missing" for item in diagnostics) else 0


def command_diff_trace(args: argparse.Namespace) -> int:
    original = load_jsonl(args.original)
    reimplementation = load_jsonl(args.reimplementation)
    difference = first_trace_difference(original, reimplementation)
    if difference is None:
        print(f"TRACE_MATCH rows={len(original)}")
        return 0
    index, fields = difference
    print(f"TRACE_MISMATCH index={index}")
    for field, values in list(fields.items())[: args.max_fields]:
        print(f"{field}: original={values[0]!r} reimplementation={values[1]!r}")
    return 1


def command_diff_frame(args: argparse.Namespace) -> int:
    result = write_raw_diff(
        args.expected,
        args.actual,
        args.width,
        args.height,
        args.json,
        args.diff,
    )
    print(
        f"diff_pixels={result['diff_pixels']} "
        f"ratio={result['diff_ratio']:.6f} bbox={result['bbox']}"
    )
    return 0 if result["diff_pixels"] <= args.max_diff_pixels else 1


def command_audit_tree(args: argparse.Namespace) -> int:
    errors = audit_public_tree(args.root, args.max_file_size)
    for error in errors:
        print(f"ERROR {error}")
    if errors:
        print(f"PUBLIC_TREE_REJECTED errors={len(errors)}")
        return 1
    print(f"PUBLIC_TREE_OK root={args.root.resolve()}")
    return 0


def command_capture(args: argparse.Namespace) -> int:
    project = load_project(args.project)
    errors = validate_project(project)
    if errors:
        raise ValueError("invalid project: " + "; ".join(errors))
    scenarios = load_scenarios(project)
    if args.scenario not in scenarios:
        raise ValueError(
            f"unknown scenario {args.scenario!r}; "
            f"expected one of {', '.join(sorted(scenarios))}"
        )
    adapter = project.data.get("capture_adapter", {})
    command = adapter.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ValueError("capture_adapter.command must be an argument array")
    scenario = scenarios[args.scenario]
    actions = scenario_actions(project.root, scenario)
    replacements = {
        "project": str(project.path),
        "project_dir": str(project.root),
        "scenario": args.scenario,
        "out_dir": str(args.out_dir.resolve()),
        "startup_actions": ",".join(actions),
        "wait_state": ";".join(scenario.get("wait_state", [])),
    }
    replacements.update(
        {
            str(key): str(value)
            for key, value in scenario.get("arguments", {}).items()
        }
    )
    rendered = [
        part.format_map(replacements)
        for part in command
    ]
    if args.dry_run:
        print(json.dumps(rendered, indent=2))
        return 0
    exit_code = subprocess.run(rendered, check=False).returncode
    manifest_path = write_evidence_manifest(
        project,
        args.scenario,
        args.out_dir.resolve(),
        rendered,
        exit_code,
    )
    print(f"wrote {manifest_path}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-project")
    validate.add_argument("project", type=Path)
    validate.set_defaults(func=command_validate)

    parse = subparsers.add_parser("parse-state")
    parse.add_argument("--schema", type=Path, required=True)
    parse.add_argument("--dump", type=Path, required=True)
    parse.add_argument("--base", type=lambda value: int(value, 0), default=0)
    parse.add_argument("--out", type=Path)
    parse.set_defaults(func=command_parse_state)

    diff = subparsers.add_parser("diff-state")
    diff.add_argument("--schema", type=Path, required=True)
    diff.add_argument("--original", type=Path, required=True)
    diff.add_argument("--reimplementation", type=Path, required=True)
    diff.add_argument("--strict", action="store_true")
    diff.set_defaults(func=command_diff_state)

    classify = subparsers.add_parser("classify-screen")
    classify.add_argument("--signatures", type=Path, required=True)
    classify.add_argument("--frame", type=Path, required=True)
    classify.set_defaults(func=command_classify_screen)

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("project", type=Path)
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=command_doctor)

    trace = subparsers.add_parser("diff-trace")
    trace.add_argument("original", type=Path)
    trace.add_argument("reimplementation", type=Path)
    trace.add_argument("--max-fields", type=int, default=20)
    trace.set_defaults(func=command_diff_trace)

    frame = subparsers.add_parser("diff-frame")
    frame.add_argument("--expected", type=Path, required=True)
    frame.add_argument("--actual", type=Path, required=True)
    frame.add_argument("--width", type=int, required=True)
    frame.add_argument("--height", type=int, required=True)
    frame.add_argument("--json", type=Path)
    frame.add_argument("--diff", type=Path, help="Optional grayscale PGM difference image")
    frame.add_argument("--max-diff-pixels", type=int, default=0)
    frame.set_defaults(func=command_diff_frame)

    audit = subparsers.add_parser("audit-public-tree")
    audit.add_argument("root", type=Path, nargs="?", default=Path("."))
    audit.add_argument("--max-file-size", type=int, default=1_000_000)
    audit.set_defaults(func=command_audit_tree)

    capture = subparsers.add_parser("capture")
    capture.add_argument("project", type=Path)
    capture.add_argument("scenario")
    capture.add_argument("--out-dir", type=Path, required=True)
    capture.add_argument("--dry-run", action="store_true")
    capture.set_defaults(func=command_capture)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
