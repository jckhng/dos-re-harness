"""Command-line interface for the portable DOS reverse-engineering harness."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .audio import compare_waves, summarize_wave
from .audit import audit_public_tree
from .backend import diagnose
from .capture_summary import (
    build_capture_summary,
    format_capture_summary_line,
    write_capture_summary,
)
from .evidence import write_evidence_manifest
from .frames import write_raw_diff
from .movie import load_movie, scenario_actions
from .mzexplode import unpack_mz
from .project import load_project, load_scenarios, validate_project
from .schema import load_schema
from .screens import ScreenClassifier
from .state import diff_states, load_state, parse_dump_file
from .state_tail import build_state_tail_plan
from .traces import first_trace_difference, load_jsonl
from .write_trace import extract_register_pair_trace


def capture_adapter_replacements(
    adapter: dict[str, object],
    scenario: dict[str, object],
    overrides: list[str],
) -> dict[str, str]:
    configuration = adapter.get("configuration", {})
    if not isinstance(configuration, dict):
        raise ValueError("capture_adapter.configuration must be an object")
    arguments = scenario.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("scenario arguments must be an object")
    replacements = {
        str(key): str(value)
        for source in (configuration, arguments)
        for key, value in source.items()
        if isinstance(value, (str, int, float))
        and not isinstance(value, bool)
    }
    for assignment in overrides:
        key, separator, value = assignment.partition("=")
        if not separator or not key:
            raise ValueError(
                "capture adapter arguments must use NAME=VALUE syntax"
            )
        if key not in replacements:
            raise ValueError(
                f"unknown capture adapter argument {key!r}"
            )
        replacements[key] = value
    return replacements


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


def _emit_json(document: dict[str, object], output: Path | None) -> None:
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(encoded, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")
    print(f"wrote {output}")


def command_inspect_wave(args: argparse.Namespace) -> int:
    _emit_json(summarize_wave(args.wave), args.out)
    return 0


def command_diff_wave(args: argparse.Namespace) -> int:
    result = compare_waves(
        args.expected,
        args.actual,
        mixdown=args.mixdown,
        sample_tolerance=args.sample_tolerance,
        skip_expected_frames=args.skip_expected_frames,
        skip_actual_frames=args.skip_actual_frames,
    )
    _emit_json(result, args.out)
    if not result["formats_compatible"]:
        return 1
    return (
        0
        if int(result["different_samples"]) <= args.max_different_samples
        else 1
    )


def command_extract_write_trace(args: argparse.Namespace) -> int:
    result = extract_register_pair_trace(
        args.capture,
        address_register=args.address_register,
        value_register=args.value_register,
        address_mask=args.address_mask,
        value_mask=args.value_mask,
    )
    _emit_json(result, args.out)
    return 0


def command_audit_tree(args: argparse.Namespace) -> int:
    errors = audit_public_tree(args.root, args.max_file_size)
    for error in errors:
        print(f"ERROR {error}")
    if errors:
        print(f"PUBLIC_TREE_REJECTED errors={len(errors)}")
        return 1
    print(f"PUBLIC_TREE_OK root={args.root.resolve()}")
    return 0


def command_unpack_mz(args: argparse.Namespace) -> int:
    manifest_path = unpack_mz(
        input_path=args.input,
        output_path=args.output,
        tool=args.tool,
        wsl_distribution=args.wsl_distribution,
        manifest_path=args.manifest,
        force=args.force,
    )
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(
        f"UNPACKED input={document['input']['sha256']} "
        f"output={document['output']['sha256']}"
    )
    print(f"wrote {manifest_path}")
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
    movie_path = args.movie.resolve() if args.movie is not None else None
    input_script_path = (
        args.input_script.resolve()
        if args.input_script is not None
        else None
    )
    if input_script_path is not None and not input_script_path.is_file():
        raise ValueError(f"input script is missing: {input_script_path}")
    actions = (
        list(load_movie(movie_path)["actions"])
        if movie_path is not None
        else scenario_actions(project.root, scenario)
    )
    replacements = {
        "project": str(project.path),
        "project_dir": str(project.root),
        "scenario": args.scenario,
        "out_dir": str(args.out_dir.resolve()),
        "startup_actions": ",".join(actions),
        "input_script": (
            str(input_script_path)
            if input_script_path is not None
            else ""
        ),
        "wait_state": ";".join(scenario.get("wait_state", [])),
    }
    replacements.update(
        capture_adapter_replacements(
            adapter,
            scenario,
            args.adapter_argument,
        )
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
        input_movie_path=movie_path,
        input_script_path=input_script_path,
    )
    print(f"wrote {manifest_path}")
    return exit_code


def _state_tail_capture_cli_args(
    project_path: Path,
    scenario: str,
    output: str,
    movie: Path,
    input_script: Path,
    adapter_arguments: list[str],
) -> list[str]:
    command = [
        "capture",
        str(project_path),
        scenario,
        "--out-dir",
        output,
        "--movie",
        str(movie.resolve()),
        "--input-script",
        str(input_script.resolve()),
    ]
    for argument in adapter_arguments:
        command.extend(["--adapter-argument", argument])
    return command


def command_plan_state_tail(args: argparse.Namespace) -> int:
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
    runtime = project.data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise ValueError("project runtime must be an object")
    dump_size_value = (
        args.dump_size
        if args.dump_size is not None
        else runtime.get("dump_size")
    )
    if not isinstance(dump_size_value, (str, int)):
        raise ValueError("project runtime.dump_size is missing")
    dump_size = (
        int(dump_size_value, 0)
        if isinstance(dump_size_value, str)
        else dump_size_value
    )
    dump_segment = args.dump_segment or runtime.get("dump_segment", "ds")
    if not isinstance(dump_segment, str):
        raise ValueError("project runtime.dump_segment must be a string")
    plan = build_state_tail_plan(
        previous_script=args.previous_input_script,
        current_script=args.input_script,
        snapshot=args.resume_from,
        checkpoint_value=args.checkpoint_value,
        end_value=args.end_value,
        breakpoint=args.breakpoint,
        state_field=args.state_field,
        bootstrap_movie=args.movie,
        capture_out=args.capture_out,
        maximum_hit_margin=args.maximum_hit_margin,
        resume_next_linear=args.resume_next_linear,
        dump_segment=dump_segment,
        dump_offset=args.dump_offset,
        dump_file=args.dump_file,
        dump_size=dump_size,
        transition_breakpoint=args.transition_breakpoint,
        transition_out=args.transition_out,
        allow_existing_capture=args.allow_existing_output,
        allow_existing_transition=args.allow_existing_output,
    )
    adapter = project.data.get("capture_adapter", {})
    if not isinstance(adapter, dict):
        raise ValueError("capture_adapter must be an object")
    scenario = scenarios[args.scenario]
    capture_arguments = plan["capture"]["adapter_arguments"]
    capture_adapter_replacements(adapter, scenario, capture_arguments)
    commands: dict[str, list[str]] = {
        "capture_cli_args": _state_tail_capture_cli_args(
            project.path,
            args.scenario,
            plan["capture"]["output"],
            args.movie,
            args.input_script,
            capture_arguments,
        )
    }
    transition = plan.get("transition")
    if isinstance(transition, dict):
        transition_arguments = transition["adapter_arguments"]
        capture_adapter_replacements(
            adapter,
            scenario,
            transition_arguments,
        )
        commands["transition_cli_args"] = _state_tail_capture_cli_args(
            project.path,
            args.scenario,
            transition["output"],
            args.movie,
            args.input_script,
            transition_arguments,
        )
    plan["project"] = {
        "id": project.data["id"],
        "path": str(project.path),
    }
    plan["scenario"] = args.scenario
    plan["commands"] = commands
    _emit_json(plan, args.out)
    print(
        "STATE_TAIL_PLAN "
        f"first_changed={plan['first_changed_value']} "
        f"resume={plan['capture']['first_value']} "
        f"last={plan['capture']['last_value']} "
        f"values={plan['capture']['value_count']} "
        f"transition={args.transition_breakpoint}",
    )
    return 0


def command_summarize_capture(args: argparse.Namespace) -> int:
    summary = build_capture_summary(args.capture_dir)
    if args.out is not None:
        output = write_capture_summary(args.capture_dir, args.out)
        print(f"wrote {output}")
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(format_capture_summary_line(summary))
    return 0


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

    inspect_wave = subparsers.add_parser(
        "inspect-wave",
        help="Report hash, format, duration, and signal metrics for a PCM WAV.",
    )
    inspect_wave.add_argument("wave", type=Path)
    inspect_wave.add_argument("--out", type=Path)
    inspect_wave.set_defaults(func=command_inspect_wave)

    diff_wave = subparsers.add_parser(
        "diff-wave",
        help="Compare two PCM WAV streams with explicit transforms.",
    )
    diff_wave.add_argument("expected", type=Path)
    diff_wave.add_argument("actual", type=Path)
    diff_wave.add_argument("--mixdown", action="store_true")
    diff_wave.add_argument("--sample-tolerance", type=int, default=0)
    diff_wave.add_argument("--skip-expected-frames", type=int, default=0)
    diff_wave.add_argument("--skip-actual-frames", type=int, default=0)
    diff_wave.add_argument("--max-different-samples", type=int, default=0)
    diff_wave.add_argument("--out", type=Path)
    diff_wave.set_defaults(func=command_diff_wave)

    write_trace = subparsers.add_parser(
        "extract-write-trace",
        help=(
            "Extract a masked register-pair stream from breakpoint_hit-N "
            "capture checkpoints."
        ),
    )
    write_trace.add_argument("capture", type=Path)
    write_trace.add_argument("--address-register", required=True)
    write_trace.add_argument("--value-register", required=True)
    write_trace.add_argument(
        "--address-mask",
        type=lambda value: int(value, 0),
        default=0xFF,
    )
    write_trace.add_argument(
        "--value-mask",
        type=lambda value: int(value, 0),
        default=0xFF,
    )
    write_trace.add_argument("--out", type=Path, required=True)
    write_trace.set_defaults(func=command_extract_write_trace)

    audit = subparsers.add_parser("audit-public-tree")
    audit.add_argument("root", type=Path, nargs="?", default=Path("."))
    audit.add_argument("--max-file-size", type=int, default=1_000_000)
    audit.set_defaults(func=command_audit_tree)

    unpack = subparsers.add_parser(
        "unpack-mz",
        help="Unpack a DOS MZ executable with mzexplode and write hash evidence.",
    )
    unpack.add_argument("input", type=Path)
    unpack.add_argument("output", type=Path)
    unpack.add_argument("--tool", required=True, help="Native or WSL mzexplode path.")
    unpack.add_argument("--wsl-distribution")
    unpack.add_argument("--manifest", type=Path)
    unpack.add_argument("--force", action="store_true")
    unpack.set_defaults(func=command_unpack_mz)

    summarize = subparsers.add_parser(
        "summarize-capture",
        help="Print a compact summary without expanding large capture records.",
    )
    summarize.add_argument("capture_dir", type=Path)
    summarize.add_argument("--json", action="store_true")
    summarize.add_argument("--out", type=Path)
    summarize.set_defaults(func=command_summarize_capture)

    tail = subparsers.add_parser(
        "plan-state-tail",
        help=(
            "Preflight two state-input scripts and emit resumable tail "
            "capture commands without launching the backend."
        ),
    )
    tail.add_argument("project", type=Path)
    tail.add_argument("scenario")
    tail.add_argument("--previous-input-script", type=Path, required=True)
    tail.add_argument("--input-script", type=Path, required=True)
    tail.add_argument("--resume-from", type=Path, required=True)
    tail.add_argument("--checkpoint-value", type=int, required=True)
    tail.add_argument("--end-value", type=int, required=True)
    tail.add_argument("--state-field", required=True)
    tail.add_argument("--breakpoint", required=True)
    tail.add_argument("--resume-next-linear")
    tail.add_argument("--maximum-hit-margin", type=int, default=62)
    tail.add_argument("--movie", type=Path, required=True)
    tail.add_argument("--capture-out", type=Path, required=True)
    tail.add_argument("--transition-breakpoint")
    tail.add_argument("--transition-out", type=Path)
    tail.add_argument("--allow-existing-output", action="store_true")
    tail.add_argument("--dump-segment", choices=("ds", "ss"))
    tail.add_argument("--dump-offset", type=lambda value: int(value, 0), default=0)
    tail.add_argument("--dump-file", default="remote_runtime_ds.bin")
    tail.add_argument("--dump-size", type=lambda value: int(value, 0))
    tail.add_argument("--out", type=Path, required=True)
    tail.set_defaults(func=command_plan_state_tail)

    capture = subparsers.add_parser("capture")
    capture.add_argument("project", type=Path)
    capture.add_argument("scenario")
    capture.add_argument("--out-dir", type=Path, required=True)
    capture.add_argument(
        "--movie",
        type=Path,
        help="Override the scenario input movie and hash the override as evidence.",
    )
    capture.add_argument(
        "--input-script",
        type=Path,
        help=(
            "State-boundary input script passed to the capture adapter and "
            "hashed as evidence."
        ),
    )
    capture.add_argument(
        "--adapter-argument",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help=(
            "Override one configured capture-adapter argument; repeatable. "
            "Only names declared by the adapter or scenario are accepted."
        ),
    )
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
