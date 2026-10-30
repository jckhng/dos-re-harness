"""One-shot command receipts; execution success is not fidelity qualification."""
from __future__ import annotations

from pathlib import Path
import json
import math
import os
import shutil
import subprocess
import time

from .bindings import binding_paths, inspect_bindings
from .evidence import sha256_file
from .host_profile import environment_key, expand_value, load_host_profile, validate_environment


def _merge_bindings(bindings, base):
    merged = {}
    for item in bindings:
        resolved, identity = binding_paths([item], base)[0]
        if resolved in merged and merged[resolved]["sha256"] != identity:
            raise ValueError("conflicting input bindings: " + str(resolved))
        merged[resolved] = dict(path=str(resolved), sha256=identity)
    return list(merged.values())


def load_run_plan(path: Path, *, job: str | None = None, host_profile: Path | None = None) -> dict:
    path = path.resolve()
    plan = json.loads(path.read_text(encoding="utf-8-sig"))
    common = {"command", "cwd", "environment", "inputs", "timeout_seconds", "dependencies_complete"}
    version = plan.get("format_version") if isinstance(plan, dict) else None
    if type(version) is not int or version not in (1, 2):
        raise ValueError("invalid run-plan version or fields")
    groups, expected = {}, None
    if version == 1:
        if set(plan) - (common | {"format_version"}) or job is not None:
            raise ValueError("invalid version 1 run-plan fields or job")
        selected = plan
    else:
        if set(plan) - {"format_version", "jobs", "input_groups"}:
            raise ValueError("invalid version 2 run-plan fields")
        jobs = plan.get("jobs")
        if not isinstance(jobs, dict) or not jobs or any(not isinstance(k, str) or not k or not isinstance(v, dict) for k, v in jobs.items()):
            raise ValueError("jobs must be a nonempty named object")
        if job not in jobs:
            raise ValueError("choose a declared --job")
        selected = jobs[job]
        if set(selected) - (common | {"unset_environment", "input_groups", "expected_exit_code", "expected_stdout", "expected_stderr"}):
            raise ValueError("invalid job fields")
        groups = plan.get("input_groups", {})
        if not isinstance(groups, dict) or any(not isinstance(k, str) or not k for k in groups):
            raise ValueError("input_groups must be a named object")
        for bindings in groups.values():
            binding_paths(bindings, path.parent)
        expected = dict(exit_code=selected.get("expected_exit_code", 0),
                        stdout=selected.get("expected_stdout", []), stderr=selected.get("expected_stderr", []))
        if type(expected["exit_code"]) is not int or any(
                not isinstance(expected[k], list) or any(not isinstance(v, str) or not v for v in expected[k])
                for k in ("stdout", "stderr")):
            raise ValueError("invalid job expectations")
    profile = load_host_profile(host_profile)
    scope = dict(profile["values"], plan_dir=str(path.parent))
    expand = (lambda value: expand_value(value, scope)) if version == 2 or host_profile is not None else (lambda value: value)
    plan = selected
    command = plan.get("command")
    if not isinstance(command, list) or not command or any(not isinstance(v, str) or not v or "\0" in v for v in command):
        raise ValueError("command must be a nonempty argument array")
    command = [expand(v) for v in command]
    command = [*profile["tools"].get(command[0], [command[0]]), *command[1:]]
    cwd = plan.get("cwd", ".")
    if not isinstance(cwd, str) or not cwd:
        raise ValueError("cwd must be a path")
    cwd = (path.parent / expand(cwd)).resolve()
    if not cwd.is_dir():
        raise ValueError("cwd is not a directory")
    environment = plan.get("environment", {})
    unset = plan.get("unset_environment", [])
    validate_environment(environment, unset)
    layered = {environment_key(k): v for k, v in profile["environment"].items()}
    removed = {environment_key(k) for k in profile["unset_environment"]}
    for key in unset:
        key = environment_key(key)
        layered.pop(key, None)
        removed.add(key)
    for key, value in environment.items():
        key = environment_key(key)
        removed.discard(key)
        layered[key] = expand(value)
    timeout = plan.get("timeout_seconds", 120)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    complete = plan.get("dependencies_complete", False)
    if type(complete) is not bool:
        raise ValueError("dependencies_complete must be boolean")
    binding_paths(plan.get("inputs", []), path.parent)
    inputs = list(plan.get("inputs", []))
    selected_groups = plan.get("input_groups", [])
    if not isinstance(selected_groups, list) or any(not isinstance(k, str) or k not in groups for k in selected_groups):
        raise ValueError("job references an unknown input group")
    for name in selected_groups:
        inputs.extend(groups[name])
    inputs = _merge_bindings(inputs, path.parent)
    if profile["binding"]:
        inputs = _merge_bindings([*inputs, profile["binding"]], path.parent)
    result = dict(command=command, cwd=cwd, environment=layered, unset_environment=sorted(removed), inputs=inputs,
                  timeout_seconds=timeout, dependencies_complete=complete,
                  base=path.parent, plan_path=path, plan_sha256=sha256_file(path))
    if version == 2:
        result.update(job=job, expectations=expected)
    return result


def run_command(command: list[str], *, cwd: Path, out_dir: Path,
                environment: dict[str, str] | None = None, inputs: list[dict] | None = None,
                base: Path | None = None, timeout_seconds: float = 120,
                dependencies_complete: bool = False, unset_environment: list[str] | None = None) -> dict:
    if not command or any(not isinstance(arg, str) or not arg for arg in command):
        raise ValueError("command must be a nonempty argument array")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be finite and positive")
    if type(dependencies_complete) is not bool:
        raise ValueError("dependencies_complete must be boolean")
    environment = {} if environment is None else environment
    unset_environment = [] if unset_environment is None else unset_environment
    validate_environment(environment, unset_environment)
    cwd, out_dir = cwd.resolve(), out_dir.resolve()
    if not cwd.is_dir() or out_dir.exists():
        raise ValueError("cwd must exist and output must be fresh")
    started = time.perf_counter()
    before = inspect_bindings(inputs or [], base or cwd)
    if any(Path(row["path"]) == out_dir or out_dir in Path(row["path"]).parents for row in before):
        raise ValueError("output cannot contain a bound input")
    env = {environment_key(k): v for k, v in os.environ.items()}
    for key in unset_environment:
        env.pop(environment_key(key), None)
    env.update({environment_key(k): v for k, v in environment.items()})
    tool = shutil.which(command[0], path=env.get("PATH"))
    if tool is None and (cwd / command[0]).is_file():
        tool = str((cwd / command[0]).resolve())
    tool_hash = sha256_file(Path(tool)) if tool and Path(tool).is_file() else None
    executed_command = [str(Path(tool).resolve()), *command[1:]] if tool else command
    preflight_seconds = time.perf_counter() - started
    out_dir.mkdir(parents=True)
    status, exit_code, error = "preflight_failed", None, None
    executed = time.perf_counter()
    with (out_dir / "stdout.log").open("xb") as stdout, (out_dir / "stderr.log").open("xb") as stderr:
        if all(row["status"] == "current" for row in before):
            try:
                result = subprocess.run(executed_command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, timeout=timeout_seconds)
                exit_code = result.returncode
                status = "success" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired as exc:
                status, error = "timeout", str(exc)
            except OSError as exc:
                status, error = "launch_error", str(exc)
            except KeyboardInterrupt:
                status, error = "interrupted", "KeyboardInterrupt; command not retried"
    execution_seconds = time.perf_counter() - executed
    after = inspect_bindings(inputs or [], base or cwd)
    inputs_unchanged = before == after
    receipt = dict(format_version=1, status=status, command=executed_command, requested_command=command, cwd=str(cwd),
        environment=environment, unset_environment=unset_environment, tool=dict(path=tool, sha256=tool_hash),
        exit_code=exit_code, error=error, timeout_seconds=timeout_seconds,
        dependencies_complete=dependencies_complete, inputs_before=before, inputs_after=after,
        inputs_unchanged=inputs_unchanged,
        cache_eligible=status == "success" and inputs_unchanged and dependencies_complete and bool(before),
        qualification="execution-only; declared file identities, no behavioral or transitive-dependency proof",
        timings=dict(preflight_seconds=preflight_seconds, execution_seconds=execution_seconds,
                     total_seconds=time.perf_counter()-started),
        outputs={name: sha256_file(out_dir / name) for name in ("stdout.log", "stderr.log")})
    (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def command_run_plan(args) -> int:
    plan = load_run_plan(args.plan, job=getattr(args, "job", None), host_profile=getattr(args, "host_profile", None))
    if args.dry_run:
        output = {key: str(value) if isinstance(value, Path) else value for key, value in plan.items()}
        output["preflight"] = inspect_bindings(plan["inputs"], plan["base"])
        print(json.dumps(output, indent=2))
        return 0 if all(row["status"] == "current" for row in output["preflight"]) else 1
    path, identity = plan.pop("plan_path"), plan.pop("plan_sha256")
    name, expected = plan.pop("job", None), plan.pop("expectations", None)
    plan["inputs"] = _merge_bindings([*plan["inputs"], dict(path=str(path), sha256=identity)], plan["base"])
    receipt = run_command(**plan, out_dir=args.out_dir)
    if expected is not None:
        matches = {}
        for stream in ("stdout", "stderr"):
            text = (args.out_dir / (stream + ".log")).read_text(encoding="utf-8", errors="replace") if expected[stream] else ""
            matches[stream] = [value in text for value in expected[stream]]
        met = (receipt["status"] in ("success", "failed") and receipt["inputs_unchanged"]
               and receipt["exit_code"] == expected["exit_code"] and all(all(v) for v in matches.values()))
        result = dict(format_version=1, job=name, expectations=expected, matched=matches, expectations_met=met,
                      qualification="Job expectations only; not behavioral or fidelity qualification.")
        (args.out_dir / "job-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if met else 1
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["status"] == "success" and receipt["inputs_unchanged"] else 1
