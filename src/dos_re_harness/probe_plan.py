"""Versioned CPU-only experiments using independently captured reference files."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import hashlib
import json
import re
import shutil
import sys
import time

from .bindings import inspect_bindings
from .evidence import sha256_file
from .execution import load_run_plan, run_command
from .unicorn_probe import run_callback

_FILES = {"specimen", "memory", "registers", "expected_memory", "expected_registers", "calibration"}
_REGISTERS = {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "cs", "ds", "es", "ss", "fs", "gs", "flags", "ip"}


def _registers(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    value = value.get("registers", value)
    if not isinstance(value, dict) or any(type(item) is not int for item in value.values()):
        raise ValueError("register snapshot must contain integer registers")
    return value


def _register_value(registers, name):
    if name == "ip" and "eip" in registers:
        return (registers["eip"] - registers["cs"] * 16) & 0xffff
    source = "eflags" if name == "flags" else "e" + name if name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp") else name
    if source not in registers and name not in registers:
        raise ValueError("reference register missing: " + name)
    return registers.get(source, registers.get(name)) & 0xffff


def run_probe_plan(path: Path, out_dir: Path, *, cache_dir: Path | None = None, dry_run: bool = False) -> dict:
    started = time.perf_counter()
    path, out_dir = path.resolve(), out_dir.resolve()
    plan = json.loads(path.read_text(encoding="utf-8-sig"))
    required = {"format_version", "id", "scope", "files", "entry", "stop", "return_kind",
                "max_instructions", "entry_bytes", "register_overrides", "overlays", "compare"}
    if (not isinstance(plan, dict) or set(plan) - required - {"timeout_us", "write_ranges", "max_writes", "stop_hit_count", "native"}
            or required - plan.keys() or type(plan["format_version"]) is not int or plan["format_version"] != 1):
        raise ValueError("invalid probe-plan version or fields")
    if not isinstance(plan['id'], str) or not plan['id'] or not isinstance(plan['scope'], str) or not plan['scope']:
        raise ValueError("probe id and scope must be nonempty strings")
    for name,default in [('max_instructions',None),('timeout_us',5_000_000),('max_writes',4096),('stop_hit_count',1)]:
        value = plan.get(name,default)
        if type(value) is not int or value < 1:
            raise ValueError(name + ' must be a positive integer')
    files = plan["files"]
    if not isinstance(files, dict) or set(files) != _FILES:
        raise ValueError("probe requires specimen, RAM/register pair and calibration bindings")
    bindings = [inspect_bindings([binding], path.parent)[0] for binding in files.values()]
    if any(row['status'] != 'current' for row in bindings):
        raise ValueError("probe inputs are missing or stale")
    paths = {name: (path.parent / spec['path']).resolve() for name, spec in files.items()}
    # A field can intentionally refer to the same entry/expected artifact.
    memory = bytearray(paths['memory'].read_bytes())
    expected = paths['expected_memory'].read_bytes()
    if not memory or len(memory) % 0x1000 or len(expected) != len(memory):
        raise ValueError("probe requires equal, page-aligned complete RAM images")
    for key in ('entry', 'stop'):
        if not isinstance(plan[key], list) or len(plan[key]) != 2 or any(type(v) is not int or not 0 <= v <= 0xffff for v in plan[key]):
            raise ValueError(key + " must be [segment, offset]")
    linear = plan['entry'][0]*16 + plan['entry'][1]
    raw = bytes.fromhex(plan['entry_bytes'])
    if not raw or memory[linear:linear+len(raw)] != raw:
        raise ValueError("unexpected original entry bytes")
    registers = _registers(paths['registers'])
    if (registers.get('cs'), _register_value(registers, 'ip')) != tuple(plan['entry']):
        raise ValueError("captured register entry differs from declared entry")
    overrides = plan['register_overrides']
    if not isinstance(overrides, dict) or any(k not in _REGISTERS | {'e'+n for n in ('ax','bx','cx','dx','si','di','bp','sp')} | {'eflags'} or type(v) is not int
                                              for k,v in overrides.items()):
        raise ValueError("invalid register overrides")
    if any(name in overrides for name in ('cs','ip')):
        raise ValueError('entry CS:IP cannot be changed by register overrides')
    for name,value in overrides.items():
        alias = 'eflags' if name=='flags' else 'flags' if name=='eflags' else (
            'e'+name if name in ('ax','bx','cx','dx','si','di','bp','sp') else
            name[1:] if name in ('eax','ebx','ecx','edx','esi','edi','ebp','esp') else None)
        if alias in overrides:
            raise ValueError('ambiguous register overrides: '+name+'/'+alias)
        if alias:
            registers.pop(alias,None)
        registers[name] = value
    if not isinstance(plan['overlays'], list):
        raise ValueError("overlays must be a list")
    overlays = []
    for overlay in plan['overlays']:
        if not isinstance(overlay, dict) or set(overlay) != {'address','bytes'} or type(overlay['address']) is not int:
            raise ValueError("overlay requires address and bytes")
        address, raw = overlay['address'], bytes.fromhex(overlay['bytes'])
        if not raw or not 0 <= address < address+len(raw) <= len(memory):
            raise ValueError("overlay lies outside RAM")
        overlays.append(dict(address=address, before=memory[address:address+len(raw)].hex(), written=raw.hex()))
        memory[address:address+len(raw)] = raw
    comparison = plan['compare']
    if not isinstance(comparison, dict) or set(comparison) != {'memory_ranges','registers'}:
        raise ValueError("compare requires memory_ranges and registers")
    ranges, selected = comparison['memory_ranges'], comparison['registers']
    if not isinstance(ranges, list) or not isinstance(selected, list) or (not ranges and not selected):
        raise ValueError("probe comparison cannot be empty")
    for region in ranges:
        if not isinstance(region, list) or len(region) != 2 or any(type(v) is not int for v in region) or not 0 <= region[0] < region[1] <= len(memory):
            raise ValueError("comparison ranges must be half-open RAM intervals")
    if any(not isinstance(name, str) or name not in _REGISTERS for name in selected) or len(set(selected)) != len(selected):
        raise ValueError("invalid compared registers")
    expected_registers = _registers(paths['expected_registers'])
    for name in selected:
        _register_value(expected_registers, name)
    native = None
    native_expected = None
    if 'native' in plan:
        if not isinstance(plan['native'], dict) or set(plan['native']) != {'plan','expected_json'}:
            raise ValueError("native comparison requires plan and expected_json bindings")
        native_inputs = inspect_bindings(list(plan['native'].values()), path.parent)
        if any(row['status'] != 'current' for row in native_inputs):
            raise ValueError("native comparison input changed")
        bindings.extend(native_inputs)
        native_expected = json.loads((path.parent/plan['native']['expected_json']['path']).read_text())
        native_plan_path = (path.parent / plan['native']['plan']['path']).resolve()
        native = load_run_plan(native_plan_path)
        if any(row['status'] != 'current' for row in inspect_bindings(native['inputs'], native['base'])):
            raise ValueError("native execution dependencies changed")
        if cache_dir:
            raise ValueError("native comparison is uncached; use declared graph keys for native workflows")
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError("qualified probe plans require Unicorn 2.1.4")
    package = Path(unicorn.__file__).parent
    engine = {str(p.relative_to(package)): sha256_file(p) for p in package.rglob('*')
              if p.is_file() and (p.suffix.lower() in ('.dll','.so','.dylib','.pyd')
                                  or re.search(r'\.so(?:\.\d+)+$', p.name))}
    if not engine:
        raise ValueError("cannot identify Unicorn native library")
    identity = dict(plan=plan, inputs=bindings, engine=engine,
        python_binding={str(p.relative_to(package)):sha256_file(p) for p in package.rglob('*.py')},
        interpreter=sha256_file(Path(sys.executable)),
        support={name:sha256_file(Path(__file__).with_name(name)) for name in ('bindings.py','evidence.py')},
        runner=sha256_file(Path(__file__).with_name('unicorn_probe.py')), executor=sha256_file(Path(__file__)))
    key = hashlib.sha256(json.dumps(['dos-re-probe-v1', identity], sort_keys=True).encode()).hexdigest()
    if dry_run:
        return dict(status='preflight_pass', id=plan['id'], cache_key=key, inputs=bindings)
    if out_dir.exists() or any(Path(row['path']) == out_dir or out_dir in Path(row['path']).parents for row in bindings):
        raise ValueError("probe output must be fresh and cannot contain inputs")
    cached = cache_dir.resolve()/key if cache_dir else None
    if cached and cached.exists():
        seal = json.loads((cached/'cache.json').read_text())
        if set(seal) != {'report.json','ram.bin'} or any(sha256_file(cached/name) != digest for name,digest in seal.items()):
            raise ValueError("corrupt probe cache")
        out_dir.mkdir(parents=True)
        for name in seal:
            shutil.copyfile(cached/name, out_dir/name)
        report = json.loads((out_dir/'report.json').read_text())
        report.update(cached=True, wall_seconds=time.perf_counter()-started)
        (out_dir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        return report
    out_dir.mkdir(parents=True)
    try:
        result = run_callback(bytes(memory), registers, entry=tuple(plan['entry']), return_address=tuple(plan['stop']),
            return_kind=plan['return_kind'], max_instructions=plan['max_instructions'],
            timeout_us=plan.get('timeout_us',5_000_000), stop_hit_count=plan.get('stop_hit_count',1),
            write_ranges=tuple(tuple(r) for r in plan.get('write_ranges',[])), max_writes=plan.get('max_writes',4096))
    except ValueError as error:
        report = dict(format_version=1,id=plan['id'],exact=False,status='rejected',error=str(error),
            classification='controlled_imported_snapshot_non_promotable',inputs=bindings,
            wall_seconds=time.perf_counter()-started)
        (out_dir/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        return report
    memory_diff = next((i for start,end in ranges for i in range(start,end) if result.memory[i] != expected[i]), None)
    register_diff = {name:dict(actual=result.registers[name], expected=_register_value(expected_registers,name))
                     for name in selected if result.registers[name] != _register_value(expected_registers,name)}
    native_exact = None
    if native:
        native_path, native_hash = native.pop('plan_path'), native.pop('plan_sha256')
        native['inputs'] = [*native['inputs'],dict(path=str(native_path),sha256=native_hash)]
        receipt = run_command(**native, out_dir=out_dir/'native')
        native_exact = False
        if receipt['status']=='success' and receipt['inputs_unchanged']:
            try:
                native_exact = json.loads((out_dir/'native/stdout.log').read_text()) == native_expected
            except (ValueError,UnicodeError):
                native_exact = False
    after = [inspect_bindings([dict(path=row['path'],sha256=row['sha256'])],path.parent)[0] for row in bindings]
    unchanged = after == bindings
    report = dict(format_version=1, id=plan['id'], scope=plan['scope'], cached=False, cache_key=key,
        classification='controlled_imported_snapshot_non_promotable',
        exact=memory_diff is None and not register_diff and native_exact is not False and unchanged,
        first_memory_difference=memory_diff, register_differences=register_diff, native_json_exact=native_exact,
        instructions=result.instructions, engine=engine, inputs=bindings, inputs_after=after,
        inputs_unchanged=unchanged, overlays=overlays,
        register_overrides=overrides, comparison=comparison, registers=result.registers,
        writes=[dict(asdict(w),before=w.before.hex(),written=w.written.hex()) for w in result.writes],
        ram_sha256=hashlib.sha256(result.memory).hexdigest(), wall_seconds=time.perf_counter()-started,
        limitations='CPU contract only; calibration binding is declared provenance, not recursive qualification. No natural route/device/timing claim.')
    (out_dir/'ram.bin').write_bytes(result.memory)
    (out_dir/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    if cached and unchanged:
        cached.mkdir(parents=True)
        for name in ('report.json','ram.bin'):
            shutil.copyfile(out_dir/name,cached/name)
        (cached/'cache.json').write_text(json.dumps({name:sha256_file(cached/name) for name in ('report.json','ram.bin')}))
    return report


def command_probe_plan(args) -> int:
    report = run_probe_plan(args.plan,args.out_dir,cache_dir=args.cache_dir,dry_run=args.dry_run)
    print(json.dumps(report,indent=2))
    return 0 if report.get('exact', report.get('status')=='preflight_pass') else 1
