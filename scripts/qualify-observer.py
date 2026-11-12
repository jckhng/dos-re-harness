"""Qualify bounded passive observations with a generated DOS probe on Linux."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dos_re_harness.cli import build_parser
from dos_re_harness.evidence import file_record
from dos_re_harness.remote_protocol import QmpClient, RspClient

PROBE_BASE = 0x80000
RESULT_OFFSET = 0x300
RESULT_VALUE = 0x1234
PROBE_MEMORY_BYTES = 0x440
DEFAULT_EVENT_LIMIT = 10000
REMOTE_TIMEOUT = 30


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def run_case(backend, root, program, start, stop, *, observed, limit=DEFAULT_EVENT_LIMIT, core='normal'):
    root.mkdir()
    (root / 'PROBE.COM').write_bytes(program)
    gdb_port, qmp_port = free_port(), free_port()
    while qmp_port == gdb_port:
        qmp_port = free_port()
    config = root / 'dosbox.conf'
    config.write_text(
        '[sdl]\noutput=surface\nfullscreen=false\n'
        '[dosbox]\nmachine=svga_s3\nmemsize=16\n'
        f'gdbserver=true\ngdbserver port={gdb_port}\nqmpserver=true\nqmpserver port={qmp_port}\n'
        f'[cpu]\ncore={core}\ncputype=386\ncycles=fixed 60000\n'
        '[mixer]\nnosound=true\nrate=48000\n'
        '[sblaster]\nsbtype=sb16\nsbbase=220\nirq=7\ndma=1\nhdma=5\noplmode=none\n'
        f'[autoexec]\nmount c "{root.as_posix()}"\nc:\nPROBE.COM\n', encoding='utf-8')
    plan = root / 'observer.plan'
    plan.write_text(f'dos-re-observer-v1\nstart {start}\nstop {stop}\nlimit {limit}\n'
                    f'probe {start} enter probe entry\nprobe {stop} leave probe return\n'
                    'event irq-dispatch\nevent interrupt-return-attempt\nevent dma-read-request\n'
                    'event dma-write-request\nevent display-complete\nport 0x3c8\nport 0x3c9\n', encoding='utf-8')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('DOS_RE_HARNESS_')}
    environment.update(SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy',
                       DOS_RE_HARNESS_STATE_INPUT_HOOK_LINEAR=str(stop),
                       DOS_RE_HARNESS_STATE_INPUT_LINEAR=str(PROBE_BASE + RESULT_OFFSET),
                       DOS_RE_HARNESS_STATE_INPUT_WIDTH='2', DOS_RE_HARNESS_STATE_INPUT_STOP_VALUE=str(RESULT_VALUE))
    if observed:
        environment.update(DOS_RE_HARNESS_OBSERVER_PLAN=str(plan),
                           DOS_RE_HARNESS_OBSERVER_OUTPUT=str(root / 'raw.jsonl'))
    command = [str(backend), '-conf', str(config), '-logfile', str(root / 'dosbox.log')]
    with (root / 'process.log').open('wb') as log, ExitStack() as connections:
        process = subprocess.Popen(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            rsp = RspClient('127.0.0.1', gdb_port, REMOTE_TIMEOUT)
            connections.callback(rsp.close)
            rsp.wait_for_stop(REMOTE_TIMEOUT)
            registers = rsp.registers()
            memory = rsp.read_memory_chunked(PROBE_BASE, PROBE_MEMORY_BYTES)
            if memory[RESULT_OFFSET:RESULT_OFFSET + 2] != RESULT_VALUE.to_bytes(2, 'little'):
                raise RuntimeError('synthetic probe failed or missed its terminal boundary')
            qmp = QmpClient('127.0.0.1', qmp_port, REMOTE_TIMEOUT)
            connections.callback(qmp.close)
            display = qmp.displaydump()
            (root / 'ram.bin').write_bytes(memory)
            (root / 'registers.json').write_text(json.dumps(registers, indent=2) + '\n')
            # The display API retains source pixels and a synchronized palette.
            (root / 'display.json').write_text(json.dumps(display, default=lambda value: value.hex(), sort_keys=True) + '\n')
            return dict(registers=registers, memory=memory, display=display)
        finally:
            try:
                connections.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--assembler', default='nasm')
    parser.add_argument('--core', action='append', choices=('normal', 'full', 'simple'))
    args = parser.parse_args()
    if args.out_dir.exists():
        parser.error('output must be fresh')
    root, backend = args.out_dir.resolve(), args.backend.resolve(strict=True)
    assembler = shutil.which(args.assembler)
    if assembler is None:
        parser.error('NASM assembler is required')
    cores = args.core or ['normal', 'full']
    if len(set(cores)) != len(cores):
        parser.error('cores must be unique')
    root.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / 'tests/fixtures/observer-probe.asm'
    inputs = [file_record(path) for path in (backend, source, Path(__file__), Path(assembler))]
    subprocess.run([assembler, '-f', 'bin', str(source), '-o', str(root / 'PROBE.COM')], check=True)
    program = (root / 'PROBE.COM').read_bytes()
    entry = program.index(bytes.fromhex('0e1fb81300cd10'))
    stop = PROBE_BASE + program.index(bytes.fromhex('b8efbeebfe')) - entry
    reports = []
    for core in cores:
        original = run_case(backend, root / (core + '-off'), program, PROBE_BASE, stop, observed=False, core=core)
        observed = run_case(backend, root / (core + '-on'), program, PROBE_BASE, stop, observed=True, core=core)
        checks = {key: original[key] == observed[key] for key in ('registers', 'memory')}
        display_fields = ('data', 'palette', 'width', 'height', 'bpp', 'pitch')
        checks['display_content'] = all(original['display'][key] == observed['display'][key] for key in display_fields)
        if not all(checks.values()):
            raise RuntimeError('observer changed synthetic guest result: ' + str(checks))
        raw = root / (core + '-on/raw.jsonl')
        imported = root / (core + '-import')
        command = ['import-observations', str(raw), '--backend', str(backend), '--observer-plan',
                   str(root / (core + '-on/observer.plan')), '--execution', 'controlled',
                   '--supplied', 'generated conventional-memory probe', '--out-dir', str(imported)]
        options = build_parser().parse_args(command)
        options.func(options)
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        boundaries = {row.get('boundary') for row in rows}
        required = {'entry', 'return', 'irq-dispatch', 'interrupt-return-attempt',
                    'dma-read-request', 'display-complete', 'port-write-attempt'}
        if not required <= boundaries:
            raise RuntimeError('missing synthetic device observations: ' + str(required - boundaries))
        reports.append(dict(core=core, checks=checks, events=len(rows)-2, required_boundaries=sorted(required),
                            renderer_generations=[original['display']['generation'], observed['display']['generation']]))
    overflow = root / 'overflow'
    run_case(backend, overflow, program, PROBE_BASE, stop, observed=True, limit=1)
    overflow_rows = [json.loads(line) for line in (overflow / 'raw.jsonl').read_text().splitlines()]
    if not any(row.get('overflow') for row in overflow_rows) or overflow_rows[-1]['complete'] is not False:
        raise RuntimeError('overflow was incorrectly reported as complete')
    command = ['import-observations', str(overflow/'raw.jsonl'), '--backend', str(backend),
               '--observer-plan', str(overflow/'observer.plan'), '--out-dir', str(root/'overflow-import'),
               '--execution', 'controlled']
    options = build_parser().parse_args(command)
    try:
        options.func(options)
    except ValueError:
        pass
    else:
        raise RuntimeError('overflow import unexpectedly succeeded')
    rejected = reject_invalid_plans(backend, root, root/(cores[0]+'-off/dosbox.conf'),
                                    (root/(cores[0]+'-on/observer.plan')).read_text())
    if inputs != [file_record(path) for path in (backend, source, Path(__file__), Path(assembler))]:
        raise RuntimeError('qualification inputs changed during execution')
    report = dict(format_version=1, cases=reports, overflow_rejected=True,
                  invalid_plans_rejected=rejected,
                  inputs=inputs,
                  qualification='Synthetic fixed-cycle registers, RAM, display pixels/palette/geometry equivalence. Renderer-generation equality, physical timing and other CPU cores remain unqualified.')
    (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


def reject_invalid_plans(backend, root, config, valid):
    cases = dict(header=valid.replace('dos-re-observer-v1', 'invalid'),
                 zero_limit=valid.replace(f'limit {DEFAULT_EVENT_LIMIT}', 'limit 0'),
                 unknown_event=valid+'event unknown\n', duplicate_port=valid+'port 0x3c8\n',
                 malformed_probe=valid+'probe -1 point owner boundary\n', existing_output=valid)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('DOS_RE_HARNESS_')}
    environment.update(SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy')
    for name, text in cases.items():
        directory = root/('rejected-'+name)
        directory.mkdir()
        plan, output = directory/'observer.plan', directory/'raw.jsonl'
        plan.write_text(text, encoding='utf-8')
        if name == 'existing_output':
            output.write_bytes(b'preserved')
        env = dict(environment, DOS_RE_HARNESS_OBSERVER_PLAN=str(plan), DOS_RE_HARNESS_OBSERVER_OUTPUT=str(output))
        result = subprocess.run([str(backend), '-conf', str(config)], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=15)
        (directory/'process.log').write_bytes(result.stdout)
        if result.returncode == 0 or b'DOS_RE_HARNESS observer:' not in result.stdout:
            raise RuntimeError('invalid observer plan was not rejected: '+name)
        if name == 'existing_output' and output.read_bytes() != b'preserved':
            raise RuntimeError('existing observer output was modified')
    return list(cases)


if __name__ == '__main__':
    main()
