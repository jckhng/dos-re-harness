"""Clock-explicit event and lifecycle observations normalized by target adapters."""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path

from .bindings import inspect_bindings
from .evidence import file_record
from .traces import iter_jsonl, write_trace_context

MAX_OBSERVATION_EVENTS = 1000000


def _names(values):
    return (isinstance(values, list) and all(isinstance(value, str) and value for value in values))


def _clock_values(values, clocks, previous):
    if not isinstance(values, dict) or set(values) != set(clocks):
        raise ValueError("every observation requires every declared clock")
    for name, value in values.items():
        if (not isinstance(value, dict) or set(value) != {'epoch', 'tick'}
                or any(type(number) is not int or not 0 <= number < (1 << 64) for number in value.values())):
            raise ValueError("clock values require unsigned integer epoch and tick")
        old = previous.get(name)
        if old and (value['epoch'] < old['epoch'] or value['epoch'] > old['epoch'] + 1
                    or (value['epoch'] == old['epoch'] and value['tick'] < old['tick'])):
            raise ValueError("clock moved backward or skipped an explicit epoch")


def inspect_observations(path: Path, *, max_events: int = MAX_OBSERVATION_EVENTS) -> dict:
    if type(max_events) is not int or max_events < 1:
        raise ValueError("max_events must be positive")
    identity = file_record(path)
    document = json.loads(path.read_text(encoding='utf-8-sig'))
    fields = {'format_version', 'events', 'clocks', 'complete', 'initial_owners', 'final_owners', 'end_clocks', 'provenance'}
    if (not isinstance(document, dict) or set(document) != fields
            or type(document['format_version']) is not int or document['format_version'] != 1
            or document['complete'] is not True):
        raise ValueError("complete version 1 observations required")
    clocks = document['clocks']
    if not isinstance(clocks, dict) or not clocks or any(not name for name in clocks):
        raise ValueError("named clocks required")
    for clock in clocks.values():
        if clock is None:
            continue
        if (not isinstance(clock, dict) or set(clock) != {'rate_numerator', 'rate_denominator'}
                or any(type(value) is not int or value < 1 for value in clock.values())):
            raise ValueError("clock rate must be a positive rational or null for an unscaled counter")
    for field in ('initial_owners', 'final_owners'):
        if not _names(document[field]):
            raise ValueError("owner stacks require nonempty names")
    provenance = document['provenance']
    if (not isinstance(provenance, dict) or set(provenance) != {'execution', 'timing', 'supplied'}
            or provenance['execution'] not in ('component', 'controlled', 'natural')
            or provenance['timing'] not in ('unqualified', 'logical', 'emulated', 'physical')
            or not _names(provenance['supplied'])):
        raise ValueError("explicit execution, timing and supplied-input provenance required")
    binding = inspect_bindings([document['events']], path.parent)[0]
    if binding['status'] != 'current':
        raise ValueError("observation events are missing or stale")
    events = Path(binding['path'])
    owners, previous, count = list(document['initial_owners']), {}, 0
    for row in iter_jsonl(events):
        if count >= max_events:
            raise ValueError("observation event limit exceeded")
        if (set(row) != {'sequence', 'boundary', 'phase', 'owner', 'clocks', 'state'}
                or type(row['sequence']) is not int or row['sequence'] != count
                or not isinstance(row['boundary'], str) or not row['boundary']
                or not isinstance(row['owner'], str) or not row['owner']
                or row['phase'] not in ('point', 'enter', 'leave') or not isinstance(row['state'], dict)):
            raise ValueError("invalid ordered observation event")
        # JSON disallows nonfinite numbers, including within adapter state.
        json.dumps(row, allow_nan=False)
        _clock_values(row['clocks'], clocks, previous)
        previous = row['clocks']
        if row['phase'] == 'enter':
            owners.append(row['owner'])
        elif row['phase'] == 'leave':
            if not owners or owners.pop() != row['owner']:
                raise ValueError("lifecycle leave does not match active owner")
        count += 1
    _clock_values(document['end_clocks'], clocks, previous)
    if owners != document['final_owners']:
        raise ValueError("final owner stack differs from declared boundary")
    if identity != file_record(path) or inspect_bindings([document['events']], path.parent)[0] != binding:
        raise ValueError("observations changed during inspection")
    return dict(format_version=1, events=count, events_path=str(events), clocks=clocks,
                initial_owners=document['initial_owners'], final_owners=owners, end_clocks=document['end_clocks'],
                provenance=provenance, inputs=[identity, file_record(events)],
                scope="Adapter-declared clocks and ownership with checked artifact identities. Timing provenance remains a declaration.")


def command_diff_observations(args) -> int:
    if args.out_dir.exists():
        raise ValueError('output must be fresh')
    original = inspect_observations(args.original)
    native = inspect_observations(args.reimplementation)
    checks = {field: original[field] == native[field]
              for field in ('clocks', 'initial_owners', 'final_owners', 'end_clocks')}
    report = write_trace_context(Path(original['events_path']), Path(native['events_path']),
                                 args.out_dir / 'trace', before=args.before, after=args.after)
    if (report['inputs'] != [original['inputs'][1], native['inputs'][1]]
            or file_record(args.original) != original['inputs'][0]
            or file_record(args.reimplementation) != native['inputs'][0]):
        raise ValueError('observation inputs changed between validation and comparison')
    report.update(metadata_checks=checks, exact=report['exact'] and all(checks.values()),
                  original=original, reimplementation=native)
    (args.out_dir / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(exact=report['exact'], metadata_checks=checks,
                          first_difference=report['first_difference']), indent=2))
    return 0 if report['exact'] else 1


def command_import_observations(args) -> int:
    """Import a completed bounded backend log without resuming guest execution."""
    if args.out_dir.exists():
        raise ValueError('output must be fresh')
    inputs = [file_record(path) for path in (args.raw, args.backend, args.observer_plan)]
    args.out_dir.mkdir(parents=True)
    events = args.out_dir / 'events.jsonl'
    with closing(iter_jsonl(args.raw)) as rows, events.open('x', encoding='utf-8') as stream:
        header = next(rows, None)
        clocks = dict(pic_ns=dict(rate_numerator=1000000000, rate_denominator=1), instruction_boundary=None)
        if header != dict(format_version=1, observer='dos-re-observer-v1', clocks=clocks):
            raise ValueError('invalid backend observation header')
        previous = next(rows, None)
        count = 0
        for row in rows:
            if count >= MAX_OBSERVATION_EVENTS or previous is None or previous.get('overflow'):
                raise ValueError('backend observation limit exceeded')
            stream.write(json.dumps(previous, allow_nan=False) + '\n')
            previous = row
            count += 1
        if (not isinstance(previous, dict) or set(previous) != {'complete', 'end_clocks'}
                or previous['complete'] is not True):
            raise ValueError('backend observation did not reach its terminal boundary')
    if inputs != [file_record(path) for path in (args.raw, args.backend, args.observer_plan)]:
        raise ValueError('backend observation inputs changed during import')
    manifest = dict(format_version=1, events=dict(path=events.name, sha256=file_record(events)['sha256']),
                    clocks=clocks, complete=True, initial_owners=args.initial_owner, final_owners=args.final_owner,
                    end_clocks=previous['end_clocks'],
                    provenance=dict(execution=args.execution, timing='emulated', supplied=args.supplied))
    path = args.out_dir / 'observations.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    report = inspect_observations(path)
    receipt = dict(format_version=1, inputs=inputs, manifest=file_record(path), events=report['events'],
                   qualification='Completed passive backend log with declared execution provenance. Physical timing is unqualified.')
    (args.out_dir / 'import-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(receipt, indent=2))
    return 0
