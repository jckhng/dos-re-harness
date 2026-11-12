import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from dos_re_harness.cli import build_parser
from dos_re_harness.dependency_graph import inspect_graph
from dos_re_harness.observations import inspect_observations
from dos_re_harness.traces import write_trace_context


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def trace(self, name, rows):
        path = self.root / name
        text = ''.join(json.dumps(row) + '\n' for row in rows)
        if name.endswith('.gz'):
            with gzip.open(path, 'wt', encoding='utf-8') as stream:
                stream.write(text)
        else:
            path.write_text(text, encoding='utf-8')
        return path

    def test_context_keeps_bounded_preceding_and_following_rows(self):
        left = [dict(tick=i, health=10) for i in range(100)]
        right = [dict(row) for row in left]
        right[20]['health'] = 9
        report = write_trace_context(self.trace('a.jsonl.gz', left), self.trace('b.jsonl', right),
                                     self.root / 'out', before=2, after=3)
        self.assertFalse(report['exact'])
        self.assertEqual(report['first_difference']['index'], 20)
        self.assertEqual(report['window'], dict(first=18, last=23, rows=6))
        self.assertEqual(report['rows_examined'], 24)
        self.assertFalse(report['complete'])
        self.assertTrue((self.root / 'out/original-context.jsonl').is_file())
        self.assertNotIn(str(self.root), json.dumps(report['inputs']))

    def test_missing_null_and_extra_rows_stay_different(self):
        for index, right in enumerate(([dict(x=None)], [dict()], [dict(x=1), dict(x=1)])):
            left = self.trace('a.jsonl', [dict(x=1)])
            report = write_trace_context(left, self.trace('b.jsonl', right), self.root / str(index))
            self.assertFalse(report['exact'])
            self.assertIsNotNone(report['first_difference'])
        report = write_trace_context(self.trace('a.jsonl', [dict(x=None)]),
                                     self.trace('b.jsonl', [dict()]), self.root / 'null')
        change = report['first_difference']['fields']['x']
        self.assertEqual(change['original'], dict(present=True, value=None))
        self.assertEqual(change['reimplementation'], dict(present=False))

    def test_equal_empty_and_invalid_context(self):
        path = self.trace('empty.jsonl', [])
        report = write_trace_context(path, path, self.root / 'equal')
        self.assertTrue(report['exact'])
        self.assertTrue(report['complete'])
        with self.assertRaises(ValueError):
            write_trace_context(path, path, self.root / 'equal')
        for value in (-1, True, 1025):
            with self.assertRaises(ValueError):
                write_trace_context(path, path, self.root / 'bad', before=value)

    def event(self, sequence, phase='point', owner='scene', tick=None):
        return dict(sequence=sequence, boundary='boundary-' + str(sequence), phase=phase, owner=owner,
                    clocks=dict(simulation=dict(epoch=0, tick=sequence if tick is None else tick)), state={})

    def observation(self, rows, **changes):
        events = self.trace('events.jsonl', rows)
        manifest = dict(format_version=1, events=dict(path=events.name,
            sha256=hashlib.sha256(events.read_bytes()).hexdigest()),
            clocks=dict(simulation=dict(rate_numerator=40, rate_denominator=1)), complete=True,
            initial_owners=[], final_owners=[], end_clocks=dict(simulation=dict(epoch=0, tick=len(rows))),
            provenance=dict(execution='controlled', timing='logical', supplied=[]))
        manifest.update(changes)
        path = self.root / 'observation.json'
        path.write_text(json.dumps(manifest), encoding='utf-8')
        return path

    def test_lifecycle_and_distinct_clocks_are_validated(self):
        path = self.observation([self.event(0, 'enter'), self.event(1), self.event(2, 'leave')])
        report = inspect_observations(path)
        self.assertEqual(report['events'], 3)
        self.assertEqual(report['final_owners'], [])
        self.assertEqual(report['provenance']['timing'], 'logical')

    def test_incomplete_overflow_and_changed_artifact_reject(self):
        path = self.observation([self.event(0)], complete=False)
        with self.assertRaises(ValueError):
            inspect_observations(path)
        path = self.observation([dict(overflow=True)])
        with self.assertRaises(ValueError):
            inspect_observations(path)
        path = self.observation([self.event(0)])
        (self.root / 'events.jsonl').write_text('{}\n')
        with self.assertRaises(ValueError):
            inspect_observations(path)

    def test_wrong_owner_clock_reset_and_bad_types_reject(self):
        cases = [[self.event(0, 'leave')], [self.event(0, 'enter')],
                 [self.event(0, tick=2), self.event(1, tick=1)],
                 [self.event(0, tick=True)], [self.event(1)]]
        for rows in cases:
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):
                    inspect_observations(self.observation(rows))

    def test_explicit_clock_epoch_allows_reset(self):
        rows = [self.event(0, tick=200), self.event(1, tick=0)]
        rows[1]['clocks']['simulation']['epoch'] = 1
        path = self.observation(rows, end_clocks=dict(simulation=dict(epoch=1, tick=1)))
        self.assertEqual(inspect_observations(path)['events'], 2)

    def test_fidelity_dimensions_preserve_failed_and_stale_claims(self):
        source = self.root / 'source'
        source.write_text('current')
        artifact = dict(id='source', path='source', sha256=hashlib.sha256(b'current').hexdigest())
        record = dict(id='case', dependencies=['source'], dependencies_complete=True, stage='validated',
                      execution='controlled', recorded_result='fail', scope='synthetic transition',
                      domains=['state', 'audio'], timing='emulated', supplied=['initial snapshot'])
        path = self.root / 'graph.json'
        path.write_text(json.dumps(dict(format_version=2, artifacts=[artifact], records=[record])))
        report = inspect_graph(path)
        self.assertEqual(report['records'][0]['recorded_result'], 'fail')
        self.assertEqual(report['fidelity']['timing'], {'emulated': {'fail': 1}})
        source.write_text('changed')
        report = inspect_graph(path)
        self.assertEqual(report['records'][0]['freshness'], 'stale')
        self.assertEqual(report['fidelity']['current_passes'], 0)

    def run_cli(self, argv):
        args = build_parser().parse_args(argv)
        with contextlib.redirect_stdout(io.StringIO()):
            return args.func(args)

    def test_batch_preserves_expected_failures_and_stops_on_unexpected_failure(self):
        plan = self.root / 'jobs.json'
        jobs = dict(positive=dict(command=[sys.executable, '-c', 'print("ok")']),
                    negative=dict(command=[sys.executable, '-c', 'raise SystemExit(7)'], expected_exit_code=7),
                    failure=dict(command=[sys.executable, '-c', 'raise SystemExit(9)']),
                    skipped=dict(command=[sys.executable, '-c', 'print("unreachable")']))
        plan.write_text(json.dumps(dict(format_version=2, jobs=jobs)))
        self.assertEqual(self.run_cli(['run-plan', str(plan), '--all-jobs', '--out-dir', str(self.root/'batch')]), 1)
        report = json.loads((self.root / 'batch/batch-result.json').read_text())
        self.assertEqual([row['status'] for row in report['jobs']], ['met', 'met', 'unmet', 'skipped'])
        raw = json.loads((self.root / 'batch/negative/receipt.json').read_text())
        self.assertEqual(raw['status'], 'failed')
        self.assertFalse(raw['cache_eligible'])
        self.assertFalse((self.root / 'batch/skipped').exists())

    def test_batch_preflights_all_names_and_inputs_before_execution(self):
        for name, options in [('bad/name', {}), ('NUL', {}), ('case.', {}),
                              ('valid', dict(inputs=[dict(path='missing', sha256='0'*64)]))]:
            plan = self.root / 'jobs.json'
            plan.write_text(json.dumps(dict(format_version=2, jobs={name: dict(command=[sys.executable, '-V'], **options)})))
            with self.assertRaises(ValueError):
                self.run_cli(['run-plan', str(plan), '--all-jobs', '--out-dir', str(self.root/'batch')])
            self.assertFalse((self.root / 'batch').exists())

    def test_batch_dry_run_is_read_only_and_rejects_case_collisions(self):
        plan = self.root / 'jobs.json'
        jobs = {'case': dict(command=[sys.executable, '-V'])}
        plan.write_text(json.dumps(dict(format_version=2, jobs=jobs)))
        command = ['run-plan', str(plan), '--all-jobs', '--dry-run', '--out-dir', str(self.root/'batch')]
        self.assertEqual(self.run_cli(command), 0)
        self.assertFalse((self.root/'batch').exists())
        jobs['Case'] = jobs['case']
        plan.write_text(json.dumps(dict(format_version=2, jobs=jobs)))
        with self.assertRaises(ValueError):
            self.run_cli(command)

    def test_batch_detects_inputs_changed_by_an_earlier_job(self):
        (self.root / 'input').write_text('original')
        plan = self.root / 'jobs.json'
        jobs = dict(mutate=dict(command=[sys.executable, '-c',
            'from pathlib import Path;Path("input").write_text("changed")']),
            check=dict(command=[sys.executable, '-V'], inputs=[dict(path='input',
                sha256=hashlib.sha256(b'original').hexdigest())]))
        plan.write_text(json.dumps(dict(format_version=2, jobs=jobs)))
        self.assertEqual(self.run_cli(['run-plan', str(plan), '--all-jobs', '--out-dir', str(self.root/'batch')]), 1)
        receipt = json.loads((self.root / 'batch/check/receipt.json').read_text())
        self.assertEqual(receipt['status'], 'preflight_failed')

    def test_partial_batch_keeps_summary_when_a_job_output_collides(self):
        plan = self.root/'jobs.json'
        jobs = dict(first=dict(command=[sys.executable, '-c',
            'from pathlib import Path;Path("batch/second").mkdir()']),
            second=dict(command=[sys.executable, '-V']), third=dict(command=[sys.executable, '-V']))
        plan.write_text(json.dumps(dict(format_version=2, jobs=jobs)))
        self.assertEqual(self.run_cli(['run-plan', str(plan), '--all-jobs', '--out-dir', str(self.root/'batch')]), 1)
        report = json.loads((self.root/'batch/batch-result.json').read_text())
        self.assertEqual([row['status'] for row in report['jobs']], ['met', 'error', 'skipped'])

    def test_observation_comparison_rejects_wrong_rate_and_final_hold(self):
        original = self.observation([self.event(0)])
        copy = self.root / 'copy.json'
        document = json.loads(original.read_text())
        copy.write_text(json.dumps(document))
        command = ['diff-observations', str(original), str(copy), '--out-dir', str(self.root/'equal')]
        self.assertEqual(self.run_cli(command), 0)
        document['clocks']['simulation']['rate_numerator'] = 41
        copy.write_text(json.dumps(document))
        command[-1] = str(self.root/'rate')
        self.assertEqual(self.run_cli(command), 1)
        report = json.loads((self.root/'rate/comparison.json').read_text())
        self.assertFalse(report['metadata_checks']['clocks'])
        document['clocks']['simulation']['rate_numerator'] = 40
        document['end_clocks']['simulation']['tick'] = 2
        copy.write_text(json.dumps(document))
        command[-1] = str(self.root/'hold')
        self.assertEqual(self.run_cli(command), 1)

    def test_multiclock_and_recursive_owner_state(self):
        rows = [self.event(0, 'enter', 'outer'), self.event(1, 'enter', 'inner'),
                self.event(2, 'leave', 'inner'), self.event(3, 'leave', 'outer')]
        for index, row in enumerate(rows):
            row['clocks']['audio'] = dict(epoch=0, tick=index*1200)
            row['state'] = dict(carried=[7, 0, 0])
        clocks = dict(simulation=dict(rate_numerator=40, rate_denominator=1),
                      audio=dict(rate_numerator=48000, rate_denominator=1))
        end = dict(simulation=dict(epoch=0, tick=4), audio=dict(epoch=0, tick=4800))
        self.assertEqual(inspect_observations(self.observation(rows, clocks=clocks, end_clocks=end))['events'], 4)
        rows[1]['clocks'].pop('audio')
        with self.assertRaises(ValueError):
            inspect_observations(self.observation(rows, clocks=clocks, end_clocks=end))

    def test_backend_import_requires_complete_bounded_log(self):
        clocks = dict(pic_ns=dict(rate_numerator=1000000000, rate_denominator=1), instruction_boundary=None)
        row = self.event(0)
        row['clocks'] = {name: dict(epoch=0, tick=1) for name in clocks}
        header = dict(format_version=1, observer='dos-re-observer-v1', clocks=clocks)
        footer = dict(complete=True, end_clocks=row['clocks'])
        backend, plan = self.root/'backend', self.root/'observer.plan'
        backend.write_bytes(b'synthetic executable identity')
        plan.write_text('synthetic observer plan identity')
        for name, rows, valid in [('valid', [header, row, footer], True),
                                  ('overflow', [header, row, dict(overflow=True), dict(footer, complete=False)], False),
                                  ('truncated', [header, row], False),
                                  ('empty', [], False)]:
            raw = self.trace(name+'.jsonl', rows)
            args = ['import-observations', str(raw), '--backend', str(backend), '--observer-plan', str(plan),
                    '--out-dir', str(self.root/name), '--execution', 'controlled']
            if valid:
                self.assertEqual(self.run_cli(args), 0)
                self.assertEqual(inspect_observations(self.root/name/'observations.json')['events'], 1)
            else:
                with self.assertRaises(ValueError):
                    self.run_cli(args)

    def test_fidelity_rejects_ambiguous_or_empty_dimensions(self):
        record = dict(id='case', dependencies=[], dependencies_complete=False, stage='implemented',
                      execution='controlled', recorded_result='not_run', scope='synthetic',
                      domains=['state'], timing='unqualified', supplied=[])
        path = self.root/'graph.json'
        for changes in [dict(domains=[]), dict(domains=['state', 'state']), dict(timing='exact'), dict(supplied=[1])]:
            path.write_text(json.dumps(dict(format_version=2, artifacts=[], records=[dict(record, **changes)])))
            with self.assertRaises(ValueError):
                inspect_graph(path)


if __name__ == '__main__':
    unittest.main()
