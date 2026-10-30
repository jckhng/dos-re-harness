from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

from dos_re_harness.execution import load_run_plan, run_command


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'input'
        self.source.write_text('source')
        self.binding = dict(path='input', sha256=hashlib.sha256(b'source').hexdigest())

    def run_case(self, code, **options):
        return run_command([sys.executable, '-u', '-c', code], cwd=self.root,
            out_dir=self.root / 'out', inputs=[self.binding], **options)

    def test_success_records_streams_and_identities(self):
        report = self.run_case('import sys;print("ok");print("err",file=sys.stderr)', dependencies_complete=True)
        self.assertEqual(report['status'], 'success')
        self.assertTrue(report['cache_eligible'])
        self.assertTrue(report['tool']['sha256'])
        self.assertEqual((self.root/'out/stdout.log').read_text().strip(), 'ok')
        self.assertEqual((self.root/'out/stderr.log').read_text().strip(), 'err')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.run_case('pass')

    def test_stale_input_prevents_execution_and_retains_receipt(self):
        self.source.write_text('changed')
        report = self.run_case('raise Exception("must not run")')
        self.assertEqual(report['status'], 'preflight_failed')
        self.assertEqual(report['inputs_before'][0]['status'], 'stale')
        self.assertTrue((self.root/'out/receipt.json').is_file())

    def test_timeout_preserves_partial_output(self):
        report = self.run_case('import time;print("started",flush=True);time.sleep(10)', timeout_seconds=0.5)
        self.assertEqual(report['status'], 'timeout')
        self.assertIn('started', (self.root/'out/stdout.log').read_text())

    def test_mutation_and_nonzero_exit_are_not_eligible(self):
        report = self.run_case('from pathlib import Path;Path("input").write_text("new");raise SystemExit(3)', dependencies_complete=True)
        self.assertEqual(report['exit_code'], 3)
        self.assertFalse(report['inputs_unchanged'])
        self.assertFalse(report['cache_eligible'])

    def test_launch_error_is_recorded(self):
        report = run_command(['missing-command-dos-re-test'], cwd=self.root, out_dir=self.root/'out')
        self.assertEqual(report['status'], 'launch_error')

    def test_plan_paths_and_version_are_validated(self):
        path = self.root/'plan.json'
        path.write_text(json.dumps(dict(format_version=1, command=[sys.executable, '-V'], inputs=[self.binding])))
        self.assertEqual(load_run_plan(path)['cwd'], self.root)
        path.write_text(json.dumps(dict(format_version=True, command=['x'])))
        with self.assertRaises(ValueError):
            load_run_plan(path)
