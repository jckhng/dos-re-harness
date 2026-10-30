from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from dos_re_harness.dependency_graph import inspect_graph


class DependencyGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.document = dict(format_version=1, artifacts=[], records=[])
        for name in ('first', 'unrelated'):
            (self.root/name).write_text(name)
            self.document['artifacts'].append(dict(id=name, path=name, sha256=hashlib.sha256(name.encode()).hexdigest()))
            self.document['records'].append(dict(id=name+'-case', dependencies=[name], dependencies_complete=True,
                stage='integrated', execution='controlled', recorded_result='pass', scope='synthetic contract'))
        self.document['records'].append(dict(self.document['records'][0], id='parent', dependencies=['first-case']))

    def report(self):
        path = self.root/'graph.json'
        path.write_text(json.dumps(self.document))
        return {row['id']: row for row in inspect_graph(path)['records']}

    def test_transitive_staleness_keeps_recorded_result(self):
        (self.root/'first').write_text('changed')
        rows = self.report()
        self.assertEqual(rows['parent']['freshness'], 'stale')
        self.assertEqual(rows['parent']['recorded_result'], 'pass')
        self.assertIsNone(rows['parent']['cache_key'])
        self.assertEqual(rows['unrelated-case']['freshness'], 'current')

    def test_unrelated_changes_do_not_change_case_identity(self):
        before = self.report()['first-case']['cache_key']
        self.document['records'][1]['scope'] = 'unrelated contract changed'
        self.assertEqual(self.report()['first-case']['cache_key'], before)

    def test_incomplete_and_missing_fail_preflight(self):
        self.document['records'][0]['dependencies_complete'] = False
        self.assertEqual(self.report()['parent']['freshness'], 'incomplete')
        (self.root/'first').unlink()
        self.assertEqual(self.report()['parent']['freshness'], 'missing')

    def test_cycle_and_unknown_dependencies_reject(self):
        for deps in (['parent'], ['unknown']):
            self.document['records'][0]['dependencies'] = deps
            with self.assertRaises(ValueError):
                self.report()

    def test_current_failure_stays_failure(self):
        self.document['records'][0]['recorded_result'] = 'fail'
        row = self.report()['first-case']
        self.assertEqual(row['freshness'], 'current')
        self.assertEqual(row['recorded_result'], 'fail')
