from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

from dos_re_harness.probe_plan import run_probe_plan


class ProbePlanTests(unittest.TestCase):
    def setUp(self):
        try:
            import unicorn
        except ImportError:
            self.skipTest('optional Unicorn dependency is not installed')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        memory = bytearray(0x20000)
        memory[0x1020:0x1026] = bytes.fromhex('c7 06 00 01 34 12')
        expected = bytearray(memory)
        expected[0x4100:0x4102] = bytes.fromhex('34 12')
        registers = dict(cs=0x100,eip=0x1020,ds=0x400,ss=0x100,esp=0x8000,eflags=2)
        self.plan = dict(format_version=1,id='write',scope='synthetic CPU contract',
            entry=[0x100,0x20],stop=[0x100,0x26],return_kind='snapshot',max_instructions=16,
            entry_bytes='c70600013412',register_overrides={},overlays=[],
            compare=dict(memory_ranges=[[0,len(memory)]],registers=['ip','sp','ds']),
            write_ranges=[[0x4100,0x4102]],files={})
        data = dict(specimen=b'synthetic',memory=memory,expected_memory=expected,
            registers=json.dumps(registers).encode(),
            expected_registers=json.dumps(dict(registers,eip=0x1026)).encode(),calibration=b'synthetic-only')
        for name,raw in data.items():
            self.plan['files'][name] = self.bind(name,raw)

    def bind(self,name,raw):
        (self.root/name).write_bytes(raw)
        return dict(path=name,sha256=hashlib.sha256(raw).hexdigest())

    def run_case(self,output='out',**kwargs):
        path = self.root/'plan.json'
        path.write_text(json.dumps(self.plan))
        return run_probe_plan(path,self.root/output,**kwargs)

    def test_exact_and_writes_are_recorded(self):
        report = self.run_case()
        self.assertTrue(report['exact'])
        self.assertEqual(report['writes'][0]['written'],'3412')
        self.assertEqual(report['classification'],'controlled_imported_snapshot_non_promotable')

    def test_versioned_linux_library_is_bound_and_invalidates_cache(self):
        import unicorn
        package = self.root/'synthetic-binding'
        (package/'lib').mkdir(parents=True)
        library = package/'lib/libunicorn.so.2'
        library.write_bytes(b'synthetic engine identity')
        with patch.object(unicorn, '__file__', str(package/'__init__.py')):
            first = self.run_case('first', cache_dir=self.root/'cache')
            self.assertIn('lib/libunicorn.so.2', {Path(name).as_posix() for name in first['engine']})
            library.write_bytes(b'changed synthetic engine identity')
            second = self.run_case('second', cache_dir=self.root/'cache')
        self.assertNotEqual(first['cache_key'], second['cache_key'])
        self.assertFalse(second['cached'])

    def test_changed_oracle_and_incomplete_comparison_reject(self):
        (self.root/'expected_memory').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'stale'):
            self.run_case()
        self.plan['files']['expected_memory'] = self.bind('expected_memory',bytes(0x20000))
        self.assertFalse(self.run_case()['exact'])
        self.plan['compare'] = dict(memory_ranges=[],registers=[])
        with self.assertRaisesRegex(ValueError,'empty'):
            self.run_case('other')

    def test_cache_hit_and_corruption_are_distinct(self):
        cache = self.root/'cache'
        first = self.run_case('one',cache_dir=cache)
        second = self.run_case('two',cache_dir=cache)
        self.assertFalse(first['cached'])
        self.assertTrue(second['cached'])
        (cache/first['cache_key']/'ram.bin').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'corrupt'):
            self.run_case('three',cache_dir=cache)

    def test_dry_run_and_wrong_entry_have_no_outputs(self):
        self.assertEqual(self.run_case(dry_run=True)['status'],'preflight_pass')
        self.assertFalse((self.root/'out').exists())
        self.plan['entry_bytes'] = '90'
        with self.assertRaisesRegex(ValueError,'entry bytes'):
            self.run_case()

    def test_native_json_comparison_uses_shared_receipt(self):
        native = dict(format_version=1,command=[sys.executable,'-c','print("{\\"answer\\": 42}")'])
        self.plan['native'] = dict(plan=self.bind('native-plan',json.dumps(native).encode()),
                                  expected_json=self.bind('native-expected',b'{"answer":42}'))
        self.assertTrue(self.run_case()['native_json_exact'])
        self.assertTrue((self.root/'out/native/receipt.json').is_file())

    def test_unsupported_cpu_keeps_rejection_record(self):
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex('cd21')
        self.plan['files']['memory'] = self.bind('memory',memory)
        self.plan['entry_bytes'] = 'cd21'
        report = self.run_case()
        self.assertEqual(report['status'],'rejected')
        self.assertIn('interrupt',report['error'])
        self.assertFalse(report['exact'])

    def test_low_register_override_replaces_extended_snapshot_value(self):
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex('a30001')
        expected = bytearray(memory)
        expected[0x4100:0x4102] = bytes.fromhex('3412')
        self.plan['files']['memory'] = self.bind('memory',memory)
        self.plan['files']['expected_memory'] = self.bind('expected_memory',expected)
        initial = dict(cs=0x100,eip=0x1020,ds=0x400,ss=0x100,esp=0x8000,eax=0x9999)
        self.plan['files']['registers'] = self.bind('registers',json.dumps(initial).encode())
        self.plan['files']['expected_registers'] = self.bind('expected_registers',json.dumps(dict(initial,eip=0x1023)).encode())
        self.plan.update(entry_bytes='a30001',stop=[0x100,0x23],register_overrides=dict(ax=0x1234))
        self.assertTrue(self.run_case()['exact'])

    def test_native_cannot_rewrite_its_expected_json(self):
        command = 'from pathlib import Path;Path("native-expected").write_text("{\\"answer\\":42}");print("{\\"answer\\":42}")'
        native = dict(format_version=1,command=[sys.executable,'-c',command])
        self.plan['native'] = dict(plan=self.bind('native-plan',json.dumps(native).encode()),
                                  expected_json=self.bind('native-expected',b'{"answer":99}'))
        report = self.run_case()
        self.assertFalse(report['native_json_exact'])
        self.assertFalse(report['inputs_unchanged'])
        self.assertFalse(report['exact'])
