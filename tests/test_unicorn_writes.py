import unittest

from dos_re_harness.unicorn_probe import run_callback


class WriteTraceTests(unittest.TestCase):
    def setUp(self):
        try:
            import unicorn
        except ImportError:
            self.skipTest('optional Unicorn dependency is not installed')

    def execute(self, code, **options):
        memory = bytearray(0x20000)
        raw = bytes.fromhex(code)
        memory[0x1020:0x1020+len(raw)] = raw
        return run_callback(bytes(memory), dict(ds=0x400, es=0x401, ss=0x100, sp=0x8000, flags=2),
            entry=(0x100, 0x20), return_address=(0x100, 0x20+len(raw)),
            return_kind='snapshot', max_instructions=64, **options)

    def test_overlapping_writes_record_before_bytes_and_order(self):
        result = self.execute('c7 06 00 01 34 12 c6 06 01 01 ab', write_ranges=((0x4100, 0x4102),))
        self.assertEqual([(w.sequence,w.address,w.before,w.written) for w in result.writes],
            [(1,0x4100,b'\0\0',b'\x34\x12'), (2,0x4101,b'\x12',b'\xab')])
        self.assertEqual([(w.cs,w.ip) for w in result.writes], [(0x100,0x20),(0x100,0x26)])
        self.assertEqual(result.memory[0x4100:0x4102], b'\x34\xab')

    def test_segment_aliases_and_overlapping_filters_do_not_duplicate(self):
        result = self.execute('c6 06 00 01 11 26 c6 06 f0 00 22',
            write_ranges=((0x4100,0x4101),(0x40ff,0x4102)))
        self.assertEqual([w.address for w in result.writes], [0x4100,0x4100])
        self.assertEqual([w.written for w in result.writes], [b'\x11',b'\x22'])

    def test_rep_records_each_write_and_unfiltered_result_is_unchanged(self):
        code = 'b9 03 00 bf f0 00 b0 33 f3 aa'
        result = self.execute(code, write_ranges=((0x4100,0x4103),))
        plain = self.execute(code)
        self.assertEqual(result.memory, plain.memory)
        self.assertEqual(result.registers, plain.registers)
        self.assertEqual([w.address for w in result.writes], [0x4100,0x4101,0x4102])
        self.assertEqual(plain.writes, ())

    def test_trace_cap_rejects_instead_of_returning_partial_success(self):
        with self.assertRaisesRegex(ValueError, 'max_writes'):
            self.execute('c6 06 00 01 11 c6 06 00 01 22',
                         write_ranges=((0x4100,0x4101),), max_writes=1)

    def test_executed_page_writes_fail_closed_in_trace_mode(self):
        with self.assertRaisesRegex(ValueError, 'executed code pages'):
            self.execute('2e c6 06 00 01 11', write_ranges=((0x1100,0x1101),))

    def test_trace_does_not_admit_devices(self):
        with self.assertRaisesRegex(ValueError, 'port I/O'):
            self.execute('ee', write_ranges=((0x1100,0x1101),))

    def test_invalid_intervals_reject(self):
        for interval in [(0,0),(-1,1),(0,0x20001)]:
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                self.execute('90', write_ranges=(interval,))
