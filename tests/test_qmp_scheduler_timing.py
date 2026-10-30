import base64
import copy
import tempfile
import unittest
from pathlib import Path

from dos_re_harness.remote_capture import QmpClient, write_vga_dac_sequence_sample


class SchedulerTimingTests(unittest.TestCase):
    def _dacdump(self, timing):
        client = QmpClient.__new__(QmpClient)
        client.command = lambda *_args, **_kwargs: {
            "return": {"data": base64.b64encode(bytes(768)).decode("ascii"), "cpu_timing": timing}
        }
        return client.dacdump()

    def test_preserves_signed_budget_and_ordered_events(self):
        timing = {"remaining_cycles": -3, "deferred_cycles": 4000,
                  "debug_instruction_count": (1 << 53) + 1,
                  "pic_events": [{"tick_index": 0.125, "handler": 3, "value": 7},
                                 {"tick_index": 0.5, "handler": 65535, "value": (1 << 63) + 1}]}
        self.assertEqual(self._dacdump(timing)["cpu_timing"], timing)
        self.assertEqual(self._dacdump({"pic_events": []})["cpu_timing"], {"pic_events": []})
        with tempfile.TemporaryDirectory() as directory:
            sample = write_vga_dac_sequence_sample(Path(directory), 0, bytes(4), self._dacdump(timing))
            self.assertEqual(sample["dac"]["cpu_timing"], timing)

    def test_rejects_invalid_scheduler_fields(self):
        event = {"tick_index": 0.25, "handler": 3, "value": 7}
        bad_events = [None, {}, [None], [dict(event, extra=0)],
                      [dict(event, tick_index=True)], [dict(event, tick_index=float("nan"))],
                      [dict(event, tick_index=float("inf"))], [dict(event, handler=True)],
                      [dict(event, handler=-1)], [dict(event, handler=65536)],
                      [dict(event, value=-1)], [dict(event, value=1 << 64)],
                      [dict(event, tick_index=0.5), event]]
        for events in bad_events:
            with self.subTest(events=events):
                with self.assertRaisesRegex(RuntimeError, "CPU timing"):
                    self._dacdump({"pic_events": copy.deepcopy(events)})
        for name, value in (("remaining_cycles", True), ("remaining_cycles", -(1 << 63) - 1),
                            ("deferred_cycles", 1 << 63), ("debug_instruction_count", -1),
                            ("unknown", [])):
            with self.subTest(name=name, value=value):
                with self.assertRaisesRegex(RuntimeError, "CPU timing"):
                    self._dacdump({name: value})
