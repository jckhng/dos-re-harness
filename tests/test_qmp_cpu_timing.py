import base64
import unittest

from dos_re_harness.remote_capture import QmpClient


class CpuTimingTests(unittest.TestCase):
    def test_dacdump_preserves_optional_integer_cpu_timing(self):
        timing = {
            "debug_instruction_count": (1 << 53) + 1,
            "core_normal": 1,
            "cycle_budget_per_ms": 5000,
            "removed_delay_cycles": 123456789,
            "auto_cycle_adjust": 0,
            "string_iterations": (1 << 53) + 3,
        }
        client = QmpClient.__new__(QmpClient)
        payload = {"data": base64.b64encode(bytes(768)).decode("ascii")}
        client.command = lambda *_args, **_kwargs: {"return": payload}
        self.assertNotIn("cpu_timing", client.dacdump())
        payload["cpu_timing"] = timing
        self.assertEqual(client.dacdump()["cpu_timing"], timing)

    def test_dacdump_rejects_invalid_cpu_timing(self):
        client = QmpClient.__new__(QmpClient)
        for timing in (None, [], {}, {"debug_instruction_count": "bad"},
                       {"debug_instruction_count": True},
                       {"debug_instruction_count": 1.0},
                       {"debug_instruction_count": -1},
                       {"debug_instruction_count": 1 << 64}):
            with self.subTest(timing=timing):
                client.command = lambda *_args, **_kwargs: {
                    "return": {
                        "data": base64.b64encode(bytes(768)).decode("ascii"),
                        "cpu_timing": timing,
                    }
                }
                with self.assertRaisesRegex(RuntimeError, "CPU timing"):
                    client.dacdump()
