import base64
import unittest

from dos_re_harness.remote_capture import QmpClient


class VideoTimingTests(unittest.TestCase):
    def test_dacdump_preserves_optional_video_timing(self):
        timing = {
            "pic_ms": 1234.5678,
            "frame_start_ms": 1230.125,
            "frame_period_ms": 14.25,
            "line_period_ms": 0.03125,
            "retrace_start_ms": 12.5,
            "retrace_end_ms": 12.5625,
        }
        client = QmpClient.__new__(QmpClient)
        payload = {"data": base64.b64encode(bytes(768)).decode("ascii")}
        client.command = lambda *_args, **_kwargs: {"return": payload}
        self.assertNotIn("video_timing", client.dacdump())
        payload["video_timing"] = timing
        self.assertEqual(client.dacdump()["video_timing"], timing)

    def test_dacdump_rejects_invalid_video_timing(self):
        client = QmpClient.__new__(QmpClient)
        for timing in (None, [], {}, {"pic_ms": "bad"}, {"pic_ms": True},
                       {"pic_ms": float("nan")}, {"pic_ms": float("inf")}):
            with self.subTest(timing=timing):
                client.command = lambda *_args, **_kwargs: {
                    "return": {
                        "data": base64.b64encode(bytes(768)).decode("ascii"),
                        "video_timing": timing,
                    }
                }
                with self.assertRaisesRegex(RuntimeError, "video timing"):
                    client.dacdump()
