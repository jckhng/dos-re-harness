import contextlib
from fractions import Fraction
import io
import json
from pathlib import Path
import tempfile
import unittest
import wave

from dos_re_harness.presentation import compare_presentations, main, validate_audio_video


def timeline():
    return {"format_version": 1, "complete": True, "phase": "after_present",
            "clock": {"id": "hardware", "rate_numerator": 70, "rate_denominator": 1, "counter_bits": 32},
            "domains": ["rgb", "palette"], "end_tick": 120,
            "frames": [{"sequence": i, "boundary_id": f"draw-{i}", "clock_tick": tick,
                        "simulation_tick": 7, "events_applied": i == 0,
                        "hashes": {"rgb": str(i) * 64, "palette": "a" * 64}}
                       for i, tick in enumerate((100, 106, 113))]}


def audio_trace(document, rate=44100):
    result = {"format_version": 1, "sample_count_policy": "floor_cumulative", "sample_rate": rate, "frames": []}
    ticks = [row["clock_tick"] for row in document["frames"]] + [document["end_tick"]]
    clock = document["clock"]
    elapsed = Fraction(0)
    start = 0
    for picture, a, b in zip(document["frames"], ticks, ticks[1:]):
        elapsed += Fraction((b - a) * clock["rate_denominator"], clock["rate_numerator"])
        end = int(elapsed * rate)
        result["frames"].append({"sequence": picture["sequence"], "boundary_id": picture["boundary_id"],
                                 "events_applied": picture["events_applied"], "event_count": int(picture["events_applied"]),
                                 "reset": False, "sample_start": start, "sample_end": end})
        start = end
    return result


def write_wave(path, frames, rate=44100, channels=1):
    with wave.open(str(path), "wb") as output:
        output.setparams((channels, 2, rate, frames, "NONE", "not compressed"))
        output.writeframes(bytes(frames * channels * 2))


class PresentationTests(unittest.TestCase):
    def test_equal_content_and_holds_with_frozen_simulation(self):
        value = timeline()
        result = compare_presentations(value, value)
        self.assertTrue(result["passed"])
        self.assertEqual(result["content_matches"], 3)
        self.assertEqual(result["hold_matches"], 3)
        self.assertFalse(result["artifact_files_verified"])

    def test_identical_pixels_do_not_hide_a_hold_mismatch(self):
        a, b = timeline(), timeline()
        b["frames"][1]["clock_tick"] += 1
        result = compare_presentations(a, b)
        self.assertFalse(result["passed"])
        self.assertEqual(result["content_matches"], 3)
        self.assertEqual(result["first_difference"]["index"], 0)
        self.assertEqual(result["hold_matches"], 1)

    def test_final_visible_hold_is_compared(self):
        a, b = timeline(), timeline()
        b["end_tick"] += 1
        result = compare_presentations(a, b)
        self.assertFalse(result["passed"])
        self.assertEqual(result["first_difference"]["index"], 2)

    def test_clock_rates_are_converted_exactly_not_assumed_equal(self):
        a, b = timeline(), timeline()
        b["clock"].update(id="presentation", rate_numerator=140)
        for row in b["frames"]:
            row["clock_tick"] = (row["clock_tick"] - 100) * 2
        b["end_tick"] = 40
        self.assertTrue(compare_presentations(a, b)["passed"])
        b["clock"]["rate_numerator"] = 141
        self.assertFalse(compare_presentations(a, b)["passed"])

    def test_counter_wrap_is_supported(self):
        a, b = timeline(), timeline()
        for row in b["frames"]:
            row["clock_tick"] = (row["clock_tick"] - 110) % (1 << 32)
        b["end_tick"] = 10
        self.assertTrue(compare_presentations(a, b)["passed"])

    def test_backward_or_half_range_intervals_are_rejected(self):
        for bits, tick in ((32, 99), (32, 100 + (1 << 31)), (None, 99)):
            value = timeline()
            value["clock"]["counter_bits"] = bits
            value["frames"][1]["clock_tick"] = tick
            with self.subTest(bits=bits, tick=tick), self.assertRaises(ValueError):
                compare_presentations(value, value)

    def test_missing_or_reordered_draws_are_not_aligned_away(self):
        a, b = timeline(), timeline()
        b["frames"] = b["frames"][:2]
        result = compare_presentations(a, b)
        self.assertFalse(result["passed"])
        self.assertEqual(result["first_unpaired_index"], 2)
        a, b = timeline(), timeline()
        b["frames"][0]["boundary_id"] = "different-call-site"
        self.assertFalse(compare_presentations(a, b)["passed"])
        b["frames"][1]["sequence"] = 9
        with self.assertRaises(ValueError):
            compare_presentations(a, b)

    def test_equal_pixels_from_different_boundary_phases_do_not_pass(self):
        a, b = timeline(), timeline()
        b["phase"] = "before_present"
        result = compare_presentations(a, b)
        self.assertFalse(result["passed"])
        self.assertFalse(result["phase_matches"])

    def test_event_application_boundaries_must_agree(self):
        a, b = timeline(), timeline()
        b["frames"][1]["events_applied"] = True
        report = compare_presentations(a, b)
        self.assertFalse(report["passed"])
        self.assertFalse(report["first_difference"]["events_applied_matches"])

    def test_palette_or_domain_changes_are_not_pixel_parity(self):
        a, b = timeline(), timeline()
        b["frames"][1]["hashes"]["palette"] = "f" * 64
        self.assertFalse(compare_presentations(a, b)["passed"])
        b = timeline()
        b["domains"] = ["indexed", "palette"]
        for row in b["frames"]:
            row["hashes"]["indexed"] = row["hashes"].pop("rgb")
        self.assertFalse(compare_presentations(a, b)["domains_match"])

    def test_invalid_metadata_fails_closed(self):
        for field, value in (("complete", False), ("complete", 1), ("format_version", True),
                             ("end_tick", None), ("end_tick", True), ("frames", []),
                             ("domains", []), ("domains", ["rgb", "rgb"]), ("phase", "")):
            document = timeline()
            document[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                compare_presentations(document, document)
        for field, value in (("rate_numerator", 0), ("rate_numerator", 70.0),
                             ("rate_denominator", True), ("counter_bits", 1), ("counter_bits", 65)):
            document = timeline()
            document["clock"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                compare_presentations(document, document)
        for field, value in (("sequence", True), ("clock_tick", 1 << 32), ("clock_tick", -1),
                             ("events_applied", 1), ("hashes", {"rgb": "0" * 64}),
                             ("hashes", {"rgb": "invalid", "palette": "a" * 64})):
            document = timeline()
            document["frames"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                compare_presentations(document, document)


class AudioVideoTests(unittest.TestCase):
    def test_mono_and_stereo_pcm_are_sample_aligned(self):
        doc = timeline()
        audio = audio_trace(doc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audio.wav"
            for channels in (1, 2):
                write_wave(path, 12600, channels=channels)
                report = validate_audio_video(doc, audio, path)
                self.assertEqual(report["sample_frames"], 12600)
                self.assertFalse(report["waveform_fidelity_verified"])

    def test_fractional_frame_sample_counts_use_cumulative_floor(self):
        doc = timeline()
        doc["clock"].update(rate_numerator=60000, rate_denominator=1001)
        for i, row in enumerate(doc["frames"]):
            row["clock_tick"] = i
        doc["end_tick"] = 3
        audio = audio_trace(doc)
        self.assertEqual([row["sample_end"] for row in audio["frames"]], [735, 1471, 2207])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audio.wav"
            write_wave(path, 2207)
            self.assertTrue(validate_audio_video(doc, audio, path)["passed"])

    def test_holds_must_not_repeat_events_or_resets(self):
        doc = timeline()
        for field, value in (("event_count", 1), ("reset", True), ("events_applied", True)):
            audio = audio_trace(doc)
            audio["frames"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_audio_video(doc, audio, Path("unused.wav"))

    def test_trace_order_and_sample_count_corruption_fail(self):
        doc = timeline()
        for field, value in (("sequence", 5), ("sequence", True), ("boundary_id", "wrong"),
                             ("sample_start", 1), ("sample_end", 1), ("event_count", True), ("reset", 1)):
            audio = audio_trace(doc)
            audio["frames"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_audio_video(doc, audio, Path("unused.wav"))

    def test_wrong_duration_rate_and_truncated_wav_fail(self):
        doc = timeline()
        audio = audio_trace(doc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audio.wav"
            for frames, rate in ((12599, 44100), (12601, 44100), (12600, 48000)):
                write_wave(path, frames, rate)
                with self.assertRaises(ValueError):
                    validate_audio_video(doc, audio, path)
            write_wave(path, 12600)
            path.write_bytes(path.read_bytes()[:-2])
            with self.assertRaises(ValueError):
                validate_audio_video(doc, audio, path)

    def test_boolean_versions_and_policy_mismatch_fail(self):
        doc = timeline()
        for key, value in (("format_version", True), ("sample_count_policy", "round_each"),
                           ("sample_rate", True), ("frames", [])):
            audio = audio_trace(doc)
            audio[key] = value
            with self.assertRaises(ValueError):
                validate_audio_video(doc, audio, Path("unused.wav"))


class PresentationCliTests(unittest.TestCase):
    def test_exit_codes_hashes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b, out = root / "a.json", root / "b.json", root / "report.json"
            a.write_text(json.dumps(timeline()), encoding="utf-8")
            b.write_bytes(a.read_bytes())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["compare", str(a), str(b), "--out", str(out)]), 0)
                report = json.loads(out.read_text())
                self.assertEqual(report["inputs"]["expected"]["sha256"], report["inputs"]["actual"]["sha256"])
                before = out.read_bytes()
                self.assertEqual(main(["compare", str(a), str(b), "--out", str(out)]), 2)
                self.assertEqual(out.read_bytes(), before)
                changed = timeline()
                changed["end_tick"] += 1
                b.write_text(json.dumps(changed), encoding="utf-8")
                self.assertEqual(main(["compare", str(a), str(b)]), 1)
                b.write_text("[]", encoding="utf-8")
                self.assertEqual(main(["compare", str(a), str(b)]), 2)

    def test_audio_command_writes_input_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            doc = timeline()
            (root / "video.json").write_text(json.dumps(doc), encoding="utf-8")
            (root / "audio.json").write_text(json.dumps(audio_trace(doc)), encoding="utf-8")
            write_wave(root / "audio.wav", 12600)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["audio", str(root / "video.json"), str(root / "audio.json"),
                                       str(root / "audio.wav"), "--out", str(root / "report.json")]), 0)
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(len(report["inputs"]["wav"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
