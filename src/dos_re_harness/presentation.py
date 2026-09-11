"""Strict ordered presentation and PCM-clock contracts; no target adapters."""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
import wave


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _duration(delta: Fraction) -> dict[str, int]:
    return {"numerator": delta.numerator, "denominator": delta.denominator}


def _timeline(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Fraction]]:
    if not isinstance(document, dict):
        raise ValueError("presentation manifest must be an object")
    if type(document.get("format_version")) is not int or document["format_version"] != 1:
        raise ValueError("unsupported presentation format_version")
    if document.get("complete") is not True:
        raise ValueError("complete presentation capture required")
    _name(document.get("phase"), "phase")
    clock = document["clock"]
    if not isinstance(clock, dict):
        raise ValueError("clock must be an object")
    _name(clock.get("id"), "clock.id")
    rate = Fraction(_integer(clock.get("rate_numerator"), "clock rate", 1),
                    _integer(clock.get("rate_denominator"), "clock denominator", 1))
    bits = clock.get("counter_bits")
    if bits is not None and (type(bits) is not int or not 2 <= bits <= 64):
        raise ValueError("counter_bits must be null or an integer in 2..64")
    domains = document["domains"]
    if not isinstance(domains, list) or not domains:
        raise ValueError("at least one content hash domain is required")
    for name in domains:
        _name(name, "hash domain")
    if len(set(domains)) != len(domains):
        raise ValueError("duplicate hash domain")
    rows = document["frames"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("empty presentation timeline")
    ticks = []
    previous = None
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("frame must be an object")
        sequence = _integer(row.get("sequence"), "sequence")
        if previous is not None and sequence != previous + 1:
            raise ValueError("missing or reordered presentation sequence")
        previous = sequence
        _name(row.get("boundary_id"), "boundary_id")
        if type(row.get("events_applied")) is not bool:
            raise ValueError("events_applied must be boolean")
        hashes = row["hashes"]
        if not isinstance(hashes, dict) or set(hashes) != set(domains):
            raise ValueError("frame hash domains disagree with the manifest")
        for digest in hashes.values():
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("expected lowercase SHA-256 digest")
        ticks.append(_integer(row.get("clock_tick"), "clock_tick"))
    # An explicit endpoint avoids silently dropping the final visible hold.
    ticks.append(_integer(document.get("end_tick"), "end_tick"))
    if bits is not None and any(tick >= 1 << bits for tick in ticks):
        raise ValueError("clock tick exceeds its declared counter width")
    durations = []
    for left, right in zip(ticks, ticks[1:]):
        elapsed = right - left
        if bits is not None:
            elapsed %= 1 << bits
            if elapsed >= 1 << (bits - 1):
                raise ValueError("backward or ambiguous wrapped clock interval")
        elif elapsed < 0:
            raise ValueError("clock moved backward")
        durations.append(Fraction(elapsed, 1) / rate)
    return rows, durations


def compare_presentations(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Compare declared hash domains, boundary order and exact rational holds.

    Adapters must hash the actual artifacts. This function does not locate or
    authenticate their files, infer boundary identities, or align nearby draws.
    """
    left, left_holds = _timeline(expected)
    right, right_holds = _timeline(actual)
    phase_matches = expected["phase"] == actual["phase"]
    domains_match = set(expected["domains"]) == set(actual["domains"])
    count_matches = len(left) == len(right)
    comparisons = []
    for index, (a, b, ah, bh) in enumerate(zip(left, right, left_holds, right_holds)):
        comparisons.append({"index": index, "expected_boundary": a["boundary_id"],
                            "actual_boundary": b["boundary_id"],
                            "boundary_matches": a["boundary_id"] == b["boundary_id"],
                            "events_applied_matches": a["events_applied"] == b["events_applied"],
                            "content_matches": a["hashes"] == b["hashes"],
                            "expected_hold_seconds": _duration(ah),
                            "actual_hold_seconds": _duration(bh), "hold_matches": ah == bh})
    first = next((row for row in comparisons if not all(row[field] for field in (
        "boundary_matches", "events_applied_matches", "content_matches", "hold_matches"))), None)
    passed = phase_matches and domains_match and count_matches and first is None
    return {"format_version": 1, "passed": passed, "phase_matches": phase_matches,
            "domains_match": domains_match, "count_matches": count_matches,
            "expected_count": len(left), "actual_count": len(right),
            "content_matches": sum(row["content_matches"] for row in comparisons),
            "hold_matches": sum(row["hold_matches"] for row in comparisons),
            "first_difference": first,
            "first_unpaired_index": None if count_matches else min(len(left), len(right)),
            "artifact_files_verified": False, "alignment_search": False,
            "comparisons": comparisons}


def validate_audio_video(timeline: dict[str, Any], audio: dict[str, Any], wav_path: Path) -> dict[str, Any]:
    """Check cumulative sample counts and prevent event replay on held pictures."""
    rows, durations = _timeline(timeline)
    if not isinstance(audio, dict):
        raise ValueError("audio trace must be an object")
    if type(audio.get("format_version")) is not int or audio["format_version"] != 1:
        raise ValueError("unsupported audio format_version")
    if audio.get("sample_count_policy") != "floor_cumulative":
        raise ValueError("audio must declare floor_cumulative sample counting")
    rate = _integer(audio.get("sample_rate"), "sample_rate", 1)
    frames = audio["frames"]
    if not isinstance(frames, list) or len(frames) != len(rows):
        raise ValueError("audio/video presentation counts differ")
    elapsed = Fraction(0)
    expected_start = 0
    for picture, hold, sound in zip(rows, durations, frames):
        if not isinstance(sound, dict):
            raise ValueError("audio frame must be an object")
        if (_integer(sound.get("sequence"), "audio sequence") != picture["sequence"] or
                sound.get("boundary_id") != picture["boundary_id"] or
                sound.get("events_applied") is not picture["events_applied"]):
            raise ValueError("audio/video presentation order differs")
        events = _integer(sound.get("event_count"), "event_count")
        if type(sound.get("reset")) is not bool:
            raise ValueError("audio reset must be boolean")
        if not picture["events_applied"] and (events or sound["reset"]):
            raise ValueError("audio hold replays events or resets the mixer")
        elapsed += hold
        expected_end = int(elapsed * rate)
        if (_integer(sound.get("sample_start"), "sample_start") != expected_start or
                _integer(sound.get("sample_end"), "sample_end") != expected_end):
            raise ValueError("audio samples disagree with the presentation clock")
        expected_start = expected_end
    with wave.open(str(wav_path), "rb") as source:
        if (source.getcomptype() != "NONE" or source.getframerate() != rate or
                source.getnframes() != expected_start):
            raise ValueError("WAV format/duration disagrees with the audio trace")
        if len(source.readframes(expected_start)) != expected_start * source.getnchannels() * source.getsampwidth():
            raise ValueError("truncated WAV payload")
    return {"format_version": 1, "passed": True, "presentations": len(rows),
            "sample_frames": expected_start, "sample_rate": rate,
            "duration_seconds": _duration(elapsed), "waveform_fidelity_verified": False}


def _load(path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    data = path.read_bytes()
    return json.loads(data.decode("utf-8-sig")), {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("expected", type=Path)
    compare.add_argument("actual", type=Path)
    check = sub.add_parser("audio")
    check.add_argument("timeline", type=Path)
    check.add_argument("trace", type=Path)
    check.add_argument("wav", type=Path)
    for command in (compare, check):
        command.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            expected, a = _load(args.expected)
            actual, b = _load(args.actual)
            result = compare_presentations(expected, actual)
            result["inputs"] = {"expected": a, "actual": b}
        else:
            timeline, a = _load(args.timeline)
            trace, b = _load(args.trace)
            result = validate_audio_video(timeline, trace, args.wav)
            result["inputs"] = {"timeline": a, "trace": b,
                                "wav": {"path": str(args.wav), "sha256": hashlib.sha256(args.wav.read_bytes()).hexdigest()}}
        rendered = json.dumps(result, indent=2) + "\n"
        if args.out:
            with args.out.open("x", encoding="utf-8") as output:
                output.write(rendered)
        print(rendered, end="")
        return 0 if result["passed"] else 1
    except (ValueError, TypeError, KeyError, OSError, wave.Error, EOFError) as error:
        print(f"presentation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
