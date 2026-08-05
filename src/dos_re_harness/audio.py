"""Dependency-free PCM WAV inspection and differential comparison."""

from __future__ import annotations

import hashlib
import math
import struct
import wave
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _decode_samples(data: bytes, sample_width: int) -> list[int]:
    if sample_width == 1:
        return [value - 128 for value in data]
    if sample_width == 2:
        count = len(data) // 2
        return list(struct.unpack(f"<{count}h", data))
    if sample_width == 3:
        samples = []
        for offset in range(0, len(data), 3):
            value = int.from_bytes(data[offset : offset + 3], "little")
            if value & 0x800000:
                value -= 0x1000000
            samples.append(value)
        return samples
    if sample_width == 4:
        count = len(data) // 4
        return list(struct.unpack(f"<{count}i", data))
    raise ValueError(
        f"unsupported PCM sample width: {sample_width} bytes"
    )


def _read_wave(path: Path) -> tuple[dict[str, Any], list[tuple[int, ...]]]:
    path = path.resolve()
    with wave.open(str(path), "rb") as source:
        if source.getcomptype() != "NONE":
            raise ValueError(
                f"{path}: compressed WAV is unsupported: "
                f"{source.getcomptype()}"
            )
        channels = source.getnchannels()
        sample_width = source.getsampwidth()
        sample_rate = source.getframerate()
        frame_count = source.getnframes()
        raw = source.readframes(frame_count)
    samples = _decode_samples(raw, sample_width)
    expected_samples = frame_count * channels
    if len(samples) != expected_samples:
        raise ValueError(
            f"{path}: expected {expected_samples} PCM samples, "
            f"decoded {len(samples)}"
        )
    frames = [
        tuple(samples[offset : offset + channels])
        for offset in range(0, len(samples), channels)
    ]
    return (
        {
            "path": str(path),
            "sha256": _sha256_file(path),
            "bytes": path.stat().st_size,
            "encoding": "PCM",
            "channels": channels,
            "sample_rate": sample_rate,
            "sample_width_bits": sample_width * 8,
            "frame_count": frame_count,
            "duration_seconds": (
                frame_count / sample_rate if sample_rate else 0.0
            ),
        },
        frames,
    )


def _sample_metrics(samples: list[int | float]) -> dict[str, Any]:
    if not samples:
        return {
            "minimum": 0,
            "maximum": 0,
            "peak": 0,
            "dc_offset": 0.0,
            "rms": 0.0,
        }
    return {
        "minimum": min(samples),
        "maximum": max(samples),
        "peak": max(abs(value) for value in samples),
        "dc_offset": sum(samples) / len(samples),
        "rms": math.sqrt(
            sum(value * value for value in samples) / len(samples)
        ),
    }


def summarize_wave(path: Path) -> dict[str, Any]:
    """Return stable format, hash, and signal metrics for a PCM WAV file."""

    metadata, frames = _read_wave(path)
    flat = [sample for frame in frames for sample in frame]
    channel_metrics = [
        _sample_metrics([frame[channel] for frame in frames])
        for channel in range(metadata["channels"])
    ]
    return {
        **metadata,
        **_sample_metrics(flat),
        "channel_metrics": channel_metrics,
    }


def _mixdown(frames: list[tuple[int, ...]]) -> list[tuple[float]]:
    return [
        (sum(frame) / len(frame),)
        for frame in frames
    ]


def compare_waves(
    expected_path: Path,
    actual_path: Path,
    *,
    mixdown: bool = False,
    sample_tolerance: int = 0,
    skip_expected_frames: int = 0,
    skip_actual_frames: int = 0,
) -> dict[str, Any]:
    """Compare two PCM WAV streams after explicit, reproducible transforms."""

    if sample_tolerance < 0:
        raise ValueError("sample tolerance must not be negative")
    if skip_expected_frames < 0 or skip_actual_frames < 0:
        raise ValueError("frame skips must not be negative")
    expected_metadata, expected = _read_wave(expected_path)
    actual_metadata, actual = _read_wave(actual_path)
    format_differences = {}
    for field in ("sample_rate", "sample_width_bits"):
        if expected_metadata[field] != actual_metadata[field]:
            format_differences[field] = {
                "expected": expected_metadata[field],
                "actual": actual_metadata[field],
            }
    if not mixdown and expected_metadata["channels"] != actual_metadata["channels"]:
        format_differences["channels"] = {
            "expected": expected_metadata["channels"],
            "actual": actual_metadata["channels"],
        }
    if format_differences:
        return {
            "format_version": 1,
            "formats_compatible": False,
            "format_differences": format_differences,
            "expected": expected_metadata,
            "actual": actual_metadata,
        }
    if mixdown:
        expected = _mixdown(expected)
        actual = _mixdown(actual)
    expected = expected[skip_expected_frames:]
    actual = actual[skip_actual_frames:]
    common_frames = min(len(expected), len(actual))
    channel_count = 1 if mixdown else expected_metadata["channels"]
    errors = [
        actual[index][channel] - expected[index][channel]
        for index in range(common_frames)
        for channel in range(channel_count)
    ]
    first_different_frame = None
    different_samples = 0
    for index in range(common_frames):
        frame_differs = False
        for channel in range(channel_count):
            if abs(actual[index][channel] - expected[index][channel]) > sample_tolerance:
                different_samples += 1
                frame_differs = True
        if frame_differs and first_different_frame is None:
            first_different_frame = index
    tail_frames = abs(len(expected) - len(actual))
    different_samples += tail_frames * channel_count
    if tail_frames and first_different_frame is None:
        first_different_frame = common_frames
    maximum_absolute_error = max((abs(value) for value in errors), default=0)
    rmse = math.sqrt(
        sum(value * value for value in errors) / len(errors)
    ) if errors else 0.0
    expected_samples = [
        expected[index][channel]
        for index in range(common_frames)
        for channel in range(channel_count)
    ]
    actual_samples = [
        actual[index][channel]
        for index in range(common_frames)
        for channel in range(channel_count)
    ]
    expected_rms = _sample_metrics(expected_samples)["rms"]
    actual_rms = _sample_metrics(actual_samples)["rms"]
    expected_mean = (
        sum(expected_samples) / len(expected_samples)
        if expected_samples else 0.0
    )
    actual_mean = (
        sum(actual_samples) / len(actual_samples)
        if actual_samples else 0.0
    )
    covariance = sum(
        (left - expected_mean) * (right - actual_mean)
        for left, right in zip(expected_samples, actual_samples)
    )
    expected_energy = sum(
        (value - expected_mean) ** 2 for value in expected_samples
    )
    actual_energy = sum(
        (value - actual_mean) ** 2 for value in actual_samples
    )
    correlation = (
        covariance / math.sqrt(expected_energy * actual_energy)
        if expected_energy and actual_energy
        else None
    )
    return {
        "format_version": 1,
        "formats_compatible": True,
        "format_differences": {},
        "mixdown": mixdown,
        "sample_tolerance": sample_tolerance,
        "skip_expected_frames": skip_expected_frames,
        "skip_actual_frames": skip_actual_frames,
        "expected": expected_metadata,
        "actual": actual_metadata,
        "compared_frames": common_frames,
        "expected_remaining_frames": len(expected),
        "actual_remaining_frames": len(actual),
        "frame_count_delta": len(actual) - len(expected),
        "different_samples": different_samples,
        "first_different_frame": first_different_frame,
        "maximum_absolute_error": maximum_absolute_error,
        "rmse": rmse,
        "expected_rms": expected_rms,
        "actual_rms": actual_rms,
        "normalized_rmse": rmse / expected_rms if expected_rms else None,
        "correlation": correlation,
        "match": different_samples == 0,
    }
