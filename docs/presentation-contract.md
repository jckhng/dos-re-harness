# Strict Presentation Contracts

`dos_re_harness.presentation` provides dependency-free comparison after a
target adapter has normalized its captures. It does not know game addresses,
sprites, resolutions, resource IDs, emulator devices, or scene names. Existing
`dos-re` commands and capture adapters are unchanged.

```powershell
$env:PYTHONPATH = "$PWD/src"
python -m dos_re_harness.presentation compare expected.json actual.json --out comparison.json
python -m dos_re_harness.presentation audio actual.json audio-trace.json capture.wav --out audio-clock.json
```

Exit status: 0 passes, 1 is a valid comparison with differences, 2 indicates
invalid/incomplete evidence or an I/O error. Output files must not already
exist; reports hash their input manifests and, for audio, the WAV.

## Normalize At The Adapter Boundary

```json
{
  "format_version": 1,
  "complete": true,
  "phase": "after_present",
  "clock": {
    "id": "hardware",
    "rate_numerator": 70,
    "rate_denominator": 1,
    "counter_bits": 32
  },
  "domains": ["rgb"],
  "end_tick": 102,
  "frames": [
    {
      "sequence": 0,
      "boundary_id": "first-draw",
      "clock_tick": 100,
      "events_applied": true,
      "hashes": {"rgb": "0000000000000000000000000000000000000000000000000000000000000000"}
    },
    {
      "sequence": 1,
      "boundary_id": "held-draw",
      "clock_tick": 101,
      "events_applied": false,
      "hashes": {"rgb": "0000000000000000000000000000000000000000000000000000000000000000"}
    }
  ]
}
```

The all-zero hashes above are synthetic placeholders, not captured evidence.
Adapters must hash actual files and keep artifact identity/provenance in the
existing harness evidence manifest. The comparator compares declared digests;
it explicitly reports `artifact_files_verified=false`.

- Emit every relevant presentation in observed order, including multiple
  presentations within one simulation update. `sequence` is contiguous; a
  frozen simulation counter is not a frozen presentation clock.
- Derive `boundary_id` from the proven call/counter/owner boundary, independently
  on both sides. Do not choose IDs by searching for the nearest matching image.
- Use the same `phase` and hash-domain definitions on both sides. For indexed
  images, normally hash indices and palette separately; indexed equality alone
  does not prove displayed-color equality. Include dimensions and conversion
  rules in the target's evidence contract.
- Declare rational clock rates, not guessed FPS. Durations are compared using
  exact fractions, so equivalent 70 Hz and 140 Hz intervals can match.
- Use `counter_bits: null` for an unbounded monotonic counter. Wrapped counters
  require 2..64 bits and intervals strictly shorter than half their range;
  backward/ambiguous intervals are rejected.
- Supply the observed `end_tick` bounding the last visible interval. It is not
  inferred by repeating the preceding hold. `complete` means the declared
  capture window is complete, not that an entire game has been verified.

The comparison reports content, boundary order, count, phase and holds
separately. Missing or extra draws fail even if the common prefix matches.
Different clock origins are permitted because this contract compares durations;
scene-entry latency requires its own explicit entry boundary in the adapter.
There is no alignment search, masking, timestamp fitting, or expected-failure
promotion. Domain/phase/count failures remain failures even when all paired
hashes match.

## Audio Trace

```json
{
  "format_version": 1,
  "sample_count_policy": "floor_cumulative",
  "sample_rate": 44100,
  "frames": [
    {"sequence": 0, "boundary_id": "first-draw", "events_applied": true,
     "event_count": 1, "reset": false, "sample_start": 0, "sample_end": 630},
    {"sequence": 1, "boundary_id": "held-draw", "events_applied": false,
     "event_count": 0, "reset": false, "sample_start": 630, "sample_end": 1260}
  ]
}
```

Sample positions count interleaved PCM **frames**, not individual channel
samples. Mono and stereo are supported without resampling or mixdown. Each
endpoint is `floor(cumulative_duration * sample_rate)`, avoiding drift when
one presentation contains a fractional number of samples. The WAV must start
at sample zero for this capture window and contain exactly the traced duration.
Truncated payloads and format/rate/length mismatches fail.

`events_applied=false` permits the mixer and music to advance, but requires
zero newly applied events and no reset. The adapter must count all start/stop
events; an empty event list does not permit replaying a reset implicitly.
This validates chronology and sample accounting, not waveform fidelity or
physical sound-device timing. Use the existing WAV and register-write tools
for those separate domains.

## Tests

```powershell
$env:PYTHONPATH = "$PWD/src"
python -m unittest discover -s tests -p test_presentation.py -v
```

Fixtures are synthetic. No specimen, extracted frame, sound resource, Ghidra,
DOSBox, SDL, FFmpeg, NumPy, or Pillow is needed.
