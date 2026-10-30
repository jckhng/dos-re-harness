from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dos_re_harness.cli import build_parser, command_capture, command_diff_state
from dos_re_harness.remote_capture import QmpClient, RspClient


FIXTURE = Path(__file__).parent / "fixtures/minimal-project"


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeout = 1.0

    def recv(self, size):
        if not self.chunks:
            return b""
        data = self.chunks.pop(0)
        if len(data) > size:
            self.chunks.insert(0, data[size:])
        return data[:size]

    def sendall(self, data):
        self.sent.append(data)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout


class ProtocolReliabilityTests(unittest.TestCase):
    def test_rsp_rejects_corrupt_checksum(self):
        client = RspClient.__new__(RspClient)
        client.sock = FragmentedSocket([b"$OK#00"])
        with self.assertRaisesRegex(RuntimeError, "checksum"):
            client._recv_packet()
        self.assertNotIn(b"+", client.sock.sent)

    def test_rsp_reads_fragmented_checksum(self):
        client = RspClient.__new__(RspClient)
        client.sock = FragmentedSocket([b"$OK#9", b"a"])
        self.assertEqual(client._recv_packet(), "OK")
        self.assertEqual(client.sock.chunks, [])
        self.assertEqual(client.sock.sent, [b"+"])

    def test_rsp_rejects_truncated_checksum(self):
        client = RspClient.__new__(RspClient)
        client.sock = FragmentedSocket([b"$OK#9"])
        with self.assertRaisesRegex(RuntimeError, "closed"):
            client._recv_packet()

    def test_qmp_retains_coalesced_messages(self):
        client = QmpClient.__new__(QmpClient)
        client.sock = FragmentedSocket([b'{"event":"STOP"}\r\n{"return":{}}\r\n'])
        self.assertEqual(client._recv_json(), {"event": "STOP"})
        self.assertEqual(client._recv_json(), {"return": {}})

    def test_qmp_command_skips_events_before_its_reply(self):
        client = QmpClient.__new__(QmpClient)
        client.sock = FragmentedSocket([b'{"event":"STOP"}\n', b'{"return":{"ok":true}}\n'])
        self.assertEqual(client.command("query-status"), {"return": {"ok": True}})

    def test_qmp_accepts_fragmented_utf8(self):
        client = QmpClient.__new__(QmpClient)
        client.sock = FragmentedSocket([b'{"return":"\xc3', b'\xa9"}\n'])
        self.assertEqual(client._recv_json(), {"return": "é"})

    def test_qmp_timeout_prevents_late_reply_reuse(self):
        client = QmpClient.__new__(QmpClient)
        client.sock = Mock()
        client.sock.gettimeout.return_value = 1.0
        client.sock.recv.side_effect = TimeoutError("stalled")
        with self.assertRaises(TimeoutError):
            client.command("memdump")
        with self.assertRaisesRegex(RuntimeError, "unusable"):
            client.command("dacdump")
        self.assertEqual(client.sock.sendall.call_count, 1)

    def test_legacy_socket_timeout_uses_the_connection_memory_reader(self):
        class LegacySocketTimeout(OSError):
            pass

        client = QmpClient.__new__(QmpClient)
        client.command = Mock(side_effect=LegacySocketTimeout("stalled"))
        reader = Mock(return_value=b"abcd")
        client.set_memory_reader(reader)
        with patch("dos_re_harness.remote_protocol.socket.timeout", LegacySocketTimeout):
            self.assertEqual(client.memdump(32, 4), b"abcd")
        reader.assert_called_once_with(32, 4)

    def test_qmp_retains_partial_utf8_after_complete_message(self):
        client = QmpClient.__new__(QmpClient)
        client.sock = FragmentedSocket([b'{"return":{}}\n{"event":"\xc3', b'\xa9"}\n'])
        self.assertEqual(client._recv_json(), {"return": {}})
        self.assertEqual(client._recv_json(), {"event": "é"})


class CaptureReliabilityTests(unittest.TestCase):
    def test_missing_state_fields_fail_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text("{}", encoding="utf-8")
            args = build_parser().parse_args([
                "diff-state", "--schema", str(FIXTURE / "state.schema.json"),
                "--original", str(state), "--reimplementation", str(state),
            ])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(command_diff_state(args), 1)

    def test_partial_comparison_requires_explicit_option(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text("{}", encoding="utf-8")
            args = build_parser().parse_args([
                "diff-state", "--schema", str(FIXTURE / "state.schema.json"),
                "--original", str(state), "--reimplementation", str(state), "--allow-missing",
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(command_diff_state(args), 0)
            self.assertIn("0 match, 0 diff", output.getvalue())
            self.assertIn("skipped", output.getvalue())

    def test_capture_records_inputs_before_adapter_mutates_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(FIXTURE, root / "project")
            project_path = root / "project/project.json"
            document = json.loads(project_path.read_text())
            document["specimen"] = {"root": ".", "mutable_files": ["SAVE.DAT"]}
            project_path.write_text(json.dumps(document), encoding="utf-8")
            save = project_path.parent / "SAVE.DAT"
            save.write_bytes(b"before")
            movie = project_path.parent / "movies/boot.movie.json"
            movie_hash = hashlib.sha256(movie.read_bytes()).hexdigest()
            output = root / "capture"

            def execute(*args, **kwargs):
                save.write_bytes(b"after")
                movie.write_text("{}", encoding="utf-8")
                return Mock(returncode=3)

            args = build_parser().parse_args([
                "capture", str(project_path), "boot", "--out-dir", str(output),
            ])
            with patch("dos_re_harness.cli.subprocess.run", side_effect=execute), \
                    patch("dos_re_harness.evidence.git_commit", return_value="fixture"):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(command_capture(args), 3)
            manifest = json.loads((output / "harness_manifest.json").read_text())
            self.assertEqual(manifest["contracts"]["input_movie"]["sha256"], movie_hash)
            self.assertEqual(manifest["capture"]["mutable_baseline"][0]["sha256"],
                             hashlib.sha256(b"before").hexdigest())
            self.assertEqual(manifest["capture"]["mutable_after"][0]["sha256"],
                             hashlib.sha256(b"after").hexdigest())


if __name__ == "__main__":
    unittest.main()
