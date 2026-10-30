from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dos_re_harness.remote_capture import RspClient


class RspTransportTests(unittest.TestCase):
    def test_small_ack_and_request_packets_are_not_batched(self) -> None:
        connection = Mock()
        with patch("dos_re_harness.remote_capture.socket.create_connection", return_value=connection):
            client = RspClient("localhost", 1234, 2.0)
        self.assertIs(client.sock, connection)
        connection.settimeout.assert_called_once_with(2.0)
        connection.setsockopt.assert_called_once_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


if __name__ == "__main__":
    unittest.main()
