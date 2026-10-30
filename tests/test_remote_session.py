import contextlib
import io
import hashlib
import json
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from dos_re_harness.remote_protocol import QmpClient, RspClient


class ConnectionOwnershipTests(unittest.TestCase):
    def session(self, marker, events):
        from dos_re_harness.remote_session import RemoteConnections
        rsp = Mock()
        rsp.read_memory_chunked.side_effect = lambda _address, size: bytes([marker]) * size
        rsp.close.side_effect = lambda: events.append('rsp-close')
        clients = []

        def qmp(*_args):
            client = QmpClient.__new__(QmpClient)
            client.command = Mock(side_effect=TimeoutError('stalled'))
            client.close = Mock(side_effect=lambda: events.append('qmp-close'))
            clients.append(client)
            return client

        session = RemoteConnections('localhost', 1, 2, 1, rsp_factory=Mock(return_value=rsp), qmp_factory=qmp)
        return session, rsp, clients

    def test_two_captures_do_not_share_memory_readers(self):
        first, _, _ = self.session(0xA1, [])
        second, _, _ = self.session(0xB2, [])
        QmpClient.set_memory_fallback(lambda _address, size: bytes([0xCC]) * size)
        self.addCleanup(QmpClient.set_memory_fallback, None)
        with first, second:
            first.open_rsp()
            second.open_rsp()
            a, b = first.open_qmp(), second.open_qmp()
            self.assertEqual(a.memdump(32, 4), bytes([0xA1]) * 4)
            self.assertEqual(b.memdump(32, 4), bytes([0xB2]) * 4)
            first.close()
            self.assertEqual(b.memdump(32, 4), bytes([0xB2]) * 4)

    def test_paused_load_client_gets_reader_only_after_rsp_connects(self):
        session, _, _ = self.session(0xA1, [])
        QmpClient.set_memory_fallback(lambda _address, size: b'x' * size)
        self.addCleanup(QmpClient.set_memory_fallback, None)
        with session:
            client = session.open_qmp()
            with self.assertRaises(TimeoutError):
                client.memdump(32, 4)
            session.open_rsp()
            self.assertEqual(client.memdump(32, 4), bytes([0xA1]) * 4)

    def test_rsp_failure_closes_already_open_load_client(self):
        session, _, clients = self.session(0, [])
        session._rsp_factory.side_effect = RuntimeError('rsp unavailable')
        with self.assertRaisesRegex(RuntimeError, 'rsp unavailable'), session:
            session.open_qmp()
            session.open_rsp()
        clients[0].close.assert_called_once_with()

    def test_explicit_release_and_final_cleanup_close_once_in_original_order(self):
        events = []
        session, rsp, clients = self.session(0, events)
        with session:
            session.open_rsp()
            released = session.open_qmp()
            session.close_qmp(released)
            session.close_qmp(released)
            session.open_qmp()
        session.close()
        self.assertEqual(events, ['qmp-close', 'rsp-close', 'qmp-close'])
        rsp.close.assert_called_once_with()
        for client in clients:
            client.close.assert_called_once_with()
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            session.open_qmp()

    def test_cleanup_failure_does_not_mask_capture_error_or_skip_clients(self):
        session, rsp, clients = self.session(0, [])
        rsp.close.side_effect = OSError('detach failure')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'capture failed'):
            with session:
                session.open_rsp()
                session.open_qmp()
                session.open_qmp()
                raise ValueError('capture failed')
        for client in clients:
            client.close.assert_called_once_with()

    def test_cleanup_failure_on_success_is_reported_after_other_clients_close(self):
        session, rsp, clients = self.session(0, [])
        rsp.close.side_effect = OSError('detach failure')
        with self.assertRaisesRegex(OSError, 'detach failure'), session:
            session.open_rsp()
            session.open_qmp()
        clients[0].close.assert_called_once_with()

    def test_failed_qmp_handshake_closes_socket(self):
        connection = Mock()
        with patch('dos_re_harness.remote_protocol.socket.create_connection', return_value=connection), \
                patch.object(QmpClient, '_recv_json', side_effect=RuntimeError('bad greeting')):
            with self.assertRaisesRegex(RuntimeError, 'bad greeting'):
                QmpClient('localhost', 1, 1)
        connection.close.assert_called_once_with()

    def test_failed_rsp_configuration_closes_socket(self):
        connection = Mock()
        connection.setsockopt.side_effect = OSError('socket option failed')
        with patch('dos_re_harness.remote_protocol.socket.create_connection', return_value=connection):
            with self.assertRaisesRegex(OSError, 'socket option failed'):
                RspClient('localhost', 1, 1)
        connection.close.assert_called_once_with()


class DriverOwnershipTests(unittest.TestCase):
    def test_paused_load_is_closed_when_rsp_connection_fails(self):
        from dos_re_harness import remote_capture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root/'runtime.sav'
            state.write_bytes(b'synthetic state')
            (root/'remote_runtime_registers.json').write_text(json.dumps(dict(
                save_state_sha256=hashlib.sha256(state.read_bytes()).hexdigest(), dump_segment_value=0x1000)))
            qmp = Mock(spec=QmpClient)
            qmp.supports_loadstate_paused = True
            args = ['remote_capture', '--out-dir', str(root/'capture'), '--load-save-state', str(state),
                    '--load-save-state-paused']
            with patch.object(sys, 'argv', args), patch.object(remote_capture, 'QmpClient', return_value=qmp), \
                    patch.object(remote_capture, 'RspClient', side_effect=RuntimeError('rsp unavailable')):
                with self.assertRaisesRegex(RuntimeError, 'rsp unavailable'):
                    remote_capture.main()
            qmp.load_state_paused.assert_called_once_with(state)
            qmp.close.assert_called_once_with()

    def test_halted_capture_keeps_artifacts_and_execution_order(self):
        from dos_re_harness import remote_capture
        events = []
        rsp = Mock(spec=RspClient)
        rsp.packet.side_effect = lambda command: events.append(command) or 'S05'
        rsp.continue_nowait.side_effect = lambda: events.append('continue')
        rsp.halt.side_effect = lambda _timeout: events.append('halt') or 'S02'
        rsp.registers.return_value = dict(eax=0x1234, cs=0x1000, ds=0x1000, ss=0x1000, esp=0x800,
                                          eip=0x10100, eflags=2)
        rsp.close.side_effect = lambda: events.append('detach')
        qmp = Mock(spec=QmpClient)
        qmp.memdump.side_effect = lambda address, size: events.append(('memory', address, size)) or bytes([0x2A])*size
        qmp.memdump_chunked.side_effect = qmp.memdump.side_effect
        qmp.close.side_effect = lambda: events.append('qmp-close')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = ['remote_capture', '--out-dir', directory, '--delay', '0', '--dump-segment', 'ds',
                    '--dump-size', '4', '--vga-width', '2', '--vga-height', '2']
            with patch.object(sys, 'argv', args), patch.object(remote_capture, 'RspClient', return_value=rsp), \
                    patch.object(remote_capture, 'QmpClient', return_value=qmp), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote_capture.main(), 0)
            self.assertEqual((root/'remote_runtime_ds.bin').read_bytes(), bytes([0x2A])*4)
            self.assertEqual((root/'remote_runtime_vga.bin').read_bytes(), bytes([0x2A])*4)
            self.assertEqual((root/'remote_runtime_vga.pgm').read_bytes(), b'P5\n2 2\n255\n' + bytes([0x2A])*4)
            self.assertEqual(json.loads((root/'remote_runtime_registers.json').read_text())['registers'], rsp.registers.return_value)
            self.assertTrue((root/'capture_summary.json').is_file())
        self.assertEqual(events, ['?', 'continue', 'halt', ('memory', 0x10000, 4),
                                  ('memory', 0xA0000, 4), 'detach', 'qmp-close'])


class _LoopbackServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class LoopbackProtocolTests(unittest.TestCase):
    def test_capture_clients_use_real_wire_and_never_replay_timed_out_qmp(self):
        from dos_re_harness.remote_session import RemoteConnections
        commands = []

        class QmpPeer(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b'{"QMP":{}}\n')
                for line in self.rfile:
                    message = json.loads(line)
                    name = message['execute']
                    commands.append(('qmp', name))
                    if name == 'memdump':
                        # Keep the channel open without replying: the real deadline must fire.
                        continue
                    response = [] if name == 'query-commands' else {}
                    self.wfile.write((json.dumps({'return': response})+'\n').encode())

        class RspPeer(socketserver.StreamRequestHandler):
            def handle(self):
                while True:
                    prefix = self.rfile.read(1)
                    if not prefix:
                        return
                    if prefix != b'$':
                        continue
                    payload = bytearray()
                    while True:
                        part = self.rfile.read(1)
                        if part == b'#':
                            break
                        if not part:
                            return
                        payload.extend(part)
                    checksum = self.rfile.read(2)
                    if int(checksum, 16) != sum(payload) & 255:
                        return
                    name = payload.decode()
                    commands.append(('rsp', name))
                    response = 'OK' if name == 'D' else 'a5' * int(name.split(',')[1], 16)
                    self.wfile.write(b'+' + f'${response}#{sum(response.encode()) & 255:02x}'.encode())
                    if name == 'D':
                        return

        with _LoopbackServer(('127.0.0.1', 0), RspPeer) as rsp_server, \
                _LoopbackServer(('127.0.0.1', 0), QmpPeer) as qmp_server:
            threads = [threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
                       for server in (rsp_server, qmp_server)]
            for thread in threads:
                thread.start()
            try:
                with RemoteConnections('127.0.0.1', rsp_server.server_address[1], qmp_server.server_address[1],
                                       0.2, rsp_factory=RspClient, qmp_factory=QmpClient) as session:
                    session.open_rsp()
                    qmp = session.open_qmp()
                    self.assertEqual(qmp.memdump(32, 4), bytes([0xA5]) * 4)
                    with self.assertRaisesRegex(RuntimeError, 'unusable'):
                        qmp.command('dacdump')
            finally:
                for server in (rsp_server, qmp_server):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)
        self.assertEqual(commands, [('qmp', 'qmp_capabilities'), ('qmp', 'query-commands'),
                                    ('qmp', 'memdump'), ('rsp', 'm20,4'), ('rsp', 'D')])
