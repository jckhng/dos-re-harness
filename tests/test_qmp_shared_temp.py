import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dos_re_harness.remote_capture import QmpClient


class QmpSharedTempTests(unittest.TestCase):
    def test_shared_directory_reads_exact_memory_and_cleans_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            client = QmpClient.__new__(QmpClient)
            observed = []

            def command(name, arguments):
                self.assertEqual((name, arguments['address'], arguments['size']), ('memdump', 32, 4))
                path = Path(arguments['file'])
                self.assertIn(Path(directory), path.parents)
                observed.append(path)
                path.write_bytes(b'abcd')
                return {'return': {'file': str(path)}}

            client.command = command
            with patch.dict('os.environ', {'DOS_RE_HARNESS_QMP_TEMP_DIRECTORY': directory}):
                self.assertEqual(client.memdump(32, 4), b'abcd')
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].parent.exists())

    def test_default_path_preserves_base64_protocol(self):
        client = QmpClient.__new__(QmpClient)
        observed = []

        def command(name, arguments):
            observed.append((name, arguments))
            return {'return': {'data': base64.b64encode(b'abcd').decode()}}

        client.command = command
        with patch.dict('os.environ', {'DOS_RE_HARNESS_QMP_TEMP_DIRECTORY': ''}):
            self.assertEqual(client.memdump(32, 4), b'abcd')
        self.assertEqual(observed, [('memdump', {'address': 32, 'size': 4})])

    def test_truncated_memory_rejects(self):
        client = QmpClient.__new__(QmpClient)
        client.command = lambda *_args: {'return': {'data': ''}}
        with patch.dict('os.environ', {'DOS_RE_HARNESS_QMP_TEMP_DIRECTORY': ''}):
            with self.assertRaisesRegex(RuntimeError, 'unexpected size'):
                client.memdump(32, 4)


if __name__ == '__main__':
    unittest.main()
