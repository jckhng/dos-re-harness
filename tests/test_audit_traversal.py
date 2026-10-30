from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from dos_re_harness.audit import audit_public_tree


class AuditTraversalTests(unittest.TestCase):
    def test_ignored_subtrees_are_never_enumerated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ignored = root / 'project' / '.work'
            ignored.mkdir(parents=True)
            (ignored / 'private.exe').write_bytes(b'MZ')
            (root / 'public.txt').write_text('public')
            original = os.scandir

            def guarded(path):
                self.assertNotIn('.work', Path(path).relative_to(root).parts)
                return original(path)

            with patch('os.scandir', guarded):
                self.assertEqual(audit_public_tree(root), [])

    def test_findings_keep_global_path_and_per_file_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').mkdir()
            (root / 'a/z.exe').write_bytes(b'MZ')
            (root / 'a.txt').write_bytes(b'PK\x03\x04')
            self.assertEqual(audit_public_tree(root), [
                f'{Path("a/z.exe")}: forbidden publication file type',
                f'{Path("a/z.exe")}: detected DOS/Windows executable',
                'a.txt: detected ZIP archive',
            ])
