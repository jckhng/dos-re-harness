from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from dos_re_harness.program_index import mapped_inventory
from dos_re_harness.progress import build_report


class ProgramIndexTests(unittest.TestCase):
    def test_import_only_maps_and_matches_existing_progress_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image,index,out = root/'image',root/'index.json',root/'inventory.json'
            image.write_bytes(bytes(64))
            index.write_text(json.dumps(dict(format_version=1,
                program=dict(executable_sha256=hashlib.sha256(image.read_bytes()).hexdigest()),
                functions=[dict(id='ram:0010',name='function',entry=dict(space='ram',offset='10'))])))
            inventory = mapped_inventory(index,image,out)
            out.write_text(json.dumps(inventory))
            report = build_report(out)
            self.assertEqual(inventory['units'][0]['ranges'],[])
            self.assertFalse(inventory['units'][0]['integrated'])
            self.assertFalse(inventory['inventory_complete'])
            self.assertTrue(report)
            image.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'identity'):
                mapped_inventory(index,image,out)
