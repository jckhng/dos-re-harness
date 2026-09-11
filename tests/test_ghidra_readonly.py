import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GhidraReadonlySurfaceTests(unittest.TestCase):
    def test_readonly_is_distinct_from_noanalysis(self):
        source = (ROOT / "scripts/ghidra-query.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$ReadOnly", source)
        self.assertRegex(source, r'if \(\$ReadOnly\)\s*\{\s*\$headlessArgs \+= "-readOnly"')
        self.assertRegex(source, r'if \(\$NoAnalysis\)\s*\{\s*\$headlessArgs \+= "-noanalysis"')

    def test_raw_instruction_script_is_bounded_and_nonmutating(self):
        source = (ROOT / "ghidra/scripts/DumpRawInstructions.java").read_text(encoding="utf-8")
        self.assertIn("PseudoDisassembler", source)
        self.assertIn("end.subtract(cursor) >= 4096", source)
        self.assertIn("Range ends inside instruction", source)
        self.assertIn("monitor.checkCancelled()", source)
        self.assertNotRegex(source, r"\b(createFunction|clearListing|createData)\s*\(")
        self.assertNotRegex(source, r"(?<!\.)\bdisassemble\s*\(")

    def test_segmented_offsets_are_explicit_candidates(self):
        source = (ROOT / "ghidra/scripts/FindMemoryRangeRefs.java").read_text(encoding="utf-8")
        self.assertIn("getSegmentOffset()", source)
        self.assertIn("--offset-candidates", source)
        self.assertIn("segment_not_proven=true", source)
        self.assertIn("first.getSegment() != last.getSegment()", source)
        self.assertIn("!offsets &&", source)


if __name__ == "__main__":
    unittest.main()
