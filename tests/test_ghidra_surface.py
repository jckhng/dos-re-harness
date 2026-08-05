import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GhidraQuerySurfaceTests(unittest.TestCase):
    def test_public_queries_map_to_shipped_scripts(self):
        wrapper = (ROOT / "scripts" / "ghidra-query.ps1").read_text(
            encoding="utf-8"
        )
        mappings = dict(
            re.findall(
                r'^\s*"([^"]+)"\s*\{\s*"([^"]+\.java)"\s*\}\s*$',
                wrapper,
                flags=re.MULTILINE,
            )
        )
        expected = {
            "decompile": "DumpFunctionDecomp.java",
            "instructions": "DumpInstructions.java",
            "xrefs": "FindFunctionXrefs.java",
            "functions": "ListFunctionsStdout.java",
            "programs": "ListProgramsStdout.java",
            "scalar": "FindScalarUsage.java",
            "instruction-text": "FindInstructionText.java",
            "memory-range-refs": "FindMemoryRangeRefs.java",
            "bytes-and-callers": "FindBytesAndCallers.java",
            "bulk-copy": "FindBulkCopyPatterns.java",
            "dump-range": "DumpRangeStdout.java",
            "direct-offset": "FindDirectOffsetUsage.java",
            "raw-string": "FindRawStringUsage.java",
            "defined-string": "FindStringUsage.java",
        }
        self.assertEqual(expected, mappings)
        for script in mappings.values():
            self.assertTrue(
                (ROOT / "ghidra" / "scripts" / script).is_file(),
                script,
            )

    def test_generic_scripts_do_not_declare_project_categories(self):
        scripts = ROOT / "ghidra" / "scripts"
        for path in scripts.glob("*.java"):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotRegex(source, r"@category\s+\S+")


if __name__ == "__main__":
    unittest.main()
