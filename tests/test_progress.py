from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".work/tests"
sys.path.insert(0, str(ROOT / "src"))
from dos_re_harness import progress


class ProgressTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="progress-test-", dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "inventory.json"
        self.source = self.binding("code.bin", bytes(range(100)))
        self.specimen = self.binding("specimen.bin", b"specimen")
        self.implementation = self.binding("implementation.cpp", b"implemented source")
        self.evidence = self.binding("evidence.json", b"independent evidence")
        self.input = self.binding("input.json", b"scenario input")
        self.inventory = dict(
            format_version=1, id="fixture", specimen=self.specimen,
            inventory_complete=True, scope_description="100 byte synthetic scope",
            spaces=[dict(id="code", size=100, artifact=self.source, description="source code")],
            regions=[self.region("code", 0, 60, "code"), self.region("unknown", 60, 80, "unknown"),
                     self.region("excluded", 80, 90, "excluded")],
            units=[self.unit("reconstructed", "function", [(0, 10), (20, 30)], "reconstructed", True),
                   self.unit("partial", "function", [(10, 20)], "partial"),
                   self.unit("stub", "range", [(30, 40)], "stub", True),
                   self.unit("fallback", "function", [(40, 50)], "original-fallback"),
                   self.unit("mapped", "function", [], "unrecovered")],
            verification=[self.check("natural", "natural"), self.check("controlled", "controlled"),
                          self.check("component", "component"), self.check("failed", "natural", "fail")],
            milestones=[self.milestone("natural", ["natural"]), self.milestone("controlled", ["controlled"]),
                        self.milestone("component", ["component"]), self.milestone("mixed", ["natural", "controlled"]),
                        self.milestone("failed", ["failed"]), self.milestone("empty", [])],
            notes="Synthetic arithmetic, no original execution.")

    def binding(self, name, contents):
        (self.directory / name).write_bytes(contents)
        return dict(path=name, sha256=hashlib.sha256(contents).hexdigest(), bytes=len(contents))

    @staticmethod
    def region(name, start, end, kind):
        return dict(id=name, space="code", start=start, end=end, kind=kind, reason="synthetic region")

    def unit(self, name, kind, ranges, recovery, integrated=False):
        return dict(id=name, kind=kind, space="code", ranges=[dict(start=a, end=b) for a, b in ranges],
                    extent_complete=bool(ranges), recovery=recovery, integrated=integrated,
                    implementation=[copy.deepcopy(self.implementation)], evidence=[copy.deepcopy(self.evidence)], notes="fixture")

    def check(self, name, execution, result="pass"):
        return dict(id=name, scenario="fixture scenario", observable="state", execution=execution,
                    reference="original", result=result, evidence=[copy.deepcopy(self.evidence)],
                    inputs=[copy.deepcopy(self.input)], notes="fixture")

    @staticmethod
    def milestone(name, checks, status="implemented"):
        return dict(id=name, description="natural playability requirement", status=status, checks=checks)

    def report(self, inventory=None):
        self.path.write_text(json.dumps(self.inventory if inventory is None else inventory), encoding="utf-8")
        return progress.build_report(self.path)

    def invalid(self, inventory):
        with self.assertRaises(ValueError):
            self.report(inventory)

    def test_independent_denominators_and_no_stub_or_fallback_credit(self):
        report = self.report()
        recovery = report["recovery"]
        expected = dict(scope_bytes=100, excluded_bytes=10, included_bytes=90, known_code_bytes=60,
                        unknown_bytes=30, unassigned_code_bytes=10, reconstructed_bytes=20,
                        range_units=1, integrated_units=2)
        for key, value in expected.items():
            self.assertEqual(recovery[key], value, key)
        self.assertAlmostEqual(recovery["reconstructed_percent_of_included"], 100 * 20 / 90, places=4)
        self.assertFalse(recovery["inventory_complete"])
        self.assertTrue(recovery["declared_complete"])
        self.assertEqual(recovery["functions"], dict(identified=4, known_extent=3, reconstructed=1))
        units = {unit["id"]: unit for unit in recovery["units"]}
        self.assertEqual(units["reconstructed"]["credited_reconstructed_bytes"], 20)
        for name in ("partial", "stub", "fallback", "mapped"):
            self.assertEqual(units[name]["credited_reconstructed_bytes"], 0)
        regions = recovery["regions"]
        self.assertTrue(any(r["start"] == 90 and r["end"] == 100 and r["kind"] == "unknown" for r in regions))

    def test_complete_declaration_requires_no_unknown_or_unassigned_bytes(self):
        fixture = copy.deepcopy(self.inventory)
        fixture["regions"] = [self.region("all-code", 0, 100, "code")]
        fixture["units"] = [self.unit("whole", "function", [(0, 100)], "reconstructed")]
        report = self.report(fixture)["recovery"]
        self.assertTrue(report["inventory_complete"])
        self.assertEqual(report["reconstructed_percent_of_included"], 100)
        fixture["inventory_complete"] = False
        self.assertFalse(self.report(fixture)["recovery"]["inventory_complete"])
        fixture["inventory_complete"] = True
        fixture["units"].append(self.unit("mapped", "function", [], "unrecovered"))
        self.assertFalse(self.report(fixture)["recovery"]["inventory_complete"])
        fixture["units"].pop()
        fixture["units"][0]["ranges"][0]["end"] = 99
        self.assertFalse(self.report(fixture)["recovery"]["inventory_complete"])

    def test_empty_included_denominator_is_null(self):
        fixture = copy.deepcopy(self.inventory)
        fixture["regions"] = [self.region("excluded", 0, 100, "excluded")]
        fixture["units"] = []
        recovery = self.report(fixture)["recovery"]
        self.assertEqual(recovery["included_bytes"], 0)
        self.assertIsNone(recovery["reconstructed_percent_of_included"])

    def test_overlap_and_noncode_extent_rejections(self):
        for ranges in ([(0, 12), (10, 20)], [(0, 10), (9, 11)], [(55, 65)], [(80, 90)], [(99, 101)], [(3, 3)]):
            fixture = copy.deepcopy(self.inventory)
            fixture["units"][0]["ranges"] = [dict(start=a, end=b) for a, b in ranges]
            with self.subTest(ranges=ranges):
                self.invalid(fixture)
        fixture = copy.deepcopy(self.inventory)
        fixture["units"][1]["ranges"] = [dict(start=9, end=20)]
        self.invalid(fixture)
        fixture = copy.deepcopy(self.inventory)
        fixture["regions"].append(self.region("conflict", 59, 61, "excluded"))
        self.invalid(fixture)

    def test_reconstructed_requires_complete_extent_and_bindings(self):
        for field, value in (("extent_complete", False), ("ranges", []), ("implementation", []), ("evidence", [])):
            fixture = copy.deepcopy(self.inventory)
            fixture["units"][0][field] = value
            with self.subTest(field=field):
                self.invalid(fixture)

    def test_stale_and_missing_reconstruction_dependencies_remove_credit(self):
        for target in ("specimen.bin", "code.bin", "implementation.cpp", "evidence.json"):
            with self.subTest(target=target):
                path = self.directory / target
                original = path.read_bytes()
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                self.assertEqual(self.report()["recovery"]["reconstructed_bytes"], 0)
                path.write_bytes(original)
                path.unlink()
                self.assertEqual(self.report()["recovery"]["reconstructed_bytes"], 0)
                path.write_bytes(original)

    def test_verification_freshness_and_recorded_results(self):
        fixture = copy.deepcopy(self.inventory)
        fixture["verification"] += [self.check("not-run", "natural", "not_run"), self.check("unsupported", "component", "unsupported")]
        report = self.report(fixture)
        checks = {check["id"]: check for check in report["verification"]}
        self.assertEqual(checks["natural"]["status"], "passing")
        self.assertEqual(checks["failed"]["status"], "failing")
        self.assertEqual(checks["not-run"]["status"], "not_run")
        self.assertEqual(checks["unsupported"]["status"], "unsupported")
        fixture["verification"][0]["evidence"][0]["sha256"] = "0" * 64
        checks = {check["id"]: check for check in self.report(fixture)["verification"]}
        self.assertEqual(checks["natural"]["status"], "stale")
        self.assertEqual(checks["natural"]["recorded_result"], "pass")
        fixture["verification"][0]["inputs"][0]["path"] = "missing.json"
        checks = {check["id"]: check for check in self.report(fixture)["verification"]}
        self.assertEqual(checks["natural"]["status"], "missing")
        fixture["verification"][0]["inputs"] = []
        self.assertEqual({check["id"]: check for check in self.report(fixture)["verification"]}["natural"]["status"], "missing")

    def test_space_size_uses_pinned_scope_when_artifact_is_stale(self):
        fixture = copy.deepcopy(self.inventory)
        fixture["spaces"][0]["size"] = 101
        self.invalid(fixture)
        (self.directory / "code.bin").write_bytes(b"changed length")
        recovery = self.report()["recovery"]
        self.assertEqual(recovery["scope_bytes"], 100)
        self.assertEqual(recovery["included_bytes"], 90)
        self.assertEqual(recovery["reconstructed_bytes"], 0)

    def test_natural_checks_only_satisfy_implemented_playability(self):
        report = self.report()
        milestones = {m["id"]: m for m in report["playability"]}
        self.assertTrue(milestones["natural"]["satisfied"])
        for name in ("controlled", "component", "mixed", "failed", "empty"):
            self.assertFalse(milestones[name]["satisfied"])
        for status in ("partial", "not_implemented"):
            fixture = copy.deepcopy(self.inventory)
            fixture["milestones"][0]["status"] = status
            self.assertFalse(self.report(fixture)["playability"][0]["satisfied"])
        (self.directory / "input.json").unlink()
        self.assertFalse({m["id"]: m for m in self.report()["playability"]}["natural"]["satisfied"])

    def test_address_spaces_cannot_alias_path_or_hash(self):
        fixture = copy.deepcopy(self.inventory)
        duplicate = copy.deepcopy(fixture["spaces"][0])
        duplicate["id"] = "alias"
        duplicate["artifact"]["path"] = "./code.bin"
        fixture["spaces"].append(duplicate)
        self.invalid(fixture)
        duplicate["artifact"] = self.binding("other-code.bin", bytes(range(100)))
        self.invalid(fixture)

    def test_deterministic_order_and_output(self):
        first = self.report()
        self.assertEqual(first, self.report())
        fixture = copy.deepcopy(self.inventory)
        for collection in ("units", "regions", "verification", "milestones"):
            fixture[collection].reverse()
        reordered = self.report(fixture)
        for collection in ("units", "regions"):
            self.assertEqual(first["recovery"][collection], reordered["recovery"][collection])
        self.assertEqual(first["verification"], reordered["verification"])
        self.assertEqual(first["playability"], reordered["playability"])
        self.assertNotIn("timestamp", first)

    def test_inventory_identity_binds_the_parsed_bytes(self):
        self.path.write_text(json.dumps(self.inventory), encoding="utf-8")
        expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        original_hash = progress.sha256_file

        def change_inventory_after_parse(path):
            if path.name == "specimen.bin":
                self.path.write_text("{}", encoding="utf-8")
            return original_hash(path)

        with patch.object(progress, "sha256_file", side_effect=change_inventory_after_parse):
            report = progress.build_report(self.path)
        self.assertEqual(report["id"], "fixture")
        self.assertEqual(report["inventory_sha256"], expected)

    def test_malformed_hashes_numbers_ids_references_and_unknown_keys(self):
        mutations = [
            ("bad hash", lambda f: f["specimen"].update(sha256="z" * 64)),
            ("short hash", lambda f: f["specimen"].update(sha256="a" * 63)),
            ("bool size", lambda f: f["spaces"][0].update(size=True)),
            ("bool offset", lambda f: f["regions"][0].update(start=False)),
            ("bool bytes", lambda f: f["specimen"].update(bytes=True)),
            ("bool version", lambda f: f.update(format_version=True)),
            ("duplicate unit", lambda f: f["units"][1].update(id="reconstructed")),
            ("duplicate space", lambda f: f["spaces"].append(copy.deepcopy(f["spaces"][0]))),
            ("duplicate region", lambda f: f["regions"][1].update(id="code")),
            ("duplicate verification", lambda f: f["verification"][1].update(id="natural")),
            ("duplicate milestone", lambda f: f["milestones"][1].update(id="natural")),
            ("unknown space", lambda f: f["units"][0].update(space="absent")),
            ("unknown check", lambda f: f["milestones"][0].update(checks=["absent"])),
            ("invalid reference", lambda f: f["verification"][0].update(reference="unknown")),
            ("empty id", lambda f: f.update(id="")),
            ("unknown key", lambda f: f.update(unexpected=0)),
            ("empty reason", lambda f: f["regions"][1].update(reason="")),
            ("reserved region id", lambda f: f["regions"][0].update(id="gap:code:0")),
            ("numeric region space", lambda f: f["regions"][0].update(space=0)),
            ("numeric notes", lambda f: f.update(notes=0)),
            ("numeric unit notes", lambda f: f["units"][0].update(notes=0)),
            ("numeric check notes", lambda f: f["verification"][0].update(notes=0)),
            ("numeric code reason", lambda f: f["regions"][0].update(reason=0)),
        ]
        for name, mutate in mutations:
            fixture = copy.deepcopy(self.inventory)
            mutate(fixture)
            with self.subTest(case=name):
                self.invalid(fixture)

    def test_cli_cannot_overwrite_any_bound_input(self):
        self.report()
        for name in ("inventory.json", "specimen.bin", "code.bin", "implementation.cpp", "evidence.json", "input.json"):
            target = self.directory / name
            before = target.read_bytes()
            with self.subTest(target=name), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(progress.main([str(self.path), "--out", str(target.parent / "." / target.name)]), 2)
                self.assertEqual(target.read_bytes(), before)
    def test_cli_cannot_overwrite_bound_input_hardlink(self):
        self.report()
        alias = self.directory / "hardlink.bin"
        try:
            os.link(self.directory / "code.bin", alias)
        except OSError as error:
            self.skipTest(f"Filesystem does not permit fixture hardlinks: {error}")
        before = alias.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(progress.main([str(self.path), "--out", str(alias)]), 2)
        self.assertEqual(alias.read_bytes(), before)

    def test_cli_valid_incomplete_report_and_invalid_inventory(self):
        self.report()
        output = self.directory / "report.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(progress.main([str(self.path), "--out", str(output)]), 0)
        report = json.loads(output.read_text())
        self.assertFalse(report["recovery"]["inventory_complete"])
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(progress.main([str(self.path), "--format", "markdown"]), 0)
        self.assertIn("fixture", stdout.getvalue())
        self.path.write_text("{}", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(progress.main([str(self.path)]), 2)
