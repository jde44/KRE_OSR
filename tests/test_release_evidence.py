import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def ensure_private_list(tree):
    """Returns the tree's private patterns, creating a neutral list when none exists (as in an export)."""
    release = load_script("release_evidence.py")
    listing = Path(tree) / release.PRIVATE_LIST
    neutral_deny = "deny:zebra-pro" + "tocol"
    if not release.private_patterns(tree):
        listing.write_text("private-notes/\nPRIVATE_NOTE.md\n" + neutral_deny + "\n")
    elif neutral_deny not in listing.read_text():
        listing.write_text(listing.read_text().rstrip("\n") + "\nprivate-notes/\n" + neutral_deny + "\n")
    return release.private_patterns(tree)


def load_script(name):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseEvidenceTests(unittest.TestCase):
    def test_benchmark_is_deterministic_and_meets_strict_thresholds(self):
        runner = load_script("run_routing_benchmark.py")
        first = runner.evaluate(ROOT / "evals" / "benchmark_tasks.json")
        second = runner.evaluate(ROOT / "evals" / "benchmark_tasks.json")
        self.assertEqual(first, second)
        self.assertEqual(first["disposition"], "pass")
        self.assertEqual(first["metrics"]["selection_accuracy"], 1.0)
        self.assertEqual(first["metrics"]["unauthorized_cloud_rate"], 0.0)
        self.assertEqual(first["metrics"]["sensitive_leak_rate"], 0.0)
        self.assertGreaterEqual(first["metrics"]["local_completion_rate"], 0.6)
        # Savings are computed only over completed non-sensitive tasks and are reported, not gated.
        self.assertNotIn("estimated_cost_savings_usd", first["checks"])
        self.assertNotIn("estimated_token_savings", first["checks"])
        self.assertEqual(first["economics"]["comparison_set"], ["t01", "t02", "t05", "t06", "t11"])
        self.assertEqual(first["economics"]["excluded_blocked"], ["t09"])
        self.assertGreater(first["economics"]["routed_cost_usd"], 0)  # the approved cloud route is priced
        self.assertEqual(first["metrics"]["approved_cloud_routes"], 1)
        self.assertEqual(first["latency"]["kind"], "deterministic_operation_count_proxy")

    def test_manifest_is_exact_and_hashes_match(self):
        release = load_script("release_evidence.py")
        manifest = json.loads((ROOT / "release" / "public-candidate-manifest.json").read_text())
        errors = release.verify_manifest(ROOT, manifest)
        self.assertEqual(errors, [])
        # Private paths are excluded, and the public manifest never names them.
        self.assertFalse(any(item["classification"] == "internal_control" for item in manifest["files"]))
        self.assertTrue(any(item["classification"] == "public_candidate" for item in manifest["files"]))
        self.assertEqual(manifest["private_path_policy"], release.private_path_policy())
        text = json.dumps(manifest)
        for pattern in release.private_patterns(ROOT):
            self.assertNotIn(pattern.rstrip("/"), text)

    def test_sbom_is_spdx_and_license_is_apache_2(self):
        sbom = json.loads((ROOT / "release" / "sbom.spdx.json").read_text())
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        self.assertEqual(sbom["dataLicense"], "CC0-1.0")
        root_package = next(p for p in sbom["packages"] if p["name"] == "open-sovereign-router")
        self.assertEqual(root_package["licenseConcluded"], "Apache-2.0")
        self.assertEqual(root_package["licenseDeclared"], "Apache-2.0")
        self.assertEqual(root_package["externalRefs"], [])
        # No File elements are listed, so filesAnalyzed must be false and no verification code may be given.
        self.assertIs(root_package["filesAnalyzed"], False)
        self.assertNotIn("packageVerificationCode", root_package)
        self.assertNotIn("files", sbom)

    def test_release_scan_is_clean_and_uses_no_allowlisted_secret(self):
        release = load_script("release_evidence.py")
        findings = release.scan_tree(ROOT)
        self.assertEqual(findings, [])

    def test_required_release_docs_and_commands_exist(self):
        required = [
            "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
            "GOVERNANCE.md", "MAINTAINERS.md", "docs/PROVENANCE.md",
            "docs/CLAIM_TO_EVIDENCE.md", "docs/REPRODUCIBILITY.md",
            "scripts/setup.sh", "scripts/test.sh", "scripts/demo.sh", "scripts/validate_release.py", "scripts/export_candidate.py",
        ]
        for relative in required:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
        self.assertTrue((ROOT / "LICENSE").is_file())
        self.assertTrue((ROOT / "NOTICE").is_file())

    def test_benchmark_fixture_hash_is_embedded_in_raw_result(self):
        raw = (ROOT / "evals" / "benchmark_tasks.json").read_bytes()
        result = json.loads((ROOT / "evals" / "results" / "routing-benchmark.json").read_text())
        self.assertEqual(result["fixture_sha256"], hashlib.sha256(raw).hexdigest())



class EvidenceDesignTests(unittest.TestCase):
    """Evidence must survive governance-record appends and local builds, yet catch any public-candidate drift."""

    def setUp(self):
        self.release = load_script("release_evidence.py")
        self.tmp = Path(tempfile.mkdtemp(prefix="osr-evidence-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tree = self.tmp / "osr"
        shutil.copytree(ROOT, self.tree, ignore=shutil.ignore_patterns("__pycache__"))
        self.release.write_evidence(self.tree)

    def manifest(self):
        return json.loads((self.tree / self.release.MANIFEST_PATH).read_text())

    def test_private_record_changes_do_not_stale_the_manifest(self):
        patterns = ensure_private_list(self.tree)
        self.release.write_evidence(self.tree)
        for pattern in patterns:
            target = self.tree / pattern / "added-note.md" if pattern.endswith("/") else self.tree / pattern
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a") as handle:
                handle.write("\nprivate note\n")
        self.assertEqual(self.release.verify_manifest(self.tree, self.manifest()), [])

    def test_removing_the_private_list_exposes_private_files_as_drift(self):
        patterns = ensure_private_list(self.tree)
        self.release.write_evidence(self.tree)
        for pattern in patterns:
            target = self.tree / pattern / "added-note.md" if pattern.endswith("/") else self.tree / pattern
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("private\n")
        (self.tree / self.release.PRIVATE_LIST).unlink()
        self.assertTrue(self.release.verify_manifest(self.tree, self.manifest()))

    def test_private_matching_is_case_insensitive(self):
        patterns = ensure_private_list(self.tree)
        prefix = next(p for p in patterns if p.endswith("/"))
        odd = self.tree / prefix.upper() / "copy.md"
        odd.parent.mkdir(parents=True, exist_ok=True)
        odd.write_text("copy\n")
        listed = {p.relative_to(self.tree).as_posix() for p in self.release.candidate_files(self.tree)}
        self.assertNotIn(odd.relative_to(self.tree).as_posix(), listed)

    def test_public_candidate_drift_is_detected(self):
        manifest = self.manifest()
        with (self.tree / "README.md").open("a") as handle:
            handle.write("\nchanged\n")
        self.assertTrue(any("README.md" in e for e in self.release.verify_manifest(self.tree, manifest)))
        (self.tree / "docs" / "NEW_PUBLIC.md").write_text("new\n")
        self.assertIn("manifest path set/order differs from tree", self.release.verify_manifest(self.tree, manifest))

    def test_tampered_private_path_policy_is_detected(self):
        manifest = self.manifest()
        manifest["private_path_policy"]["policy"] = "nothing is private"
        self.assertTrue(self.release.verify_manifest(self.tree, manifest))

    def test_local_build_artifacts_do_not_stale_the_manifest(self):
        egg = self.tree / "src" / "open_sovereign_router.egg-info"
        egg.mkdir()
        (egg / "PKG-INFO").write_text("Name: x\n")
        (self.tree / "build").mkdir()
        (self.tree / "build" / "artifact.txt").write_text("x\n")
        self.assertEqual(self.release.verify_manifest(self.tree, self.manifest()), [])

    def test_wheel_bundles_adopted_license_and_notice(self):
        text = (ROOT / "pyproject.toml").read_text()
        section = text.split("[tool.setuptools]", 1)[1].split("\n[", 1)[0]
        self.assertIn('license-files = ["LICENSE", "NOTICE"]', section)



class EvidenceIntegrityTests(unittest.TestCase):
    """Evidence-integrity hardening: hidden paths, committed-evidence checks, dependency lock, scanner coverage, manifest metadata, symlinks."""

    def setUp(self):
        self.release = load_script("release_evidence.py")
        self.tmp = Path(tempfile.mkdtemp(prefix="osr-integrity-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tree = self.tmp / "osr"
        shutil.copytree(ROOT, self.tree, ignore=shutil.ignore_patterns("__pycache__"))
        self.release.write_evidence(self.tree)

    def manifest(self):
        return json.loads((self.tree / self.release.MANIFEST_PATH).read_text())

    def test_source_hidden_under_nested_ignored_names_is_detected(self):
        manifest = self.manifest()
        hidden = self.tree / "src" / "open_sovereign_router" / "build"
        hidden.mkdir()
        (hidden / "__init__.py").write_text("x = 1\n")
        self.assertIn("manifest path set/order differs from tree", self.release.verify_manifest(self.tree, manifest))
        for name in ("dist", ".venv", "venv", "x.egg-info"):
            other = self.tree / "docs" / name
            other.mkdir()
            (other / "note.md").write_text("n\n")
        listed = {p.relative_to(self.tree).as_posix() for p in self.release.iter_files(self.tree)}
        self.assertTrue({"docs/dist/note.md", "docs/.venv/note.md", "docs/venv/note.md", "docs/x.egg-info/note.md"} <= listed)

    def test_non_bytecode_inside_pycache_is_not_hidden(self):
        cache = self.tree / "src" / "open_sovereign_router" / "__pycache__"
        cache.mkdir()
        (cache / "x.cpython-313.pyc").write_bytes(b"\x00")
        (cache / "smuggled.py").write_text("x = 1\n")
        listed = {p.relative_to(self.tree).as_posix() for p in self.release.iter_files(self.tree)}
        self.assertIn("src/open_sovereign_router/__pycache__/smuggled.py", listed)
        self.assertNotIn("src/open_sovereign_router/__pycache__/x.cpython-313.pyc", listed)

    def test_root_build_outputs_remain_ignored(self):
        for name in ("build", "dist", ".venv", "venv"):
            (self.tree / name).mkdir()
            (self.tree / name / "a.txt").write_text("a\n")
        (self.tree / "src" / "open_sovereign_router.egg-info").mkdir()
        (self.tree / "src" / "open_sovereign_router.egg-info" / "PKG-INFO").write_text("x\n")
        self.assertEqual(self.release.verify_manifest(self.tree, self.manifest()), [])

    def test_committed_evidence_check_detects_source_drift_without_regenerating(self):
        validate = load_script("validate_release.py")
        self.assertEqual(validate.check_evidence(self.tree), [])
        with (self.tree / "src" / "open_sovereign_router" / "policy.py").open("a") as handle:
            handle.write("# tampered\n")
        before = (self.tree / self.release.MANIFEST_PATH).read_bytes()
        errors = validate.check_evidence(self.tree)
        self.assertTrue(errors)
        self.assertEqual((self.tree / self.release.MANIFEST_PATH).read_bytes(), before)
        self.assertFalse(validate.parse_args([]).regenerate)
        self.assertTrue(validate.parse_args(["--regenerate"]).regenerate)

    def test_hand_edited_adversarial_outcome_cannot_be_reblessed(self):
        validate = load_script("validate_release.py")
        result = self.tree / "evals" / "results" / "adversarial-full.json"
        data = json.loads(result.read_text())
        mapped = data["evaluations"][0]["raw_outcomes"][0]["test_id"]
        for item in data["raw_outcomes"]:
            if item["test_id"] == mapped:
                item["status"] = "fail"
        result.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        validate.regenerate(self.tree)
        self.assertTrue(any("inconsistent" in e for e in validate.check_evidence(self.tree)))

    def test_stale_benchmark_or_sbom_is_detected(self):
        validate = load_script("validate_release.py")
        result = self.tree / "evals" / "results" / "routing-benchmark.json"
        result.write_text(result.read_text().replace('"disposition": "pass"', '"disposition": "fail"'))
        self.assertTrue(any("benchmark" in e for e in validate.check_evidence(self.tree)))

    def test_dependency_lock_matches_pyproject_and_runtime_is_stdlib_only(self):
        import sys as _sys
        lock = json.loads((ROOT / "release" / "dependency-lock.json").read_text())
        self.assertEqual(lock["runtime"], [])
        self.assertEqual(lock["build_backend"]["specifier"], "setuptools>=68,<76")
        self.assertIn('requires = ["setuptools>=68,<76"]', (ROOT / "pyproject.toml").read_text())
        self.assertEqual(lock["build_backend"]["status"], "verified_offline")
        self.assertEqual(lock["build_backend"]["pinned_version"], "75.9.1")
        self.assertEqual(lock["build_backend"]["sha256"], "0a6f876d62f4d978ca1a11ab4daf728d1357731f978543ff18ecdbf9fd071f73")
        import ast
        stdlib = set(_sys.stdlib_module_names)
        for path in (ROOT / "src").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else [])
                for name in names:
                    self.assertIn(name.split(".")[0], stdlib, f"{path.name}: {name}")

    def test_scanner_finds_each_leak_class(self):
        """Positive fixtures, assembled so this file does not match itself."""
        samples = {
            "pem": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "ssh": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
            "anthropic": "sk-" + "ant-api03-abcdefghijklmnop",
            "openai": "sk-" + "proj-abcdefghijklmnopqrst",
            "github": "github" + "_pat_11ABCDEFG0123456789",
            "ghp": "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789",
            "slack": "xo" + "xb-1234-5678-abcdef",
            "google": "AI" + "za" + "SyA" + "x" * 32,
            "mail": "mail" + "to:" + "jane" + "@" + "example.org",
            "email": "jane.doe" + "@" + "example.org",
            "home": "/" + "home/alice/project",
            "users": "/" + "Users/alice/project",
            "root": "/" + "root/.ssh/config",
            "windows": "C:" + "\\Users\\alice\\x",
            "home_noslash": "/" + "home/jane",
            "legacy_sk": "sk-" + "a" * 48,
            "gitlab": "gl" + "pat-" + "a" * 20,
            "pgp": "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
            "jwt": "ey" + "J" + "a" * 10 + ".ey" + "J" + "b" * 10 + "." + "c" * 10,
            "mnt": "/" + "mnt/data/project",
            "var_folders": "/" + "var/folders/ab/T/x",
            "private_tmp": "/" + "private/tmp/x",
            "unc": "\\\\" + "server\\share",
        }
        for kind, sample in samples.items():
            (self.tree / "docs" / f"leak_{kind}.md").write_text(sample + "\n")
        flagged = {f["path"] for f in self.release.scan_tree(self.tree)}
        for kind in samples:
            self.assertIn(f"docs/leak_{kind}.md", flagged, kind)

    def test_private_deny_terms_are_enforced_without_naming_them_publicly(self):
        (self.tree / self.release.PRIVATE_LIST).write_text("private-notes/\ndeny:zebra-pro" + "tocol\n")
        (self.tree / "docs" / "leak_term.md").write_text("uses the zebra-pro" + "tocol\n")
        (self.tree / "private-notes").mkdir(exist_ok=True)
        (self.tree / "private-notes" / "ok.md").write_text("zebra-pro" + "tocol is fine here\n")
        (self.tree / "docs" / "leak_upper.md").write_text("USES THE ZEBRA-PRO" + "TOCOL\n")
        flagged = {(f["path"], f["kind"]) for f in self.release.scan_tree(self.tree)}
        self.assertIn(("docs/leak_term.md", "private_term"), flagged)
        self.assertIn(("docs/leak_upper.md", "private_term"), flagged)
        self.assertFalse(any(path.startswith("private-notes/") for path, _ in flagged))

    def test_scanner_is_clean_on_uri_userinfo_fixture(self):
        self.assertEqual(self.release.scan_tree(self.tree), [])

    def test_manifest_metadata_and_extra_keys_are_verified(self):
        for mutate in (
            lambda m: m.__setitem__("status", "approved_for_public_release"),
            lambda m: m.__setitem__("schema_version", 99),
            lambda m: m["files"][0].__setitem__("license", "MIT"),
        ):
            manifest = self.manifest()
            mutate(manifest)
            self.assertTrue(self.release.verify_manifest(self.tree, manifest))

    def test_manifest_self_entry_has_null_size_and_hash(self):
        entry = next(f for f in self.manifest()["files"] if f["path"] == self.release.MANIFEST_PATH)
        self.assertIsNone(entry["sha256"])
        self.assertIsNone(entry["bytes"])

    def test_symlinks_are_rejected(self):
        import os
        target = self.tmp / "outside.txt"
        target.write_text("outside\n")
        try:
            os.symlink(target, self.tree / "docs" / "link.md")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertTrue(any("symlink" in e for e in self.release.verify_manifest(self.tree, self.manifest())))
        self.assertTrue(any(f["kind"] == "symlink" for f in self.release.scan_tree(self.tree)))



class ReleaseCandidateTests(unittest.TestCase):
    """Release-candidate controls: adversarial-evidence freshness and an allowlisted export."""

    def setUp(self):
        self.release = load_script("release_evidence.py")
        self.validate = load_script("validate_release.py")
        self.tmp = Path(tempfile.mkdtemp(prefix="osr-rc-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tree = self.tmp / "osr"
        shutil.copytree(ROOT, self.tree, ignore=shutil.ignore_patterns("__pycache__"))
        self.release.write_evidence(self.tree)

    def test_committed_adversarial_results_match_current_source_and_catalog(self):
        errors = self.validate.adversarial_freshness(ROOT)
        self.assertEqual(errors, [])

    def test_stale_adversarial_results_are_detected(self):
        with (self.tree / "tests" / "test_scaffold.py").open("a") as handle:
            handle.write("\n# changed\n")
        errors = self.validate.adversarial_freshness(self.tree)
        self.assertTrue(errors and all("source" in e for e in errors), errors)
        catalog = self.tree / "evals" / "adversarial_catalog.json"
        catalog.write_text(catalog.read_text().replace("Prohibit silent provider fallback", "Prohibit fallback"))
        self.assertTrue(any("catalog" in e for e in self.validate.adversarial_freshness(self.tree)))

    def test_full_adversarial_result_has_no_gaps(self):
        full = json.loads((ROOT / "evals" / "results" / "adversarial-full.json").read_text())
        self.assertEqual(full["summary"]["disposition"], "pass")
        self.assertEqual(full["summary"]["fail"] + full["summary"]["error"], 0)
        self.assertEqual(full["mapping"]["unallowed_skips"], [])
        self.assertTrue(all(e["disposition"] == "pass" for e in full["evaluations"]))

    def test_export_contains_exactly_the_public_candidate(self):
        export = load_script("export_candidate.py")
        if not self.release.private_patterns(self.tree):
            ensure_private_list(self.tree)
            self.release.write_evidence(self.tree)
        destination = self.tmp / "export"
        written = export.export(self.tree, destination)
        manifest = json.loads((self.tree / self.release.MANIFEST_PATH).read_text())
        listed = [item["path"] for item in manifest["files"]]
        on_disk = sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file())
        self.assertEqual(sorted(written), sorted(listed))
        self.assertEqual(on_disk, sorted(listed))
        for pattern in self.release.private_patterns(self.tree):
            self.assertFalse(any(path.lower().startswith(pattern.lower()) for path in on_disk), pattern)
        self.assertEqual(self.release.verify_manifest(destination, manifest), [])
        self.assertEqual(self.release.scan_tree(destination), [])
        for script in ("setup.sh", "test.sh", "demo.sh"):
            self.assertTrue(os.access(destination / "scripts" / script, os.X_OK), script)

    def _regenerate_ignoring_failures(self):
        self.release.write_evidence(self.tree)

    def test_export_refuses_missing_empty_or_denyless_private_list(self):
        export = load_script("export_candidate.py")
        ensure_private_list(self.tree)
        listing = self.tree / self.release.PRIVATE_LIST
        original = listing.read_text()
        for content in (None, "", "private-notes/\n"):
            if content is None:
                listing.unlink()
            else:
                listing.write_text(content)
            self._regenerate_ignoring_failures()
            with self.assertRaises(SystemExit):
                export.export(self.tree, self.tmp / ("out-" + str(len(content or "x"))))
            listing.write_text(original)

    def test_export_refuses_private_terms_even_when_manifest_matches(self):
        export = load_script("export_candidate.py")
        ensure_private_list(self.tree)
        (self.tree / "docs" / "NOTES.md").write_text("copied note about the zebra-pro" + "tocol\n")
        self._regenerate_ignoring_failures()  # the manifest now matches, as after a failed --regenerate
        with self.assertRaises(SystemExit):
            export.export(self.tree, self.tmp / "out-terms")
        self.assertFalse((self.tmp / "out-terms").exists())

    def test_export_refuses_when_a_private_entry_is_dropped_from_the_list(self):
        export = load_script("export_candidate.py")
        ensure_private_list(self.tree)
        listing = self.tree / self.release.PRIVATE_LIST
        (self.tree / "private-notes").mkdir(exist_ok=True)
        (self.tree / "private-notes" / "plan.md").write_text("zebra-pro" + "tocol rollout\n")
        prefixes = [p for p in self.release.private_patterns(self.tree) if p.endswith("/")]
        kept = [line for line in listing.read_text().splitlines() if line.strip() != prefixes[0]]
        listing.write_text("\n".join(kept) + "\n")
        (self.tree / prefixes[0]).mkdir(parents=True, exist_ok=True)
        (self.tree / prefixes[0] / "zz-private.md").write_text("zebra-pro" + "tocol note\n")
        self._regenerate_ignoring_failures()
        with self.assertRaises(SystemExit):
            export.export(self.tree, self.tmp / "out-dropped")

    def test_export_refuses_drifted_source_and_non_empty_destination(self):
        export = load_script("export_candidate.py")
        ensure_private_list(self.tree)
        self.release.write_evidence(self.tree)
        busy = self.tmp / "busy"
        busy.mkdir()
        (busy / "x").write_text("x")
        with self.assertRaises(SystemExit):
            export.export(self.tree, busy)
        with (self.tree / "README.md").open("a") as handle:
            handle.write("drift\n")
        with self.assertRaises(SystemExit):
            export.export(self.tree, self.tmp / "fresh")
        self.assertFalse((self.tmp / "fresh").exists())


if __name__ == "__main__":
    unittest.main()
