from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def private_top_level():
    """Top-level names covered by the local private-path list (absent in an exported candidate)."""
    path = PROJECT_ROOT / ".private-paths"
    names = {".private-paths"} if path.exists() else set()
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            # Only entries that are themselves top-level (a file, or a single "name/" prefix) remove a top-level name.
            if line and not line.startswith("#") and "/" not in line.rstrip("/"):
                names.add(line.rstrip("/"))
    return names

ALLOWED_TOP_LEVEL = {
    ".gitignore",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "LICENSE",
    "NOTICE",
    "MAINTAINERS.md",
    "README.md",
    "SECURITY.md",
    "config",
    "docs",
    "evals",
    "pyproject.toml",
    "release",
    "scripts",
    "src",
    "tests",
}
PROHIBITED_SUFFIXES = {".env", ".gguf", ".safetensors", ".bin", ".slot", ".pem", ".key", ".p12", ".jsonl"}


class TopLevelBoundaryAndProhibitedArtifactTests(unittest.TestCase):
    def test_top_level_boundary_is_deliberately_classified(self):
        # A normal clone contains Git metadata; it is repository state, not a release file.
        build_outputs = {".git", "__pycache__", "build", "dist", ".venv", "venv"}
        names = {path.name for path in PROJECT_ROOT.iterdir() if path.name not in build_outputs and not path.name.endswith(".egg-info")}
        self.assertEqual(names - private_top_level(), ALLOWED_TOP_LEVEL)

    def test_no_prohibited_candidate_artifacts(self):
        violations = []
        for path in PROJECT_ROOT.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.name == ".env" or path.suffix.lower() in PROHIBITED_SUFFIXES:
                violations.append(str(path.relative_to(PROJECT_ROOT)))
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
