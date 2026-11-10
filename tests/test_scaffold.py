import sys
from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


class ScaffoldTests(unittest.TestCase):
    def test_package_identity(self):
        import open_sovereign_router

        self.assertEqual(open_sovereign_router.__version__, "0.1.0")

    def test_apache_license_is_adopted(self):
        text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", text)
        self.assertIn("Version 2.0", text)


if __name__ == "__main__":
    unittest.main()
