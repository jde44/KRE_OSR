#!/usr/bin/env python3
"""Export exactly the verified public candidate into an empty directory.

Only files listed in release/public-candidate-manifest.json are copied, so private paths can never reach an export. The source must verify against its manifest first, and every copied file is re-hashed.
This tool performs no Git, network or publication action.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")
sys.path.insert(0, str(ROOT / "scripts"))
import release_evidence


def preflight(source):
    """Refuses unless the private list is present and meaningful, the tree is clean, and all evidence is current.

    A manifest alone is not trusted: after a failed or tampered regeneration it can match a tree that now
    includes private records, so the private-term scan and the full evidence check run here as well.
    """
    source = Path(source)
    if not (source / release_evidence.PRIVATE_LIST).is_file():
        raise SystemExit("private-path list missing; refusing to export")
    if not release_evidence.private_patterns(source) or release_evidence.private_deny_terms(source) is None:
        raise SystemExit("private-path list must name at least one private path and one deny term; refusing to export")
    findings = release_evidence.scan_tree(source)
    if findings:
        raise SystemExit("scan findings in the candidate; refusing to export: " + json.dumps(findings[:5]))
    import validate_release
    errors = validate_release.check_evidence(source)
    if errors:
        raise SystemExit("evidence is stale or inconsistent; refusing to export: " + "; ".join(errors[:5]))


def export(source, destination):
    source, destination = Path(source), Path(destination)
    preflight(source)
    manifest = json.loads((source / release_evidence.MANIFEST_PATH).read_text())
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit("destination must be empty or absent: " + str(destination))
    written = []
    for item in manifest["files"]:
        relative = item["path"]
        if release_evidence.classify(relative, release_evidence.private_patterns(source)) == "internal_control":
            raise SystemExit("internal-control path listed in manifest: " + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Preserve executable bits for the documented shell entry points while retaining exact bytes.
        shutil.copy2(source / relative, target)
        if item["sha256"] is not None and hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise SystemExit("hash mismatch after copy: " + relative)
        written.append(relative)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    written = export(ROOT, args.destination)
    print(json.dumps({"status": "exported", "files": len(written), "destination": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
