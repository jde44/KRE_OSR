#!/usr/bin/env python3
"""Deterministic exact-manifest, SPDX SBOM and public-candidate scan helpers."""

import hashlib
import json
from pathlib import Path
import re

MANIFEST_PATH = "release/public-candidate-manifest.json"
# Build outputs are ignored only where build tools create them, never at arbitrary depth (a nested
# `build/` or `.venv/` inside a package would otherwise hide shippable source from manifest and scan).
ROOT_IGNORED_DIRS = {".git", "build", "dist", ".venv", "venv"}
# A local, never-published file listing private path prefixes (ending in "/") and files, one per line,
# plus optional "deny:<regex>" lines naming terms that must never appear in public files.
# Public tooling names only this list file, never the private paths themselves.
PRIVATE_LIST = ".private-paths"
DENY_PREFIX = "deny:"
BINARY_SUFFIXES = {".bin", ".gguf", ".safetensors", ".slot", ".pem", ".key", ".p12", ".pyc"}


def _ignored(parts):
    if parts[0] in ROOT_IGNORED_DIRS:
        return True
    if parts[0].endswith(".egg-info") or (len(parts) > 1 and parts[0] == "src" and parts[1].endswith(".egg-info")):
        return True
    # Only compiled bytecode inside __pycache__ is ignored; any other file there is listed and scanned.
    return "__pycache__" in parts[:-1] and parts[-1].endswith(".pyc")


def iter_files(root):
    """Every non-ignored file or symlink, sorted. Symlinks are yielded so that callers can reject them."""
    root = Path(root)
    for path in sorted(root.rglob("*")):
        parts = path.relative_to(root).parts
        if _ignored(parts):
            continue
        if path.is_symlink() or path.is_file():
            yield path


def symlinks(root):
    root = Path(root)
    return [p.relative_to(root).as_posix() for p in iter_files(root) if p.is_symlink()]


def private_patterns(root):
    path = Path(root) / PRIVATE_LIST
    if not path.is_file():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith(DENY_PREFIX):
            patterns.append(line)
    return patterns


def private_deny_terms(root):
    """Regular expressions (lines starting with "deny:") that must never appear in public files.

    Keeping them in the private list means public code never reveals the vocabulary it guards against.
    """
    path = Path(root) / PRIVATE_LIST
    if not path.is_file():
        return None
    terms = [line.strip()[len(DENY_PREFIX):].strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip().startswith(DENY_PREFIX)]
    terms = [term for term in terms if term]
    return re.compile("|".join(terms), re.IGNORECASE) if terms else None


def candidate_files(root):
    """Files covered by the manifest: everything except private paths."""
    root = Path(root)
    patterns = private_patterns(root)
    for path in iter_files(root):
        if classify(path.relative_to(root).as_posix(), patterns) != "internal_control":
            yield path


def private_path_policy():
    return {
        "list_file": PRIVATE_LIST,
        "policy": "Paths named in a local private-path list are excluded from this manifest and from every export; the list itself is private.",
    }


def classify(relative, patterns=()):
    if relative == MANIFEST_PATH:
        return "release_metadata"
    lowered = relative.lower()
    if lowered == PRIVATE_LIST:
        return "internal_control"
    for pattern in patterns:
        candidate = pattern.lower()
        if (candidate.endswith("/") and lowered.startswith(candidate)) or lowered == candidate:
            return "internal_control"
    return "public_candidate"


def manifest_for(root):
    root = Path(root)
    links = symlinks(root)
    if links:
        raise ValueError("symlinks are not permitted in the candidate: " + ", ".join(links))
    files = []
    patterns = private_patterns(root)
    for path in candidate_files(root):
        relative = path.relative_to(root).as_posix()
        own = relative == MANIFEST_PATH
        files.append({
            "path": relative,
            "sha256": None if own else hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": None if own else path.stat().st_size,
            "classification": classify(relative, patterns),
        })
    return {
        "schema_version": 1,
        "status": "approved_public_alpha",
        "self_hash_policy": "manifest lists itself with null SHA-256 and null size because both are recursive; every other listed file is hashed and sized",
        "private_path_policy": private_path_policy(),
        "files": files,
    }


def verify_manifest(root, manifest):
    """Compares the whole manifest (metadata, entries and every key) with the tree; returns readable errors."""
    root = Path(root)
    links = symlinks(root)
    if links:
        return ["symlink not permitted: " + link for link in links]
    errors = []
    expected = manifest_for(root)
    if manifest.get("private_path_policy") != expected["private_path_policy"]:
        errors.append("private-path policy differs from tooling")
    for key in sorted(set(expected) | set(manifest)):
        if key not in ("files", "private_path_policy") and manifest.get(key) != expected.get(key):
            errors.append("manifest metadata differs: " + key)
    listed = manifest.get("files", [])
    if [item.get("path") for item in listed] != [item["path"] for item in expected["files"]]:
        errors.append("manifest path set/order differs from tree")
    by_path = {item["path"]: item for item in expected["files"]}
    for item in listed:
        want = by_path.get(item.get("path"))
        if want is None:
            errors.append("missing: " + str(item.get("path")))
        elif item != want:
            fields = sorted(k for k in set(item) | set(want) if item.get(k) != want.get(k))
            errors.append("entry differs: " + want["path"] + " (" + ", ".join(fields) + ")")
    return errors


# Patterns are assembled from fragments so this scanner source does not match itself.
_SECRET_PATTERNS = [re.compile(x) for x in (
    "-----BEGIN [A-Z ]*" + "PRIVATE KEY(?: BLOCK)?-----",
    r"\bsk-" + "[A-Za-z0-9]{48}\\b",
    "gl" + r"pat-[A-Za-z0-9_-]{20}",
    "ey" + r"J[A-Za-z0-9_-]{8,}\.ey" + r"J[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    "AK" + "IA[0-9A-Z]{16}",
    r"\bsk-(?:" + "ant-|proj-|live-)[A-Za-z0-9_-]{8,}",
    "gh" + r"[pousr]_[A-Za-z0-9]{20,}",
    "github" + r"_pat_[A-Za-z0-9_]{10,}",
    "xo" + r"x[abprs]-[A-Za-z0-9-]{6,}",
    "AI" + r"za[0-9A-Za-z_-]{35}",
)]
_PRIVATE_PATH = re.compile(
    r"(?:/(?:Users|home)/[A-Za-z0-9._-]+|/" + r"root/|\b[A-Za-z]:\\{1,2}Users\\{1,2}"
    r"|/" + r"mnt/[A-Za-z0-9._-]+|/" + r"var/folders/|/" + r"private/(?:tmp|var)/|\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9.$_-]+)"
)
# `user:pass@host` URI userinfo (a rejection fixture) is not an email; `mailto:` addresses are.
_EMAIL = re.compile(r"(?:mailto:|(?<![A-Za-z0-9._%+:-]))[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def scan_tree(root):
    root = Path(root)
    findings = []
    patterns = private_patterns(root)
    deny = private_deny_terms(root)
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append({"path": relative, "kind": "symlink"})
            continue
        if classify(relative, patterns) != "public_candidate":
            continue
        if path.suffix.lower() in BINARY_SUFFIXES or path.stat().st_size > 1_000_000:
            findings.append({"path": relative, "kind": "binary_or_large"})
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append({"path": relative, "kind": "non_utf8"})
            continue
        if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
            findings.append({"path": relative, "kind": "secret_marker"})
        if _PRIVATE_PATH.search(text):
            findings.append({"path": relative, "kind": "private_absolute_path"})
        if _EMAIL.search(text):
            findings.append({"path": relative, "kind": "email_or_pii"})
        if deny is not None and deny.search(text):
            findings.append({"path": relative, "kind": "private_term"})
    return findings


def sbom_for(root):
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "open-sovereign-router-candidate-sbom",
        "documentNamespace": "https://github.com/kre-solution-engineering/open-sovereign-router/spdx/0.1.0",
        "creationInfo": {"created": "2026-11-07T00:00:00Z", "creators": ["Organization: KRE SOLUTION ENGINEERING LLC", "Tool: scripts/release_evidence.py"]},
        "packages": [{
            "name": "open-sovereign-router", "SPDXID": "SPDXRef-Package-OSR", "versionInfo": "0.1.0",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0",
            "copyrightText": "Copyright 2026 KRE SOLUTION ENGINEERING LLC", "externalRefs": [],
            "comment": "Public alpha. Runtime dependencies: Python standard library only. Build backend pinned for release verification to setuptools 75.9.1; the wheel is not bundled and validation never fetches it."
        }],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-OSR"}],
        "annotations": [{"annotationDate": "2026-11-07T00:00:00Z", "annotationType": "OTHER", "annotator": "Tool: scripts/release_evidence.py", "comment": "No third-party runtime packages. Python interpreter and optional setuptools build tooling are environment prerequisites, not bundled components. File-level integrity is recorded in release/public-candidate-manifest.json, not in this SBOM (filesAnalyzed false)."}]
    }


def write_evidence(root):
    root = Path(root)
    release = root / "release"
    release.mkdir(exist_ok=True)
    (release / "sbom.spdx.json").write_text(json.dumps(sbom_for(root), indent=2, sort_keys=True) + "\n")
    manifest_path = root / MANIFEST_PATH
    if not manifest_path.exists():
        manifest_path.write_text("{}\n")  # the manifest lists itself, so it must exist before it is rendered
    manifest_path.write_text(json.dumps(manifest_for(root), indent=2, sort_keys=True) + "\n")
