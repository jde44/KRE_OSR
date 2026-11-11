# Reproducibility

## Environment

- Python: 3.10 or newer; tested on 3.10, 3.11 and 3.13.
- Runtime dependencies: Python standard library only.
- Build metadata: PEP 517 with `setuptools>=68,<76`; validation does not fetch or install it.
- Dependency lock: `release/dependency-lock.json`. Runtime and test dependency lists are empty; Playwright is listed only as an optional developer tool for the demo UI browser check. The release build backend is pinned to `setuptools==75.9.1`; its wheel size and SHA-256 were matched to official PyPI metadata and it was unpacked and import-tested offline.
- Network: not required for setup, tests, benchmark, manifest, SBOM or scans.
- Demo: requires permission to bind an ephemeral IPv4 loopback socket.

## Export

`python3 scripts/export_candidate.py <empty-dir>` copies exactly the files listed in the manifest, after verifying the source tree against it, and re-hashes every copy. Private paths can never reach an export. The exported tree passes its own `scripts/test.sh`.

## Commands

```bash
./scripts/setup.sh
./scripts/test.sh
./scripts/demo.sh
```

`scripts/test.sh` first verifies the **committed** benchmark result, SBOM and manifest against freshly computed values, **without rewriting them**, so any source or evidence drift fails the run. It then executes all tests, compiles source, tests and scripts with bytecode outside the project, and scans the public candidate. The final JSON line records the interpreter version and platform. An intentional evidence update uses `python3 scripts/validate_release.py --regenerate`, and the resulting diff must be reviewed. `scripts/demo.sh` is separate because some managed sandboxes forbid socket binding.

## Packaging

The project is `src/`-layout and declares deterministic version `0.1.0`. An offline PEP 517 build may be run with the pinned backend and build isolation disabled. Build artifacts (`build/`, `dist/`, `*.egg-info`) are excluded from the public tree.

Packaging evidence:

- The pinned `setuptools-75.9.1-py3-none-any.whl` is 1,231,632 bytes with SHA-256 `0a6f876d62f4d978ca1a11ab4daf728d1357731f978543ff18ecdbf9fd071f73`.
- The wheel was downloaded from the official PyPI file URL, matched to PyPI metadata, unpacked offline and imported as version 75.9.1.
- `LICENSE` and `NOTICE` are included as adopted licensing materials; tests, scripts, evaluation data and governance records are not runtime package modules.

## Evidence integrity

`release/public-candidate-manifest.json` lists every candidate file with its classification, size and SHA-256. The manifest lists its own hash as null because a file cannot contain a stable hash of itself. Every other listed file is hashed, and the equality test rejects additions, removals, reordering, classification changes or hash drift.

The verifier compares the whole manifest (metadata, every entry and every key) with the tree. The manifest's own hash and size are null. Symlinks are rejected. Build outputs are ignored only where build tools create them (root `build/`, `dist/`, `.venv/`, `venv/`, `*.egg-info` at the root or under `src/`, and `.pyc` files inside `__pycache__`), so files under those names anywhere else are listed and scanned. Private development records are named only in a local private-path list (`.private-paths`), which is itself private. They are excluded from the manifest, the scan and every export, so changes to them cannot stale the candidate evidence. If the list is removed, those files reappear as manifest drift and validation fails. The SPDX SBOM is generated deterministically by `scripts/release_evidence.py` and declares package-level metadata only (`filesAnalyzed` false); file-level integrity lives in the manifest.
