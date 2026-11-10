# Candidate Manifest Policy

`release/public-candidate-manifest.json` is the exact machine-readable public tree inventory. The project is licensed under Apache License 2.0.

Each entry is classified as `public_candidate` or `release_metadata`. Private development records are excluded: they are named only in a local private-path list, and the manifest carries a generic, verified `private_path_policy`. `scripts/export_candidate.py` refuses to run if that list is missing or empty, if any scan finding exists, or if any evidence is stale. Every entry other than the manifest itself includes SHA-256 and byte size. The manifest's own hash is null because self-hashing is recursive; exact set/order, classification, all other hashes and all other sizes are tested. Models, binaries, logs, environment files, secrets, raw JSONL, private keys, runtime/data directories, and unreviewed external artifacts are prohibited.

Use `scripts/export_candidate.py` to produce a verified external copy.
