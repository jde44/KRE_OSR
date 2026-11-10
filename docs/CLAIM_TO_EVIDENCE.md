# Claim-to-Evidence Matrix

| Candidate claim | Evidence | Boundary |
|---|---|---|
| Local-first deterministic selection | `src/open_sovereign_router/policy.py`; policy and benchmark tests | Selection logic only; no model-quality claim |
| Sensitive classifications cannot use cloud | policy tests, adversarial result, benchmark zero sensitive routes | Depends on authenticated server label; detector quality is not established |
| Cloud requires single-request approval | approvals/policy/transport tests and adversarial result | Single-process development state; not durable/distributed |
| Demo uses localhost and no external provider | `scripts/demo.py`; demo output identifies `FakeProvider` | Requires loopback bind permission; no real model |
| Standard-library runtime | `pyproject.toml`, imports, SPDX SBOM | Optional packaging build uses compatible preinstalled setuptools |
| Candidate tree is exactly classified and hashed; exports contain only it | `release/public-candidate-manifest.json`; equality, evidence-design and export tests | Manifest self-hash is null by disclosed recursion rule; internal-control records are excluded by a verified policy, not hashed |
| The wheel bundles the adopted license and notice | `pyproject.toml`; `LICENSE`; `NOTICE`; packaging verification | Build tooling is not a runtime dependency |
| Runtime is dependency-free and the build backend is pinned | `release/dependency-lock.json`; AST import test; verified wheel hash | setuptools is used only for packaging and is not bundled |
| Public candidate has no scan findings | `release_evidence.scan_tree`; positive-fixture scanner tests | Pattern scan is not proof of absence; manual pre-release review remains required |
| Synthetic routing thresholds pass | fixture, raw result and `tests/test_release_evidence.py` | Synthetic assumptions; economics are reported over completed non-sensitive tasks only and are not gated; no observed billing, inference or model latency |
| Adversarial evaluation passes on the current source | `evals/results/adversarial-full.json`; freshness check in `scripts/test.sh` | Development evaluation, not certification or production readiness |
| License is Apache-2.0 | `LICENSE`; `NOTICE`; SPDX `Apache-2.0` declaration | Copyright remains with KRE SOLUTION ENGINEERING LLC |

Claims not authorized: production-ready, secure/certified, compliance-guaranteeing, benchmark-superior, or approved for a funding award.
