# Open Sovereign Router

Status: public alpha; licensed under Apache License 2.0; not production-ready.

Open Sovereign Router is an open-source project from KRE Solution Engineering for privacy-, capability-, and cost-aware AI model routing. It prefers the smallest capable local model, keeps sensitive work local, and requires explicit human approval before a request can use an enabled cloud provider.

## Intended value

- OpenAI-compatible integration surface for applications and agents.
- Local-first routing constrained by privacy and operator policy.
- Explicit, single-request cloud escalation rather than silent fallback.
- Provider-neutral adapters and explainable routing decisions.
- Prompt-free audit metadata and synthetic, reproducible evaluation.
- Usable on ordinary hardware, beginning with llama.cpp-compatible local runtimes.

## Current state

Implemented and tested:

- A deterministic local-first policy core: smallest capable model, local preference, hard local-only handling for confidential and restricted data, no silent fallback.
- An authenticated, localhost-only, OpenAI-compatible development transport with two-phase, single-request cloud approval; connection, timeout and read-deadline limits; strict request parsing; and fail-closed, prompt-free audit of every decision and outcome.
- A deterministic adversarial evaluation catalog and runner (`docs/SECURITY_EVALUATION.md`).
- Offline reproducibility tooling: a localhost fake-provider demo, an exact hashed candidate manifest, an SPDX 2.3 SBOM, public-candidate scans, a synthetic routing benchmark and an allowlisted export (`scripts/export_candidate.py`).

`scripts/test.sh` verifies the committed evidence without rewriting it, then runs the full suite. The suite passes on Python 3.10, 3.11 and 3.13; the IPv6-loopback test is skipped on hosts without IPv6. This is an alpha release and is not production-ready.

## Quickstart (offline)

Python 3.10+ is required. Runtime code and validation use only the Python standard library; no package download is required.

```bash
./scripts/setup.sh
./scripts/test.sh
./scripts/demo.sh
```

The demo binds an ephemeral `127.0.0.1` port, calls the real development HTTP transport, and uses `FakeProvider`; it does not contact a model or external service. Some managed sandboxes prohibit loopback binding, so run it in a normal local shell when that occurs.

## Architecture

```text
authenticated local caller -> localhost transport -> deterministic policy
                                            |-> local FakeProvider (demo)
                                            |-> cloud route blocked unless enabled + one-request approval
                                            `-> prompt-free audit events
```

The policy selects the smallest capable enabled model, prefers local execution, blocks cloud for confidential/restricted classifications, and never silently falls back across a provider boundary.

## Evidence and limitations

- [Reproducibility](docs/REPRODUCIBILITY.md)
- [Synthetic benchmark](docs/BENCHMARK.md)
- [Claim-to-evidence matrix](docs/CLAIM_TO_EVIDENCE.md)
- [Exact candidate manifest](release/public-candidate-manifest.json)
- [SPDX SBOM](release/sbom.spdx.json)
- [Security policy](SECURITY.md)

The benchmark tests routing logic only. It does not run a model or establish response quality, production cost, wall-clock model latency, energy use, security certification, or superiority over another router. Outbound cloud transport, durable approvals/audit integrity, secret lifecycle, multi-tenancy, production availability, and robust sensitive-content detection remain out of scope.

## Roadmap

1. Harden provider networking, durable approval state and audit integrity.
2. Add measured model and hardware benchmarks.
3. Add supported integrations while preserving provider neutrality.

## Local validation

Requires Python 3.10 or newer and no network access:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

`./scripts/test.sh` is the authoritative one-command validation. It fails if the committed evidence is stale; `python3 scripts/validate_release.py --regenerate` is for reviewed evidence updates only.

## License

Copyright 2026 KRE SOLUTION ENGINEERING LLC. Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.
