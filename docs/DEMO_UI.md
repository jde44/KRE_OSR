# Local demo UI

A browser view of the existing router for reviewers. It shows, for one synthetic request at a time, which model the
policy selects and why, when a cloud route needs explicit single-request approval, when sensitive data is forced
local or blocked, and the prompt-free audit events the router records.

It is a demonstration, not a product surface. It runs only on this machine, uses `FakeProvider` for every model, and
is not production-ready. Estimates on the page use synthetic assumptions and are not measurements.

## Run it

Prerequisites: Python 3.10 or newer and a modern browser. No package download, API key or network is needed, so the
demo works offline once the repository is on disk.

```bash
./scripts/demo_ui.sh            # serves http://127.0.0.1:8765/
./scripts/demo_ui.sh --port 0   # any free loopback port
```

Open the exact URL the launcher prints. It carries a per-launch token in the URL fragment (`#t=…`); the page reads
it, removes it from the address bar and sends it as a header on each API call. Press Ctrl+C to stop. Every launch
starts a fresh router with new keys, a new approval secret and an empty audit log.

## Three-minute walkthrough

1. **Public, simple request.** Routed to `local-small`, the smallest enabled model with the basic capability. The
   flow, decision card and audit table show the selection; nothing leaves the machine.
2. **Public, needs the cloud model.** No local model has the advanced capability, so the router returns HTTP 409
   `approval_required` and executes nothing. The approval card lists the exact bindings (provider, model,
   sensitivity, capability, output budget, payload digest, request ID). Choose **Approve this single request** to
   run it once through the simulated cloud provider, then **Try to reuse this approval** to see the router refuse a
   replay.
3. **Restricted, cloud prohibited.** Restricted data can never use cloud and no local model is capable, so the
   request is blocked (`sensitive_local_unavailable`). No approval is offered: there is nothing a human can approve.
4. Optional: **Confidential, kept local** shows confidential data forced onto `local-standard`. You can also edit
   the text, sensitivity, capability and output-token budget and run the policy yourself.
5. **Reset demo** discards the router instance, its pending approvals and its audit log.

## How it works

```text
browser (static page, no routing logic)
   |  same-origin fetch + X-OSR-Demo-Token
   v
scripts/demo_ui/server.py  (127.0.0.1 only)
   |  maps the chosen sensitivity to a per-launch caller key held server-side
   |  POST /v1/chat/completions over loopback HTTP
   v
existing transport: open_sovereign_router.transport.build_server  (127.0.0.1, ephemeral port)
   -> RouterService -> PolicyEngine -> FakeProvider (local) | FakeProvider (simulated cloud, approval required)
   -> MemoryAuditSink (prompt-free decision and outcome events)
```

- The backend stays authoritative. The page renders the decision, reason code, approval request and audit events
  the transport returns; it does not compute a route. Explanations and estimates are generated server-side from the
  router's reason codes.
- Sensitivity stays server-owned, as in the transport: the demo creates one caller identity per sensitivity level
  and the browser chooses which identity to use. The keys never reach the browser.
- Approval is two-phase and unchanged. `/demo/approve` signs only the exact bindings the router presented, and only
  when a person clicks Approve. The router then re-verifies the envelope (HMAC, bindings, expiry, single use) as it
  would for any caller.

### Demo endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/`, `/static/app.js`, `/static/styles.css` | the three static files (nothing else is served) |
| GET | `/demo/config` | models, presets, limits |
| POST | `/demo/route` | validate a synthetic request and forward it to the transport |
| POST | `/demo/approve` | sign the presented bindings after a human click |
| GET | `/demo/audit` | audit events, newest first (metadata only) |
| POST | `/demo/reset` | replace the router instance |

## Security boundaries

- Binds to `127.0.0.1` (or `::1`) only; any other bind address raises an error. Requests whose `Host` header is not a
  loopback name are rejected, which blocks DNS rebinding.
- Every API route needs the per-launch UI token (constant-time comparison). Router API keys and the approval secret
  are per-launch, random and held only in server memory.
- Strict Content-Security-Policy (`default-src 'none'`, scripts and styles from self only, no inline code),
  `nosniff`, `no-referrer`, same-origin opener and resource policies and `no-store`.
- The page builds all output with `textContent`; it never uses `innerHTML` or evaluates strings, so markup in
  synthetic input is shown as text.
- No telemetry, analytics, external fonts, CDNs or third-party services. The only network connections are loopback
  connections from the demo server to the transport. Tests check both.
- Bounded input: 8 KiB request bodies, 2,000-character messages, output budgets of 1–2,048 tokens, an explicit field
  allowlist, `Content-Length` required, a 10-second socket timeout. The transport keeps its own limits.
- The demo writes nothing into the repository (bytecode caches go to a temporary directory) and does not log requests. The audit view and route responses never include the
  request text; the audit schema has no field for it.

## Tests

```bash
python3 -m unittest tests.test_demo_ui -v     # part of ./scripts/test.sh; standard library only
python3 scripts/demo_ui/e2e_check.py --screenshots /tmp/osr-shots   # optional browser check
```

`tests/test_demo_ui.py` runs the real demo server and transport. It covers the presets, local-first selection,
confidential and restricted cloud prohibition at every capability, approval binding and replay refusal, no silent
fallback, prompt-free audit, invalid, oversized, malformed and chunked bodies, token and Host checks, the static
file allowlist, security headers, the loopback-only bind and connections, and static accessibility and XSS checks
on the frontend.

`scripts/demo_ui/e2e_check.py` is an optional developer tool that needs Playwright for Python and a Chromium build
(recorded under `optional_developer_tools` in `release/dependency-lock.json`; not installed by `setup.sh` and not
needed by the release suite). It drives the page in a real browser: the three scenarios, XSS rendering, the keyboard
path and visible focus, no horizontal overflow at 1440, 1024 and 820 pixels, no console errors and no request to any
host other than the loopback server. It writes the three scenario screenshots outside the repository; screenshots
are not committed because the release scanner rejects binary files.

## Known limitations

- Demonstration only: in-memory state, one process, fake providers, synthetic models and prices. It does not run a
  model or measure cost, latency or quality.
- Token counts are approximated as characters ÷ 4. Costs use the disclosed synthetic price table and are labelled
  as estimates.
- Choosing sensitivity in the page stands in for a caller identity. In a deployment, sensitivity comes from the
  operator's identity configuration, not from the person making the request.
- The page is designed for desktop and tablet widths; phone layouts work but are not a target.
- Some managed sandboxes forbid loopback binding; run the demo in a normal local shell.
