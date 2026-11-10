# Authenticated Localhost Transport

Status: implemented development transport; independently reviewed; covered by the offline and loopback suite (the IPv6 bind test is skipped on hosts without IPv6 loopback). Not production-ready: the accepted residual and deferred gates below remain.

## Trust boundaries

- The server binds to `127.0.0.1` by default (`::1` is also supported, using an IPv6 socket) and rejects non-loopback bind requests.
- `X-OSR-API-Key` is matched against a server-managed identity registry using hashed, constant-time comparisons. The registry supplies trusted actor and sensitivity; body attempts to set actor, sensitivity, provider, or endpoint are rejected.
- Parsed messages are schema- and size-validated, then canonicalized together with `max_tokens`. The SHA-256 of that canonical form enters the routing request and any cloud approval binding, so an approved request cannot be replayed with different messages or a larger output budget.
- `X-OSR-Approval` is bounded, passed only to the approval verifier, and excluded from responses and audit events.
- A body `model` may select only a configured registry model. Per-request endpoint/provider/base-URL overrides are prohibited.
- Only `model`, `messages`, `max_tokens`, `stream` and `required_capability` are accepted. Any other field, including common OpenAI sampling fields such as `temperature`, is rejected with 400 rather than silently ignored. `required_capability` must be a true integer, not a boolean.
- The `Host` header must name a loopback host (`127.0.0.1`, `localhost` or `[::1]`, with an optional port). This is a DNS-rebinding defence; CORS stays disabled.

## Two-phase cloud approval

1. The client sends a chat request. If policy selects a cloud route and no approval is supplied, the server mints a request ID, stores a pending entry (actor, canonical payload digest, monotonic expiry), audits the `approval_required` decision and returns 409 with `approval_request`: `request_id`, `expires_at`, the exact `bindings` the approver must sign, and an informational, unsigned `max_tokens` so the approver can see the output budget that the signed digest covers. The response contains no prompt text, only the digest.
2. An approver who holds the approval secret reviews those bindings out of band and issues a one-time envelope with its own short TTL and nonce.
3. The client resubmits the identical messages and `max_tokens` with `X-OSR-Approval` and `X-OSR-Approval-Request-Id`. The server atomically claims the pending entry, and only when the same actor presents the same payload digest; any other caller is rejected without touching the entry. The token must then verify against the server-held request ID. A successful execution consumes the entry, so neither a replayed token nor a fresh token can run the request again. A failed attempt by the owner restores the entry until its original expiry, unless the owner has filled its own quota with newer requests in the meantime; in that case the entry is dropped and the owner restarts phase 1. Other key holders can never claim, and therefore never cancel, a legitimate request.
4. The pending store is bounded in total (`max_pending_approvals`) and per actor (`max_pending_per_actor`; an actor's own oldest entry, by insertion order, is evicted first, so one actor cannot exhaust the store for others). Entries expire after `pending_approval_ttl_seconds`, measured on a monotonic clock. A full store returns 429 and is audited as `approval_queue_full`. It lives in a single process: a restart drops pending approvals, and multi-process deployment needs a durable store, which is a later gate.

Every approval failure, including a malformed `X-OSR-Approval` or `X-OSR-Approval-Request-Id` header or a reference sent without a token, is audited and returned to the caller as a generic 409 `invalid approval`. The specific verifier reason is recorded only in the audit `detail` field.

## Interfaces and limits

The stdlib HTTP service exposes authenticated `/health`, `/v1/health`, `/models`, `/v1/models`, and `/v1/chat/completions`. Chat output uses the non-streaming OpenAI-compatible shape; `stream=true` is explicitly rejected. Body bytes, message count/size, output size, maximum tokens, elapsed provider time, concurrent calls, simultaneous connections (`max_connections`; excess connections get an immediate 503) socket idle time per read (`socket_timeout_seconds`; a stalled body gets 408) and the **total** time to receive headers and body (`read_deadline_seconds`: a watchdog shuts down connections that drip bytes to dodge the per-read timeout) are all bounded. A POST is authenticated before its body is read. A missing, chunked or non-decimal Content-Length (for example `+15`, `1_5`, `0x0f`) gets 411. The Host port must be ASCII digits in the range 1–65535. Malformed, deeply nested or non-finite (`NaN`/`Infinity`) JSON gets a structured 400. Server tracebacks are suppressed. The response `model` is always the routed model, and a provider that reports a different model is rejected with 502. Errors use a structured, length-bounded form and do not echo prompt, token, secret, endpoint, or upstream body.

`ProviderExecutor` is the execution protocol. `FakeProvider` supports offline tests. `LlamaCppAdapter` is a configured-endpoint design: endpoint and model are constructor-owned and redirects are disabled. Tests do not invoke it or make outbound requests. There is no silent provider fallback.

## Accepted residual: pre-authentication lockout by local processes

Connection slots (`max_connections`) are claimed before authentication, because the API key is only known once the headers have been read. The read deadline bounds each individual connection, but any process on the same host that keeps reopening slow connections can occupy every slot and lock legitimate clients out **indefinitely**, without credentials. A probe with `max_connections=2` saw 9 of 10 valid requests rejected with 503 over 5 seconds. This is accepted for a single-user localhost development transport, since a hostile local process can already deny service in many other ways. It must be revisited, for example with reserved slots, per-peer limits or OS-level socket permissions, before any multi-user or non-localhost deployment.

## Audit behavior

Every policy decision, including blocked ones (`approval_required`, `invalid_approval`, `sensitive_local_unavailable`, and others), is written as a `decision` event. For selected routes the decision event is written before the provider is invoked. After the provider call, an `outcome` event records `completed`, `provider_error`, `provider_unavailable`, `timeout`, `invalid_output` or `model_mismatch`. Any audit failure returns `audit_unavailable`: before the provider call, the provider is not called; after it, the provider output is withheld. Requests rejected during schema validation, before any routing decision, are not audited. `FileAuditSink` uses append mode, `fsync`, and owner-only `0600` permissions; its typed interface accepts only the prompt-free `AuditEvent`. This is process/filesystem append behavior, not tamper-proof storage against an administrator.

## Deferred real-network gates

Before any real provider promotion: add connection-time DNS resolution and IP pinning, rebinding protection, redirect verification, TLS/certificate policy, interruptible timeouts, durable multi-process replay and pending-approval state, an approver tool or user interface, API-key/approval-secret rotation, revocation, and production audit integrity/retention. The current elapsed-time check detects a slow return but cannot preempt a blocked provider call.
