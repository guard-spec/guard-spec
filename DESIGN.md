# Guard Spec design notes

This document describes the design **as built in v0.1.0**. It replaces the
pre-implementation draft of 2026-09-22. That draft also planned a dashboard,
ClickHouse, GPU serving and several third-party models; those parts were not
built, and the [last section](#planned-in-the-original-draft-not-built)
lists them so that nobody mistakes them for features. Routing to named
upstreams, text rule conditions, config as code and the policy simulator were
added after v0.1.0, and the admin UI is in progress. The README has the
user-facing details, measured benchmarks and configuration;
[docs/arch-flow.html](docs/arch-flow.html) shows the request flow, and
[docs/adr/](docs/adr/) holds the decision records.

## 1. Threat model

| Category | Vector | Handled by |
|---|---|---|
| Direct injection | User chat message | L0 sanitizer, detector (L1/L2/L3), policies |
| Indirect injection | Retrieved document, web page, e-mail, tool output | Scored per document / tool message, `INDIRECT_BLOCK_THRESHOLD`, optional spotlighting |
| MCP tool poisoning | Instructions in tool descriptions or schema descriptions | Detector plus MCP signals (`internal/indirect`), `/guardrail/scan/tools` |
| Character-level evasion | Tag-block characters, variation selectors, zero-width and bidi characters, homoglyphs, leetspeak, entity encoding | L0 sanitizer (normalize and strip before classifying), L1 skeleton |
| Output-side exfiltration | Markdown image beacons, links carrying data, leaked system prompt | Output guard (link/image allowlist, PII redaction, canary) |

Not in scope: harmful-content moderation, tool execution and egress control,
non-text content. See "Security model and limitations" in the README.

**Design principle: sanitize first, classify second.** Published work
(Hackett et al., arXiv:2504.11168) reports that character-injection tricks
such as emoji/variation-selector smuggling evade many guardrail classifiers.
Most of them disappear after NFKC normalization and removal of
default-ignorable code points, so the sanitizer runs before every detector and
its own anomaly score can block on its own.

**Positioning.** Defence in depth and a smaller blast radius, not "100%
detection". Benchmarks are published with their limitations.

## 2. Components

```
client ──► gateway (Go, Fiber) ──────────────► upstream LLM (OpenAI-compatible, Anthropic)
             │  reads keys, policies, settings, exemplars; writes audit rows
             ▼
          Postgres 17 ◄── control-plane (Go, Fiber): REST management API
```

- **gateway** (`cmd/gateway`): OpenAI-compatible proxy (`/v1/chat/completions`,
  `/v1/completions`), the Anthropic Messages API (`/v1/messages`) and
  guardrail endpoints (`/guardrail/scan`, `/guardrail/scan/tools`,
  `/guardrail/sanitize`). There is no REST sync from
  the control plane: the gateway reads Postgres directly and caches briefly.
- **control-plane** (`cmd/control-plane`): JWT login, organizations, RBAC,
  API keys, projects, policies, guard settings, exemplars, invites, audit log
  listing and audit retention.
- **Postgres**: all state. Shared schema with `org_id` on every tenant table
  and row-level security as a backstop; the services connect as the
  non-owner role `guardspec_app`, and every tenant query runs in a
  transaction that sets `app.org_id` with `set_config(..., true)`.
- **Models** (optional): files under `models/`, mounted read-only; never baked
  into an image.

## 3. Request pipeline (gateway)

1. **Tenant and rate limit.** API key (SHA-256 lookup), then per-key token
   buckets (requests and estimated tokens per minute, in memory per replica).
2. **Org settings.** `scan_roles` and `spotlight` overrides; failure to read
   them fails closed (503).
3. **L0 sanitizer** (`internal/sanitizer`), order fixed:
   UTF-8 validation; then, repeated until stable (at most 8 passes), NFKC,
   removal of default-ignorable / tag / variation-selector / bidi / control
   characters, ANSI escapes, HTML (bluemonday strict) and entity decoding,
   and removal of spoofed spotlight markers; then homoglyph detection (signal
   only). The anomaly score blocks at 0.6.
4. **Detector** (`internal/inference`). Text is split into overlapping windows
   and the worst window counts, so padding cannot push a payload past a cut.
   - L1 rules (`rules`, `skeleton`): canonical skeleton (diacritics,
     homoglyphs, fullwidth, leet, spelled-out letters, repeats, Vietnamese
     teencode), weighted phrase and co-occurrence rules per category, with
     suppressors for meta discussion, quotes and code.
   - L2 classifier (`ml`, `onnx`): `guardspec-classifier-v3b`, an 8-label
     sigmoid head on `intfloat/multilingual-e5-small`, INT8 ONNX; risk is
     1 − p(benign); 256-token windows with 64-token overlap.
   - L3 similarity: e5 embeddings against built-in and per-org exemplars.
   - Fusion (`fusion`): per-layer Platt scaling, logistic regression over the
     calibrated logits (fallback: max of the layers that ran), optional
     cascade. Calibration data: `fusion/testdata/calibration.jsonl` for L1 and
     the classifier's validation splits for L2/L3; never `eval/`.
   L2 and L3 run in parallel, in-process through ONNX Runtime
   (`yalue/onnxruntime_go` + `daulet/tokenizers`, see ADR 0001), and only in
   binaries built with `-tags onnx` and with the model files present.
   Otherwise the gateway runs L1 only.
5. **Fixed thresholds.** Direct ≥ 0.85 blocks; the largest untrusted score
   (tool results, documents, tool descriptions) ≥ `INDIRECT_BLOCK_THRESHOLD`
   blocks.
6. **Spotlighting** (optional): tool results wrapped in random-boundary
   delimiters or datamarked.
7. **CEL policies** (`internal/policy`). Rules are stored as a JSON condition
   tree and compiled to CEL on the server only. Project policies, then
   org-wide ones; first matching `allow` / `block` / `route` decides, `log`
   records and continues. At most 200 rules per policy, a per-rule cost limit,
   a shared per-request budget and a timeout; any failure is a 503. `redact`
   is refused when saved because the gateway cannot enforce it. Conditions can
   be edited as text: `policy.ParseCondition` runs the cel-go parser for the
   syntax tree only (no check, compile or evaluation of client text), accepts
   a small subset (`&&`, `||`, `!`, parentheses, field-vs-literal comparisons,
   `contains` / `startsWith` / `endsWith`, `in`) and rebuilds the JSON tree;
   parentheses found in the token stream keep groups, so
   `parse(format(tree))` gives the tree back in canonical form. The stored
   form stays the tree.
8. **Routing and upstream** (`cmd/gateway/routing.go`, migration 011). The
   upstream is the `route` rule's target, else the project's default, else
   the org's default (all named upstreams of the org), else
   `UPSTREAM_LLM_URL`, else a stub response. A missing or disabled target, or
   an unset `UPSTREAM_KEY_*` variable, fails closed with 502; there is no
   fallback to another upstream. Keys never reach the database: an upstream
   names the gateway variable that holds its key, and the operator's
   `UPSTREAM_KEY_ORGS` says which org may name which variable (checked on
   save by the control plane and again per request by the gateway, since an
   org admin controls `base_url`). Org upstreams may not reach cloud metadata
   addresses, nor loopback/private/CGNAT ones unless
   `UPSTREAM_ALLOW_PRIVATE=true`, checked by the dialer after DNS. The
   upstreams a request may need are read in the policies' transaction. One
   proxy (and connection pool) per upstream is cached until the row's
   `updated_at` changes. Defaults reference upstreams through composite
   foreign keys that include `org_id`, since foreign keys are checked without
   RLS.
9. **Output guard** (`internal/outputguard`): link/image allowlist, PII
   redaction (e-mail, Vietnamese phone, CCCD, Luhn-valid cards, optional
   IPv4), canary, reasoning fields, refusals and tool-call arguments; whole
   responses and streams (256-character window).
10. **Audit row** in `requests`: hashes and lengths by default, content only
    when enabled; `route_target` names the upstream used.

The control plane also serves the admin UI (`web/`, embedded from
`web/dist` with `go:embed`) at `/ui/` under a strict CSP, keeps the org's
upstreams, defaults and policies as one YAML file (`GET`/`PUT .../config`,
applied in one transaction, the file is the whole truth), and simulates
policies against given field values.

CEL variables: `request.model`, `request.tenant_id`, `request.tokens`,
`injection.score`, `injection.label`, `injection.category`, `scores.l1`,
`scores.l2`, `scores.l3`, `indirect.score`, `indirect.source`,
`injection.source_role`, `anomaly.score`, `anomaly.has_tag_chars`,
`anomaly.has_bidi`, `mcp.is_tool_response`.

## 4. Data and evaluation

- `eval/`: 2,176-row EN/VI eval set, built deterministically. **Never used
  for training, calibration or threshold tuning** of L2/L3/fusion. The L1
  rules were refined on half of it, which is documented in `eval/README.md`.
- `train/`: data generation, training, ONNX export and calibration of the
  classifier; rows whose fingerprint is in `eval/fingerprints.txt` are
  dropped from training data.
- CI compares the L1 detector with `eval/baseline.json` on every PR, and the
  model layers with `eval/baseline-onnx.json` when models are present.

## 5. Packaging

- `docker-compose.yml` (+ dev override): gateway (built with `-tags onnx`,
  ships `libonnxruntime`), control plane, Postgres, migrations, `db-roles`,
  optional `models-pull`.
- `deploy/helm/guard-spec`: gateway and control plane against an external
  Postgres.
- GoReleaser: static (`CGO_ENABLED=0`, L1-only) binaries for linux/darwin ×
  amd64/arm64, distroless images for linux amd64/arm64, SBOMs, keyless cosign
  signatures.

## 6. Key risks and their mitigations

| Risk | Mitigation in the code |
|---|---|
| Naive truncation hides a payload | Windowing with overlap, max over windows; too many windows is rejected with 413, not truncated |
| Tenant leak through pooled connections | Transaction-local `set_config('app.org_id', ..., true)`; RLS; integration tests |
| Tokenizer or export mismatch | Golden-file tests in `internal/onnx/testdata`; pinned SHA-256 in `models/manifest.yaml` |
| CEL expression DoS by a tenant | Compile-time checks, runtime cost limits, rule cap, timeout, fail closed |
| Model license drift | Pinned revisions; `make licenses-check` in CI; NOTICE lists model and data licenses |
| False positives, mainly Vietnamese teencode / no diacritics with L2/L3 | `DETECTOR_LAYERS=l1` option; documented rates; classifier v2 on the roadmap |

## 7. License compliance

Apache-2.0. Model families with incompatible licenses are not used: Llama
Guard / Prompt Guard (Llama Community License), ShieldGemma (Gemma Terms of
Use), NVIDIA NeMoGuard. The L2 base model is MIT; datasets and their licenses
are in `train/DATA_LICENSES.md` and `eval/LICENSES.md`.

## Planned in the original draft, not built

These appeared in the 2026-09 draft (and in older versions of this repository's
compose file and README). **None of them exists in v0.1.0.** Some are on the
[roadmap](ROADMAP.md); the rest are not planned.

- A Next.js dashboard with attack analysis and monitoring. (A smaller admin UI
  is in progress at `/ui/`, and routing to named upstreams with the `route`
  action is built; see sections 3 and the README.)
- Fallback chains and cost caps for routing.
- Input-side PII NER, toxicity and topic classifiers (the `pii.entities`,
  `toxicity.score` and `topic.categories` policy fields were removed). Decided
  against for now in [ADR 0002](docs/adr/0002-no-input-pii-toxicity-topic.md).
- ClickHouse audit storage, hash-chained tamper-evident logs.
- GPU serving through Triton; Granite Guardian, Qwen3Guard and other LLM judges.
- hugot as the ONNX library (ADR 0001 chose onnxruntime_go instead).
- `/v1/embeddings` pass-through and `/guardrail/models`.
- gRPC between gateway and control plane; OIDC/SAML/SCIM; open-core tiers.
- Unmeasured latency targets from the draft (per-model milliseconds, CEL
  nanoseconds) were removed; the README has measured numbers only.

## References

- Hackett et al., arXiv:2504.11168: character injection against guardrails
- Hines et al., arXiv:2403.14720: spotlighting
- Debenedetti et al., arXiv:2503.18813: CaMeL
- OWASP Top 10 for LLM Applications 2025
- AgentDojo, arXiv:2406.13352; InjecGuard, arXiv:2410.22770
- cel-go: https://github.com/google/cel-go
