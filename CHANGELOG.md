# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes; they are listed under
"Changed" and in the upgrade notes.

## [Unreleased]

### Added

- **Routing to named upstreams** (migration 011). An organization defines
  upstreams (`/v1/organizations/:orgId/upstreams`) and a default for the org
  and for each project. The gateway sends an allowed request to the matching
  `route` rule's `route_target`, else the project default, else the org
  default, else `UPSTREAM_LLM_URL`, else the stub. A missing or disabled
  target, or an unset key variable, fails closed with 502
  (`route_unavailable`). Keys stay in the gateway's environment
  (`UPSTREAM_KEY_*`, named by `api_key_env`); no secret is stored. Deleting
  an upstream in use returns 409 with its references.
- The **`route` rule action**; `redact` is still refused.
- **Text rule conditions**: `GET /v1/policy/schema`, `POST /v1/policy/parse`
  and `POST /v1/policy/format`. Text is parsed with the cel-go parser only and
  mapped to the condition tree; the stored form and the generated CEL are
  unchanged. Two new string operators, `beginsWith` and `endsWith`.
- **Config as code**: `GET`/`PUT /v1/organizations/:orgId/config` (YAML,
  `?dry_run=true`), applied in one transaction; the file is the whole truth.
- **Policy simulator**: `POST /v1/organizations/:orgId/policies/simulate`.
- Audit rows record `route_target`; `GET .../requests` returns it, and the
  action `route` when a route rule decided.
- The control plane serves the admin UI at `/ui/` (embedded from `web/dist`,
  strict CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) and
  redirects `/` there. Builds without Node show a placeholder.
- `GET /v1/organizations`: the organizations of the signed-in user, with the
  role in each (migration 012 adds `user_organizations`, a narrow
  `SECURITY DEFINER` lookup, since memberships are row-level secured per org).
- `POST /v1/organizations/:orgId/policies` accepts `enabled` (default true), so
  a policy can be created disabled without being live in between.
- **Admin UI** (`web/`, React and TypeScript): a flow diagram of the request
  path with the policy rules as editable nodes (visual and text conditions,
  drag to reorder, connect a rule to an upstream to route it), a policy
  simulator, upstreams and defaults, config as code (YAML with validation,
  diff and apply), guard settings, API keys, projects, exemplars and the audit
  log. English and Vietnamese, light and dark themes. Released control-plane
  binaries and images embed it (GoReleaser builds it before the Go builds).
- Metric `guardspec_gateway_route_selections_total{source,outcome}`.
- `UPSTREAM_KEY_ORGS` (gateway and control plane): which organizations may
  name which `UPSTREAM_KEY_*` variable. Empty by default, so no org can use
  a key until the operator lists it (`UPSTREAM_KEY_MAIN=*` for every org).
  Refused on save and, for older rows, at request time (502).
- `UPSTREAM_ALLOW_PRIVATE` (gateway, default `false`): org-defined upstreams
  may not reach loopback, RFC 1918, unique local or CGNAT addresses unless it
  is `true`. Compose sets `true` and `UPSTREAM_KEY_ORGS=UPSTREAM_KEY_MAIN=*`.
- L2 classifier `guardspec-classifier-v2` (`train/`): more benign Vietnamese
  text in teencode and without diacritics (`data/gen_vi_v2.py`), randomized
  teencode spellings, the same benign:attack ratio in every variant, and
  training-time no-diacritics / teencode augmentation. New validation split
  `train/data/val_vi_variants.jsonl`. The gateway loads
  `models/local/guardspec-classifier-v2` first, then `-v1`, then `-v0`.
- L2 classifier `guardspec-classifier-v3b` (`train/`), the new default: the
  v3 recipe (English hard negatives from `data/gen_v3.py`, English prompts
  from `nvidia/HelpSteer2` (CC-BY-4.0), realistic EN/VI rows in
  `data/realistic/` with formal Vietnamese seen twice per epoch, a
  per-language benign:attack ratio of EN 2.0 / VI 1.75) plus owner-supplied
  rows and OTP/eKYC rows read at build time and not redistributed
  (`GUARD_OWNER_*`, `GUARD_OTPKYC_*`, `GUARD_BUILD_OUT`). On the eval set
  (fused, 0.85): FPR 1.4% (v2 2.0%), TPR 0.932 (v2 0.933), Vietnamese
  no-diacritics FPR 0.4% (v2 3.0%), but teencode FPR 3.5% (v2 1.4%).
  New validation split `train/data/val_v3.jsonl` (also used by
  `cmd/calibrate fit`) and hold-outs `val_v3_holdout`,
  `val_realistic_holdout`. Built-in fusion calibration for v3b. The gateway
  loads `models/local/guardspec-classifier-v3b` first, then `-v2`, `-v1`,
  `-v0`. Classifier v3 (the same recipe without the owner rows) failed the
  eval set (FPR 2.2%, TPR 0.915) and is not shipped or searched by default.
- `train/soup.py` (weight averaging of seed runs; tried for v3, not used),
  and `train.py` / `export.py` flags to override seed, learning rate, epochs,
  label smoothing, run, output and data directories, and the training file.
- `eval/baseline-onnx.json` now holds the v3b run.
- Sanitizer: content that HTML hides from the reader (`display:none`,
  `visibility:hidden`, `font-size:0`, `opacity:0`, white on white,
  `aria-hidden`, `hidden`, `sr-only`-style classes, HTML comments) is kept
  between `[hidden]` and `[/hidden]` markers instead of being dropped (comments)
  or losing the fact that it was hidden; `Report.HadHiddenHTML` signals it.
- L1 rules `ii.hidden.override`, `ii.hidden.send`, `ii.hidden.address_ai`
  and `ii.hidden.boost`: override, exfiltration or model-addressed language
  inside hidden content is an indirect injection, without the meta and quote
  suppressors.

### Changed

- The gateway's dialer refuses link-local, multicast and unspecified
  addresses and the cloud metadata addresses `fd00:ec2::254`,
  `100.100.100.200` and `192.0.0.192` for every upstream, including
  `UPSTREAM_LLM_URL`.
- Policy names are unique per organization: create or rename onto a used
  name returns 409. `GET .../config` returns 409, with the problems and how
  to fix them, when the stored config would not apply again.
- The audit `model` column holds the model sent upstream after a named
  upstream's `model` rewrite.
- `GET /organizations/:orgId` and the project list include
  `default_upstream_id`.
- L1 treats a ```` ``` ```` fence as a code block, not as a quotation, so an
  instruction wrapped in a fence is no longer discounted as a string literal;
  spacing modifier letters (`ˆ`, `ʼ`, ...) separate words, so datamark-style
  text is matched.
- `DefaultL1Calibration` refitted for the new rules (A 0.998, B 0.356);
  `eval/baseline.json` refreshed (FPR unchanged in every group; two attack
  rows near 0.85 moved below it).
- `cmd/calibrate fit` uses `val_vi_variants.jsonl` too by default.

### Fixed

- `GET /v1/organizations/:orgId/requests` no longer fails (500) on audit rows
  whose scores or flags are NULL; they read as 0 and false.

## [0.1.0] - unreleased (release candidate)

First release. Summarises everything since the PromptShield prototype that
was imported into this repository.

### Upgrade notes (from the PromptShield prototype)

- **Renamed to Guard Spec.** Go module `github.com/giaplee/guard-spec`;
  images `ghcr.io/giaplee/guard-spec-gateway` and `-control-plane`; `Server`
  headers `guard-spec` and `guard-spec-cp`; new API keys `gs_...` and invite
  tokens `gsinv_...` (old `ps_` keys and `psinv_` invites keep working).
- **Database role** `ps_app` is renamed to `guardspec_app` by migration 010.
  Run the migrations as the owner, set `GUARDSPEC_APP_PASSWORD` (the old
  `PS_APP_PASSWORD` is still read for one release, with a warning), then
  change the user in `DATABASE_URL`, in one maintenance window.
- **Default database and compose project** are now `guardspec` and
  `guard-spec`. To keep an existing stack's data, set
  `POSTGRES_DB=promptshield` and `COMPOSE_PROJECT_NAME=<old directory name>`.
- **Secrets are required** outside `GUARD_ENV=dev`: `POSTGRES_PASSWORD`,
  `GUARDSPEC_APP_PASSWORD`, `JWT_SECRET`, `ADMIN_PASSWORD`. Default, weak or
  missing values stop the services. Production must not load
  `docker-compose.override.yml`.
- **Audit retention** starts with migration 007: rows older than 90 days are
  deleted. Set `AUDIT_RETENTION_DAYS=0` before upgrading to keep them.
- **Policy fields** `toxicity.score`, `pii.entities` and `topic.categories`
  were removed; run `control-plane -check-policies` to find rules that use
  them. `log` rules no longer stop evaluation.
- **`[DATA]` markers** are no longer added to prompts; use `SPOTLIGHT`.

See "Upgrade notes" in the README for the full procedure.

### Added

- OpenAI-compatible gateway: `/v1/chat/completions` and `/v1/completions`
  proxied to any OpenAI-compatible upstream (`UPSTREAM_LLM_URL`), streaming
  included; stub responses without an upstream.
- L0 sanitizer: UTF-8 validation, repeated NFKC and removal of invisible,
  tag-block, bidi, variation-selector and control characters, ANSI and HTML,
  entity unwrapping, homoglyph signal and an anomaly score that blocks at 0.6.
- L1 detector v2: skeleton normalisation (Vietnamese diacritics and teencode,
  leetspeak, homoglyphs, fullwidth, spelled-out letters) and weighted
  per-category rules with suppressors for meta discussion, quotes and code.
- L2 classifier `guardspec-classifier-v1`: multilingual-e5-small fine-tuned
  on English and Vietnamese with an 8-label head, INT8 ONNX, with the
  reproducible training pipeline in `train/` and a model card.
- L3 embedding similarity to 520 built-in exemplars and per-organization
  exemplars (`/v1/organizations/:orgId/exemplars`, migration 009).
- Calibrated fusion: Platt scaling per layer and a logistic regression over
  the layers, fitted outside `eval/`; optional cascade; `DETECTOR_*`
  settings; L1-only fallback when models are absent.
- In-process ONNX Runtime (`-tags onnx`) with pinned, SHA-256-checked native
  libraries and model downloads (`cmd/models`, `models/manifest.yaml`).
- Indirect injection and MCP tool poisoning: tool results, documents and tool
  descriptions scored on their own, MCP poisoning signals, `SCAN_ROLES`,
  `SPOTLIGHT`, `INDIRECT_BLOCK_THRESHOLD`, per-org guard settings (migration
  008), `POST /guardrail/scan` with `documents`, `POST /guardrail/scan/tools`.
- Output guard: link and image allowlist, PII redaction (e-mail, Vietnamese
  phone, CCCD, card, optional IPv4), canary, reasoning fields, refusals and
  tool-call arguments, in whole responses and streams.
- CEL policies per organization and per project, compiled server-side from a
  JSON condition tree, with cost limits and fail-closed evaluation; layer
  scores (`scores.l1/l2/l3`) and indirect fields in policies.
- Control plane: login, organizations, roles, API keys with per-key rate
  limits, projects, policies, invites, audit log listing, audit retention.
- Per-key rate limits, Prometheus metrics, OpenTelemetry tracing.
- Audit privacy: hashes and lengths by default, content only on opt-in.
- EN/VI eval set (2,176 rows) with a deterministic builder, `cmd/eval` and
  CI regression baselines.
- Release gateway images built with `-tags onnx` (ONNX Runtime included) for
  linux/amd64 and linux/arm64 on native runners: they run L1 + L2 + L3 when
  the models are mounted at `/models`, and L1 only, with a warning, when it is
  empty. Linux `_onnx` tarballs with the same binary and `libonnxruntime.so`.
  The plain release archives stay static and run L1 only.
- `GET /readyz` on the gateway: lists the active detection layers, why a
  requested layer is missing, and whether the binary has `-tags onnx`. The
  gateway image `HEALTHCHECK` and the Helm readiness probe use it.
- Helm chart, GoReleaser pipeline with SBOMs and keyless cosign signing,
  CodeQL, govulncheck, golangci-lint and license checks in CI.
- Community files: CONTRIBUTING (DCO, the `eval/` rule), CODE_OF_CONDUCT,
  MAINTAINERS, ROADMAP, issue and pull request templates, Vietnamese README.

### Changed

- Project renamed from PromptShield to Guard Spec (see upgrade notes).
- Tool messages are classified separately from the user's text.
- Upstream failures are audited as `error`, not `allow`.
- README, README.vi.md, DESIGN.md and `docs/arch-flow.html` (moved from the
  repository root) rewritten to describe what is built; unmeasured latency
  claims removed; benchmarks are now measured numbers with their limits.

### Removed

- `ui`, `clickhouse` and `model-init` compose services, `build/model-init.Dockerfile`
  and `cmd/model-init/download.py`: placeholders for components that were
  never built (admin UI, ClickHouse analytics, Qwen3Guard/DeBERTa download).
- Unused `CLICKHOUSE_URL`, `CONTROL_PLANE_URL` and `LOG_LEVEL` compose
  variables; stale Makefile targets (`-tags ORT`, `models-download`,
  `generate`).
- Policy fields `toxicity.score`, `pii.entities`, `topic.categories`.

### Fixed

- Migration 002's down step failed once the `requests` table had rows for
  the default organization; it now deletes those audit rows first. CI
  inserts rows before rolling all migrations back.
- Many sanitizer, scanner and output-guard bypasses found in review; the
  gateway fails closed when policies or settings cannot be read.
- Control-plane authentication and tenant isolation (row-level security,
  non-owner application role without a default password).

### Known issues

- With L2/L3 enabled, about 2.7% of benign eval prompts are blocked, mostly
  Vietnamese teencode and text without diacritics (L1 alone: 0.1%).
- The classifier weights are not published; build them with `train/`.
- The plain release archives (`guard-spec_<version>_<os>_<arch>.tar.gz`) are
  built without `-tags onnx` and run L1 only; use the gateway image or the
  linux `_onnx` tarball for the model layers. There is no darwin ONNX build.

[Unreleased]: https://github.com/giaplee/guard-spec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/giaplee/guard-spec/releases/tag/v0.1.0
