# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes; they are listed under
"Changed" and in the upgrade notes.

## [Unreleased]

### Added

- L2 classifier `guardspec-classifier-v2` (`train/`): more benign Vietnamese
  text in teencode and without diacritics (`data/gen_vi_v2.py`), randomized
  teencode spellings, the same benign:attack ratio in every variant, and
  training-time no-diacritics / teencode augmentation. New validation split
  `train/data/val_vi_variants.jsonl`. The gateway loads
  `models/local/guardspec-classifier-v2` first, then `-v1`, then `-v0`.
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

- L1 treats a ```` ``` ```` fence as a code block, not as a quotation, so an
  instruction wrapped in a fence is no longer discounted as a string literal;
  spacing modifier letters (`ˆ`, `ʼ`, ...) separate words, so datamark-style
  text is matched.
- `DefaultL1Calibration` refitted for the new rules (A 0.998, B 0.356);
  `eval/baseline.json` refreshed (FPR unchanged in every group; two attack
  rows near 0.85 moved below it).
- `cmd/calibrate fit` uses `val_vi_variants.jsonl` too by default.

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
- Release images and archives are built without `-tags onnx` and run L1
  only; build `build/gateway.Dockerfile` for the model layers.

[Unreleased]: https://github.com/giaplee/guard-spec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/giaplee/guard-spec/releases/tag/v0.1.0
