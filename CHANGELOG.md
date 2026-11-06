# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes; they are listed under
"Changed" and in the upgrade notes.

## [Unreleased]

### Added

- Bench workflow (`.github/workflows/bench.yml`, manual only): detection
  latency with the released v3b and multilingual-e5-small models on
  GitHub-hosted `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` runners, as a
  markdown table in the job summary and an artifact. `cmd/eval` and
  `cmd/onnxbench` now also report p95.
- `GET /v1/organizations/:orgId/dashboard`: request log aggregates over 24h,
  7d or 30d (totals, block rate, latency p50/p95/p99, an hourly or daily
  series, top detections, rules and projects), computed in Postgres. The
  admin UI dashboard uses it, with a period and a project filter, instead of
  sampling the latest 1,000 requests in the browser.
- Helm chart: `dbRoles.podSecurityContext` sets the pod securityContext of
  the `dbRoles` job.
- Helm chart: the control plane reads `MFA_ENC_KEY` from `existingSecret`
  when the key is there (optional; `controlPlane.extraEnvFrom` still works).
- `GET /readyz`: `detector.required` reports `DETECTOR_REQUIRE_ML`.

### Changed

- `GET /readyz` answers 503, with `"status":"degraded"` and the same detailed
  body, when a detection layer the configuration requires
  (`DETECTOR_REQUIRE_ML=true`) is missing. A gateway that runs on fewer
  layers without requiring them (the plain image without models) stays at
  200 with `"degraded":true`. Outside `GUARD_ENV=dev` such a gateway already
  refused to start, so this shows mostly in dev mode.
- Helm chart: the gateway mounts a volume at `/models` only with a models
  claim (`models.existingClaim`, or `models.persistence.enabled=true`, the
  default). With neither, nothing is mounted (before: an `emptyDir`), so
  `guard-spec-gateway-full` keeps the models inside its image and starts.
- Helm chart: gateway resources default to a 500m CPU / 1Gi request and a
  2Gi memory limit (before: 250m / 256Mi and 1Gi); L1 + L2 + L3 use about
  900 MiB right after start.
- Helm chart: the `dbRoles` job no longer forces `runAsUser: 70` on
  OpenShift (clusters serving `security.openshift.io/v1`), where the SCC
  assigns the UID; elsewhere it still defaults to 70 unless
  `dbRoles.podSecurityContext` sets one.

### Documentation

- README: the `kubectl create secret` example includes `MFA_ENC_KEY`.
- docs/deploy: the workarounds for the points above are gone; notes on
  Helm 4 post-renderers (plugins only) and on migration 004's
  `CREATE ROLE` on a Postgres server shared with other databases.

## [0.1.0] - 2026-11-06

First release.

### Added

**Gateway and detection**

- OpenAI-compatible gateway: `/v1/chat/completions` and `/v1/completions`,
  streaming included, in front of any OpenAI-compatible upstream.
- L0 sanitizer: UTF-8 validation, repeated NFKC, removal of invisible,
  tag-block, bidi, variation-selector and control characters, ANSI and HTML,
  entity unwrapping, a homoglyph signal and an anomaly score that blocks at
  0.6. Content that HTML hides from the reader is kept between `[hidden]`
  markers so that the detectors see it.
- L1 rules on a skeleton of the text (Vietnamese diacritics and teencode,
  leetspeak, homoglyphs, fullwidth and spelled-out letters), weighted per
  attack category, with suppressors for meta discussion, quotes and code.
- L2 classifier `guardspec-classifier-v3b`: multilingual-e5-small fine-tuned
  on English and Vietnamese, INT8 ONNX, run in process with ONNX Runtime
  (`-tags onnx`). The training pipeline is in `train/`, with a model card.
- L3 similarity to 520 built-in exemplars and to each organization's own.
- Calibrated fusion of the layers into one injection score, fitted outside
  `eval/`; optional cascade; L1-only fallback when models are absent.
- Indirect injection and MCP tool poisoning: tool results, documents and tool
  descriptions are scored one by one (`INDIRECT_BLOCK_THRESHOLD`), with MCP
  poisoning signals and optional spotlighting; `POST /guardrail/scan`,
  `/guardrail/scan/tools` and `/guardrail/sanitize`.
- Output guard: link and image allowlist, redaction of e-mail, Vietnamese
  phone, CCCD and card numbers (and optionally IPv4), a canary, reasoning
  fields and tool-call arguments, in whole responses and streams.
- `GET /readyz` lists the active detection layers.

**Policies and routing**

- CEL policies per organization and project, written as a condition tree or
  as text (`scores.l2 > 0.8 && injection.category == "jailbreak"`), compiled
  on the server, fail-closed: `allow`, `block`, `log` and `route`. A policy
  simulator and config as code (`GET`/`PUT .../config`, YAML, dry run).
- Named upstreams per organization (OpenAI, Azure OpenAI, Anthropic, Gemini,
  vLLM, Ollama) with defaults per org and project, allowed models, headers,
  limits, retries and a connection test. Keys stay in the gateway's
  environment (`UPSTREAM_KEY_*`, `UPSTREAM_KEY_ORGS`); private and metadata
  addresses are refused.

**Control plane and administration**

- Organizations, projects, roles (viewer, member, admin, owner), invites,
  API keys with per-key rate limits; Postgres row-level security per
  organization.
- Sessions, TOTP two-factor authentication with recovery codes, OpenID
  Connect single sign-on (Google preset, Entra ID, Okta, Keycloak), an
  organization security policy (require 2FA, login methods, domain join,
  session lifetime), user management and an activity log.
- Real-time alerts: events for blocked and flagged requests, upstream
  failures and security changes; rules with conditions, thresholds,
  throttling, grouping and quiet hours; Telegram, Slack, Microsoft Teams,
  email, signed webhooks, A2A agents and an in-app bell; delivery with
  retries and a delivery log.
- Audit: one row per request with scores and the decision (content only on
  opt-in), retention in days.
- Admin UI at `/ui/`, English and Vietnamese, light and dark: dashboard,
  request flow with editable policy rules, simulator, providers, request log,
  alerts, members, security and my account.

**Models, operations and supply chain**

- Versioned models: `models pull name@version`, SHA-256 verified, from
  Hugging Face with GitHub Release mirrors; `L2_MODEL` / `L3_MODEL` pick a
  version.
- `scripts/quickstart.sh`, Docker Compose with the released images, a Helm
  chart, and the `gateway-full` image with the models built in.
- Images for linux/amd64 and arm64 signed with cosign, SBOMs and provenance;
  archives with signed checksums; `version` subcommand in every binary.
- Prometheus metrics and OpenTelemetry tracing.
- EN/VI eval set (2,176 rows) with a deterministic builder, `cmd/eval` and
  CI regression baselines.
- Community files: CONTRIBUTING (DCO), CODE_OF_CONDUCT, SECURITY, MAINTAINERS,
  ROADMAP, issue and pull request templates, Vietnamese README.

### Known issues

- With L2 and L3, 1.4% of benign eval prompts are blocked; benign Vietnamese
  teencode is blocked 3.5% of the time. The Vietnamese eval and training data
  is synthetic.
- The plain release archives (`guard-spec_<version>_<os>_<arch>.tar.gz`) are
  built without `-tags onnx` and run L1 only; use the gateway image or the
  linux `_onnx` tarball for the model layers. There is no darwin ONNX build.
- The Helm chart has no autoscaling, PodDisruptionBudget, Ingress or
  migration job yet, and the models volume is ReadWriteOnce.
- List endpoints still answer the older `{"data": [...]}` shape when called
  without `limit` and `cursor`; use the paginated form.

[Unreleased]: https://github.com/guard-spec/guard-spec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/guard-spec/guard-spec/releases/tag/v0.1.0
