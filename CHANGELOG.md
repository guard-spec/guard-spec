# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes; they are listed under
"Changed" and in the upgrade notes.

## [Unreleased]

### Added

- Gateway: `POST /v1/messages`, the Anthropic Messages API, so that Claude
  Code can use the gateway as `ANTHROPIC_BASE_URL` (API-key mode, with
  `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY` set to a Guard Spec key).
  Requests go through the same checks as chat completions: user text, system
  text and `tool_use` input by the scan roles, `tool_result` blocks and text
  documents as untrusted content, tool definitions for poisoning; policies,
  routing, rate limits, shadow mode, metrics and audit rows as on
  `/v1/chat/completions`. Answers, streamed or not, go through the output
  guard (text, thinking, tool input). Requests are sent as they are to an
  upstream with provider `anthropic` (`{base_url}/messages`, its key as
  `x-api-key`, the client's `anthropic-version` or `2023-06-01`, and
  `anthropic-beta` without OAuth values); any other upstream gets a 400, with
  no translation. Errors use the Anthropic error shape with the same
  statuses. `UPSTREAM_LLM_PROVIDER=anthropic` lets `UPSTREAM_LLM_URL` serve it.
- Gateway: `POST /v1/messages/count_tokens`, forwarded to the Anthropic
  upstream without scanning, and `GET /v1/models`, the models of the key's
  default upstream, in the OpenAI list shape or Anthropic's (with an
  `anthropic-version` header).
- Gateway: `SCAN_TOOL_PREFIXES` limits the tool-poisoning check to tools whose
  name starts with one of the given prefixes. Claude Code's own `Bash` and
  `Agent` tool descriptions score as poisoning; `SCAN_TOOL_PREFIXES=mcp__`
  checks only the tools of its MCP servers.
- Control plane: the Anthropic provider preset says it also serves
  `/v1/messages` (`anthropic_messages`), and the connection test of an
  Anthropic upstream sends the key as `x-api-key` with `anthropic-version`.
- `docs/integrations.md`: Claude Code through the gateway, checked with the
  real CLI against a fake Anthropic upstream; Cursor and `/v1/models`, not
  verified.

- `docs/security/`: documentation for security teams: architecture and trust
  boundaries, the data flow of a request, what is stored where and for how
  long (audit content off by default, retention per table), secrets and
  encryption at rest, and how to verify a release (cosign signatures pinned
  to the release tag, SBOMs, SLSA provenance) with the output for v0.1.0.
- `deploy/terraform/aws/`: a Terraform reference for AWS (ECS on Fargate,
  RDS for PostgreSQL 17, Secrets Manager, two ALBs), with variables for the
  image tags or digests and the detection layers and models. Reference, not
  yet verified against a real account. CI runs `terraform fmt -check`,
  `validate` and `test` (a plan against a mocked provider).
- Documentation site at <https://guardspec.io/docs/>, built from this
  repository's Markdown; linked from the README.
- Helm chart 0.2.0, every addition off by default (the default render is
  unchanged): `migrations.enabled` runs golang-migrate as a pre-install /
  pre-upgrade hook before `dbRoles` (the SQL comes from the gateway image);
  `models.pull` adds an init container that runs `./models pull` (Hugging
  Face or `MODELS_MIRROR`, SHA-256 checked against the manifest) into the
  models claim or a per-pod `emptyDir`; `ingress`, OpenShift `route`,
  `gateway/controlPlane.autoscaling` (HPA), `.podDisruptionBudget`,
  `.topologySpreadConstraints`, `networkPolicy` (ingress per port, optional
  egress restriction), `serviceAccount` (annotations for IRSA and GKE / AKS
  Workload Identity), `podLabels` and `podAnnotations`.
- Helm chart: reference values for EKS, AKS, GKE and OpenShift in
  `deploy/helm/guard-spec/examples/` (rendered and schema-checked in CI, not
  verified on those platforms).
- `doctor`: checks a deployment from inside it (database reachable,
  migration version against the image's `migrations/`, model files against
  the manifest's SHA-256, which detection layers would load, upstream
  reachable, secrets, dev mode and TLS settings). Exit 0 when nothing
  failed, 1 when a check failed (`-strict`: also on warnings), 2 on usage
  errors; `-json` for machines. Shipped at `/app/doctor` in the gateway,
  gateway-full and control-plane images and in the release archives.
- `docs/airgapped.md`: mirroring the images (with their cosign signatures
  and attestations) and the models to a private registry and storage,
  verifying signatures offline, pointing the chart at the mirror, and an
  External Secrets example.
- CI: a `kind-e2e` job (not a required check) installs the chart on kind with
  images built from the change, an in-cluster Postgres and a fake upstream,
  and checks that EN and VI prompt injections are blocked and a benign
  prompt passes (L1 only); `tests/kind/e2e.sh` runs it locally. The `helm`
  job lints and validates every new values file.
- Light mode: `DETECTOR_LAYERS=l1,l2` (L1 + L2, no L3 embedder) in
  `.env.example`; `scripts/quickstart.sh` writes it into a new `.env`, checks
  that `/readyz` reports the requested layers, and compose's `models-init`
  pulls only the models the layers need (the classifier for `l1,l2`, none
  for `l1`).
- `deploy/compose/production/`: a production compose for one host. Caddy with
  automatic HTTPS (or `CADDY_TLS=internal` for testing) is the only service
  with published ports; CPU and memory limits, json-file log rotation,
  health checks, `unless-stopped` restarts, internal network for Postgres,
  `DETECTOR_REQUIRE_ML=true`, secrets required from `.env`.
  `managed-postgres.yml` runs it against a managed database.
- `scripts/backup.sh` and `scripts/restore.sh`: `pg_dump` / `pg_restore` of a
  compose stack together with its `.env` (`MFA_ENC_KEY` and the other
  secrets) and Caddy's certificates; restore only into an empty database and
  creates the cluster-wide `guardspec_app` role first.
- Docs: [integrations](docs/integrations.md) (OpenAI SDK for Python and
  JavaScript, LangChain, LlamaIndex, Claude Code hooks, Cursor, with limits),
  [sizing](docs/sizing.md) (RAM and CPU measured for L1, L1 + L2 and
  L1 + L2 + L3), [upgrade and rollback](docs/upgrade.md), and
  [managed PostgreSQL](docs/managed-postgres.md) (RDS, Cloud SQL, Neon,
  Supabase; reference, not yet verified on those providers).
- Shadow mode: `SHADOW_L2_MODEL` (or `SHADOW_L2_MODEL_DIR`) runs a candidate
  L2 classifier on the same traffic as the active one, asynchronously and off
  the response path (`SHADOW_TIMEOUT`, `SHADOW_SAMPLE`,
  `SHADOW_MAX_INFLIGHT`). It records each compared request's scores and
  would-be decisions in the new `shadow_results` table (migration 017, row
  level secured, no content) and never changes a decision.
- `GET /v1/organizations/:orgId/shadow` (viewer): agreement rate,
  disagreements by direction, statuses and score distributions over 24h, 7d
  or 30d; `GET /v1/organizations/:orgId/shadow/disagreements` (admin): the
  disagreeing requests, paged. Capabilities `shadow.read` and
  `shadow.disagreements.read`.
- Hot reload of the models: SIGHUP, or `POST /admin/models/reload` with
  `GATEWAY_ADMIN_TOKEN` (`GET /admin/models` for the status). A reload
  verifies every file against the manifest's SHA-256, loads the model fully
  and swaps it atomically; requests in flight are not dropped and a failure
  keeps the running model. `MODELS_MANIFEST` names a manifest file to use
  instead of the built-in one.
- `GET /readyz`: `detector.models` reports the running classifier
  (`name@version`, verified or not), the manifest's recommended version, the
  installed versions, `update_available`, shadow mode and the last reload.
- `GET /v1/gateway/models` on the control plane (`GATEWAY_URL`) and an admin
  UI **Models** page: the running model, a notice when a new version is
  available, the shadow comparison and its disagreements, in English and
  Vietnamese.
- Helm chart: `gateway.shadow`, `gateway.modelsManifest` and
  `gateway.adminToken` (all off by default); the control plane's
  `GATEWAY_URL` points at the gateway Service (`controlPlane.gatewayURL`),
  and `networkPolicy` lets it reach port 8080. `doctor` uses
  `MODELS_MANIFEST` when `-manifest` is not given.

### Changed

- `docs/security/verifying-releases.md` shows the verification output for
  v0.1.1, and the Terraform reference deploys 0.1.1 by default.

## [0.1.1] - 2026-11-06

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
- Go benchmarks for the input sanitizer, the output guard (whole answers and
  streams), CEL policy evaluation and the gateway's HTTP path end to end
  against a fake upstream. `make bench` runs them with L1 only; `make
  bench-onnx` adds L1+L2+L3 and L1+L2 (skipped without models).

### Changed

- The gateway's `GET /health` and `GET /readyz` report the version the binary
  was built from instead of a fixed `0.1.0`.
- Default image tag (`GUARDSPEC_VERSION`, chart `appVersion`) is `0.1.1`.

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

### Security

- `github.com/go-jose/go-jose/v4` 4.1.4 → 4.1.9 (control plane, via the
  OIDC login): fixes a denial of service when parsing JWKs with RSA keys
  (GHSA-mgcc-cww5-fp2q, high) and panics in JSON parsing
  (GHSA-vvm8-gf78-28g4) and in CBC-HMAC processing (GHSA-4w3g-jfj2-cw2q).
- `golang.org/x/crypto` 0.58.0 → v0.58.1-0.20261009181718-2f1f834330b2,
  which removes the unmaintained `openpgp` packages (GO-2026-5932). Guard
  Spec never imported them; `govulncheck` and OpenSSF Scorecard reported
  the module.
- Training tooling (`train/`, not shipped): torch 2.13.0, transformers
  5.10.2, onnx 1.22.0, protobuf 5.29.6, sentencepiece 0.2.1 and pyarrow
  23.0.1 fix the open advisories against the pinned versions. The scripts
  load the tokenizer with `PreTrainedTokenizerFast` so that an export keeps
  the base model's `tokenizer.json` unchanged under transformers 5, and
  `export.py` keeps the TorchScript ONNX exporter (`dynamo=False`).
- Admin UI build tooling (not shipped): npm overrides move `minimatch` to
  11.0.5 (GHSA-g3hv-75wg-m249) and `glob` to 14.0.4 (GHSA-3g3m-2fjr-6pw4)
  under typescript-eslint and the license checker.

### Documentation

- README: the `kubectl create secret` example includes `MFA_ENC_KEY`.
- ADR 0002: input-side PII, toxicity and topic detection are decided against
  for now, with the reasons and what to use instead; README, ROADMAP and
  DESIGN point to it.
- README, "Benchmarks": measured numbers for the new Go benchmarks (Apple M3
  Max), with the command and date.
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

[Unreleased]: https://github.com/guard-spec/guard-spec/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/guard-spec/guard-spec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/guard-spec/guard-spec/releases/tag/v0.1.0
