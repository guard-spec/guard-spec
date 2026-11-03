# PromptShield — Open-Source LLM Guardrail Backend Service
## Research-Backed Architecture Design
**Date:** 2026-09-22  
**Status:** Draft v1.0 — for review before implementation

---

## Executive Summary

**Market gap:** LLM Guard (Protect AI) archived 2026-07-09. Rebuff archived 2025-05-16. No OSS product exists that is simultaneously (a) a standalone containerized backend service, (b) compatible with docker-compose AND K8s, and (c) has a professional admin UI with routing + rules config + analytics + RBAC + multi-tenancy.

**Critical research finding:** Emoji smuggling (variation selectors) achieves **100% ASR** against all 6 production guardrail products tested (Azure Prompt Shield, ProtectAI v1/v2, Meta Prompt Guard, NeMo, Vijil). However, this entire attack class is defeated by a single Unicode normalization step *before* classification. The existing tools fail because they classify first, normalize never.

**Correct positioning:** Defense-in-depth + blast radius reduction, not "100% detection." Honest benchmarking is a competitive advantage.

---

## 1. Threat Model

### 1.1 Prompt Injection Attack Vectors

| Category | Vector | Severity |
|---|---|---|
| Direct injection | Chat message | Medium |
| Indirect via document | PDF/DOCX/HTML (white text, hidden markup) | High |
| Indirect via RAG chunk | Attacker-controlled document in vector DB | Critical |
| Indirect via tool output | Web page, email, calendar invite | Critical |
| MCP tool poisoning | Tool description/metadata contains instructions | Critical |

### 1.2 Evasion Techniques (measured ASR)

| Technique | Best ASR | Notes |
|---|---|---|
| Emoji smuggling (variation selectors) | **100%** | Defeats all 6 tested production guardrails |
| Unicode tag block (U+E0000-E007F) | **90.15% / 81.79%** | Invisible characters |
| Bidi overrides / upside-down text | **78.7% / 99-100%** | Confuses tokenizers |
| Numbers/leet mapping | **81.2% / 94.6%** | Character substitution |
| FlipAttack (horizontal flip) | **~98%** | Defeats 5 guardrail models |
| Many-shot jailbreaking | ~70% at 256 shots | Long-context alignment |
| MCP tool poisoning | PoC demonstrated | CVE-2025-54136 |
| EchoLeak-style IPI | CVSS 9.3 (Teams) | Zero-click via image proxy |

**Key insight:** All Unicode encoding attacks are defeated by NFKC normalization + stripping `Default_Ignorable_Code_Point` before classification. The correct pipeline order is: sanitize first, classify second.

### 1.3 Output-Side Exfiltration Channels

| Channel | Mitigation |
|---|---|
| Markdown image auto-render beacons | Disable or strict CSP |
| Clickable links with data in query string | Strip/block untrusted links |
| Agent tool call to attacker URL | Per-tool egress policy + network isolation |
| DNS exfiltration (CVE-2025-55284) | Remove from auto-approve, network policy |
| Vendor-proxied images (Camo, Teams proxy) | Domain allowlist is insufficient — need URL inspection |
| Authenticated write via allowlisted host | Domain-level policy not enough, need tenant-aware |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE (Go)                           │
│  Admin UI (Next.js) <-> Management API <-> Postgres (multi-tenant)   │
│  [RBAC | Rules Config | Analytics | Monitoring | Key Management]      │
└─────────────────────────────┬───────────────────────────────────────┘
                               │ REST (config + policy sync)
┌─────────────────────────────▼───────────────────────────────────────┐
│                         DATA PLANE (Go)                              │
│                                                                      │
│  Client Request                                                      │
│       |                                                              │
│       v                                                              │
│  [Sanitizer Pipeline]  ->  [ML Inference x4 concurrent]  ->  [CEL]  │
│       |                          |                                   │
│  1. UTF-8 validate          Injection classifier (ONNX)             │
│  2. NFKC normalize          PII NER (ONNX)                          │
│  3. Strip ignorable chars   Toxicity (ONNX)                         │
│  4. Strip ANSI              Topic (ONNX)                            │
│  5. Sanitize HTML                                                    │
│  6. Detect homoglyphs            |                                   │
│  7. Apply spotlighting      [CEL Policy Engine]                     │
│       |                          |                                   │
│       v                     allow/block/redact/route/log            │
│  [Output Guard]                  |                                   │
│  - Strip untrusted links         v                                   │
│  - PII redaction            Upstream LLM API                        │
│  - Egress URL check                                                  │
└─────────────────────────────────────────────────────────────────────┘
                               |
┌─────────────────────────────▼───────────────────────────────────────┐
│                    OBSERVABILITY                                      │
│  OpenTelemetry gen_ai.* | Audit Log (ClickHouse) | Metrics | Alerts  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Design

### 3.1 Data Plane — Go Service

**Language:** Go 1.22+  
**HTTP Framework:** Fiber v3 (OpenAI-compatible routing)  

**Why Go for data plane:** Zero-overhead goroutine fan-out for concurrent ML inference; single process loading 4 ONNX models uses ~256MB RAM (INT8) vs Python 4 workers = ~4GB; cgo overhead with ORT is ~40ns — negligible.

**OpenAI-compatible proxy surface:**
```
POST /v1/chat/completions    <- intercept (input guard + output guard)
POST /v1/completions         <- intercept
POST /v1/embeddings          <- pass-through with injection scan
POST /guardrail/scan         <- direct scan endpoint (no LLM call); optional documents[]
POST /guardrail/scan/tools   <- MCP tool definitions: poisoning scan
POST /guardrail/sanitize     <- sanitize only, return cleaned text
GET  /guardrail/models       <- list loaded models and health
```

**Streaming:** Buffer chunks, scan incrementally. First token unblocked after input guard passes. Output scanning uses 512-token sliding window.

### 3.2 ML Inference — ONNX Runtime in-process (Go)

**Library:** `knights-analytics/hugot` with `-tags ORT` (Apache-2.0, amd64-linux)

**Model selection — Apache-2.0 ONLY:**

| Role | Model | License | Latency (2-core CPU) |
|---|---|---|---|
| Injection detector | protectai/deberta-v3-xsmall-prompt-injection | Apache-2.0 | ~30ms |
| Broad safety classifier | ibm-granite/granite-guardian-3.3-8b | Apache-2.0 | GPU required |
| Fast safety (default) | Qwen/Qwen3Guard-Gen-0.6B | Apache-2.0 | ~50ms |
| PII NER | GLiNER-small or custom DistilBERT | Apache-2.0 | ~15ms |
| Toxicity | unitary/toxic-bert (DistilBERT class) | Apache-2.0 | ~10ms |

**BLOCKED models — NOT usable in Apache-2.0 project:**
- Llama Guard 3/4: Llama Community License (non-OSI, "Built with Llama" display required, 700M MAU clause)
- Llama Prompt Guard 2 22M/86M: Llama 4 Community License
- ShieldGemma 1/2: Gemma Terms of Use (must propagate restrictions downstream)
- NVIDIA NeMoGuard: NVIDIA Open Model License + Llama dual-encumbered

**Thread configuration:**
```go
// 4 models x 2 IntraOp threads = 8 cores, run concurrently
opts := []ort.SessionOption{
    ort.WithIntraOpNumThreads(2),
    ort.WithInterOpNumThreads(1),
    ort.WithSequentialExecution(),
    ort.WithCpuMemArena(false),
    ort.WithMemPattern(false),
}
```

**Chunking strategy — CRITICAL security requirement:**
```go
// DO NOT truncate naively: attacker prepends 512 benign tokens to hide injection
// CORRECT: sliding window with overlap, aggregate max() over windows
func chunkForGuard(tokens []int, windowSize, stride int) [][]int {
    // windowSize=512, stride=448 (64-token overlap)
    // aggregate: max() over window scores, not mean()
    // cap windows at 16 to prevent CPU exhaustion DoS
}
```

**Latency budget (CPU, 8 cores, VNNI):**
```
Go HTTP parse:          0.3ms
Tokenize (cgo/Rust):    0.01ms
4 models concurrent:    ~15ms  (slowest model, not sum)
Post-process:           0.5ms
GC jitter headroom:     4ms
Total p99:              ~22-26ms  [target: < 30ms]
```

### 3.3 Sanitizer Pipeline (Ordered — do not reorder)

```go
func Sanitize(input string) (cleaned string, report SanitizeReport) {
    // 1. UTF-8 validate, reject lone surrogates
    if !utf8.ValidString(input) { return "", ErrInvalidUTF8 }
    
    // 2. NFKC normalize
    normalized := norm.NFKC.String(input)
    
    // 3. Strip Default_Ignorable_Code_Point
    //    (covers Tags block, zero-width chars, variation selectors, WJ, SHY)
    //    Use golang.org/x/text/runes + unicode package
    stripped := stripDefaultIgnorable(normalized)
    
    // 4. Explicit range strip (defense-in-depth, catches NFKC edge cases)
    //    U+E0000-E007F  Tags block
    //    U+FE00-FE0F    Variation selectors
    //    U+E0100-E01EF  Variation selectors supplement
    //    U+200B-200D    Zero-width space/non-joiner/joiner
    //    U+2060, U+FEFF Word joiner, BOM/ZWNBSP
    //    U+00AD         Soft hyphen
    //    U+202A-202E    Bidi embedding/override
    //    U+2066-2069    Bidi isolate
    //    C0/C1 controls 0x00-0x1F, 0x7F-0x9F
    //    EXCEPTION: preserve U+1F3F4 + tag letters + U+E007F (regional flag sequences)
    stripped = stripDangerousRanges(stripped)
    
    // 5. Strip ANSI escape sequences
    //    Use ansi-regex pattern (handles OSC terminated by ST/BEL/C1)
    //    Unconditionally kill OSC 52 (clipboard write command)
    stripped = stripANSI(stripped)
    
    // 6. HTML sanitize with strict allowlist (bluemonday)
    stripped = bluemonday.StrictPolicy().Sanitize(stripped)
    
    // 7. Homoglyph detection (UTS #39 skeleton algorithm)
    //    Raise signal but do NOT rewrite (rewrites cause legitimate content loss)
    report.HomoglyphRisk = checkHomoglyphs(stripped)
    report.HadTagChars = (input != stripped)
    
    // 8. Spotlighting is not applied here. The gateway marks tool results
    //    after cleaning (SPOTLIGHT=delimit|datamark, package indirect); the
    //    cleaning passes strip spoofed markers so an attacker cannot fake one.
    
    return stripped, report
}
```

**MCP tool description scanning:**
```go
var mcpPoisonSignals = []string{
    "<IMPORTANT>", "<SYSTEM>", "<INSTRUCTIONS>",
    "do not mention this to the user",
    "~/.ssh", "id_rsa", ".env", "/etc/shadow", "mcp.json",
    "send all emails to", "BCC:",
    "VERY VERY important",
    "the tool will not work otherwise",
    "Before using this tool",
}
// Plus structural signals:
// - description > 1500 chars
// - zero-width chars in metadata
// - ANSI bytes in tool definition
// - anomalous parameter injection patterns
```

### 3.4 Policy Engine — CEL (cel-go)

**Decision: CEL over OPA or Cedar**
- CEL: ~130ns/3 allocs per eval
- OPA (Rego): ~40,000ns/382 allocs — 300x slower
- Cedar: fastest benchmarks but authorization-shaped, not predicate-shaped; experimental Go templates

```go
type Policy struct {
    ID        uuid.UUID `json:"id"`
    OrgID     uuid.UUID `json:"org_id"`
    ProjectID uuid.UUID `json:"project_id"`
    Version   int       `json:"version"`
    Rules     []Rule    `json:"rules"`   // ordered, first-match wins
}

type Rule struct {
    Condition    json.RawMessage `json:"condition"`   // react-querybuilder JSON AST
    Action       Action          `json:"action"`      // allow|block|redact|route|log
    RuleTemplate string          `json:"template"`    // template ID if instantiated
}

func compileToCEL(rule Rule, env *cel.Env) (cel.Program, error) {
    celExpr := jsonASTToCEL(rule.Condition)  // server-side only, never client
    ast, issues := env.Compile(celExpr)
    if issues.Err() != nil { return nil, issues.Err() }
    
    // Cost budget: tenant cannot stall data plane with expensive expressions
    prg, err := env.Program(ast,
        cel.EvalOptions(cel.OptOptimize),
        cel.CostLimit(10_000),                  // ~0.013ms max per expression
        cel.InterruptCheckFrequency(100),
    )
    return prg, err
}
```

**CEL activation variables (lazy-evaluated):**
```
request.model          string
request.tenant_id      string
request.tokens         int
injection.score        float   (lazy: fused, calibrated score of all layers)
injection.category     string  (top category: direct_injection, jailbreak, ... or "")
scores.l1              float   (L1 rules, calibrated)
scores.l2              float   (L2 classifier; -1 until it exists or when it fails)
scores.l3              float   (L3 embeddings; -1 until it exists or when it fails)
injection.source_role  string  (where the strongest finding came from: user, system, assistant, tool, tool_description)
indirect.score         float   (largest score over tool results and tool descriptions; 0 when none)
indirect.source        string  (tool, document or tool_description; "" when none)
pii.entities           list    (lazy)
toxicity.score         float   (lazy)
topic.categories       list    (lazy)
anomaly.has_tag_chars  bool    (cheap, from sanitizer)
anomaly.has_bidi       bool    (cheap)
mcp.is_tool_response   bool
```

**Rule templates (non-engineers fill slots, server validates):**
```yaml
templates:
  - id: "block-high-injection"
    name: "Block High Injection Risk"
    condition: "injection.score >= {threshold}"
    params:
      threshold: {type: float, default: 0.85, min: 0.5, max: 0.99}
  
  - id: "pii-in-model"
    name: "Block PII Sent to Specific Model"
    condition: "request.model == '{model}' && pii.entities.exists(e, e == '{pii_type}')"
    params:
      model: {type: string}
      pii_type: {type: enum, values: [SSN, CREDIT_CARD, EMAIL, PHONE]}
```

### 3.5 Multi-Tenancy and RBAC

**Schema: shared schema + org_id leading-column index + RLS as backstop**

```sql
-- Every tenant-owned table has org_id as leading index column
CREATE TABLE requests (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL,           -- leading column of all indexes
    project_id UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
    -- ... data columns
);

CREATE INDEX idx_requests_tenant ON requests (org_id, created_at DESC);

-- RLS: direct equality comparison (NOT a subquery — subquery disables index)
ALTER TABLE requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON requests
    USING (org_id = current_setting('app.org_id')::uuid);

-- CRITICAL for PgBouncer transaction mode:
-- Set GUC as first statement in every transaction
-- "SELECT set_config('app.org_id', $1, true)" where true = transaction-local
```

**RBAC tables:**
```sql
CREATE TYPE org_role     AS ENUM ('owner', 'admin', 'member', 'viewer');
CREATE TYPE project_role AS ENUM ('admin', 'member', 'viewer');

CREATE TABLE org_memberships (
    user_id UUID REFERENCES users(id),
    org_id  UUID REFERENCES organizations(id),
    role    org_role NOT NULL,
    PRIMARY KEY (user_id, org_id)
);

CREATE TABLE project_memberships (
    user_id    UUID REFERENCES users(id),
    project_id UUID REFERENCES projects(id),
    role       project_role NOT NULL,
    PRIMARY KEY (user_id, project_id)
);
```

**API Keys (with rotation support from day 1):**
```sql
CREATE TABLE api_keys (
    key_hash          TEXT PRIMARY KEY,    -- SHA-256 of plaintext key
    key_alias         TEXT,
    org_id            UUID NOT NULL,
    project_id        UUID,
    budget_id         UUID REFERENCES budgets(id),
    tpm_limit         BIGINT,
    rpm_limit         INT,
    auto_rotate       BOOL DEFAULT FALSE,
    rotation_interval INTERVAL,
    last_rotation_at  TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);
```

**Open-core line (Langfuse model — minimizes resentment):**
- FREE: org RBAC, unlimited users, unlimited API keys, rate limits, generic OIDC, **audit logs**
- PAID EE: project-level fine-grained roles, SSO enforcement, SAML 2.0, SCIM, dedicated-DB tenancy, org management API

### 3.6 Admin UI

**Stack:** Next.js 15 (App Router) + TypeScript + shadcn/ui + TanStack Query v5 + TanStack Table v8

**Screens:**
1. **Dashboard** — real-time injection rate, top attack patterns, model usage
2. **Rules Config** — react-querybuilder with CEL backend, template gallery, live test playground  
3. **Routing** — drag-drop model routing rules, fallback chains, cost caps
4. **Attack Analysis** — per-request timeline, sanitizer report, model scores, CEL trace
5. **Monitoring** — alert rules, anomaly detection, time-series charts
6. **RBAC** — org/project members, role assignment, API key management
7. **Audit Log** — immutable tamper-evident log (EU AI Act Article 12)

```tsx
// Rules builder: JSON AST sent to server for CEL compilation, never compile client-side
<QueryBuilder
  fields={guardrailFields}  // injection.score, pii.entities, etc.
  onQueryChange={(q) => {
    api.validateRule({ condition: q }).then(result => {
      if (result.celExpression) showPreview(result.celExpression)
    })
  }}
/>
```

### 3.7 Observability

**Tracing:** OpenTelemetry with `gen_ai.*` semantic conventions
```go
span.SetAttributes(
    semconv.GenAIOperationNameKey.String("chat"),
    semconv.GenAISystemKey.String("openai"),
    semconv.GenAIRequestModelKey.String(req.Model),
    attribute.Float64("guardrail.injection_score", score),
    attribute.Bool("guardrail.blocked", blocked),
    attribute.String("guardrail.action", action),
    attribute.StringSlice("guardrail.pii_entities", entities),
    attribute.Bool("guardrail.sanitizer.had_tag_chars", hadTagChars),
)
```

**Storage:** ClickHouse for high-volume audit/analytics (append-only, columnar = fast aggregations). Postgres for transactional data (policies, keys, memberships).

**EU AI Act Article 12 compliance:**
- Log all decisions with model version, timestamp, scores
- Append-only ClickHouse + periodic SHA-256 hash chaining (tamper-evident)
- 6-month minimum retention enforcement
- Audit trail answers: "which model version at which timestamp classified this as injection"

---

## 4. Docker Compose and Kubernetes

### 4.1 docker-compose.yml

```yaml
services:
  gateway:
    image: promptshield/gateway:latest
    ports: ["8080:8080", "9090:9090"]   # proxy + metrics
    environment:
      DATABASE_URL: postgres://ps:ps@postgres:5432/promptshield
      CLICKHOUSE_URL: clickhouse://clickhouse:9000
      MODELS_PATH: /models
    volumes: ["models:/models"]
    depends_on: [postgres, clickhouse, model-init]

  control-plane:
    image: promptshield/control-plane:latest
    ports: ["8081:8081"]
    environment:
      DATABASE_URL: postgres://ps:ps@postgres:5432/promptshield

  ui:
    image: promptshield/ui:latest
    ports: ["3000:3000"]
    environment:
      NEXT_PUBLIC_API_URL: http://control-plane:8081

  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: promptshield
      POSTGRES_USER: ps
      POSTGRES_PASSWORD: ps
    volumes: ["pgdata:/var/lib/postgresql/data"]

  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    volumes: ["chdata:/var/lib/clickhouse"]

  model-init:
    image: promptshield/model-init:latest
    command: ["download", "--models", "qwen3guard-0.6b,deberta-v3-xsmall-pi"]
    volumes: ["models:/models"]
    restart: "no"

volumes:
  models:   # model weights — not baked into images
  pgdata:
  chdata:
```

### 4.2 Kubernetes / Helm

```yaml
# HPA: CPU-bound workload (ML inference)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: promptshield-gateway
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: promptshield-gateway
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**Model distribution:**
- Init container downloads from HuggingFace Hub at pod start (image stays 200MB, not 2-8GB)
- PVC shared between pods on same node (ReadWriteMany with NFS/EFS)
- Pre-built ONNX exports vendored in private registry for air-gapped deployments
- DO NOT bake model weights into Docker images

---

## 5. Project Structure

```
pi_sanitation/
├── cmd/
│   ├── gateway/          # Go data plane binary
│   ├── control-plane/    # Go management API binary
│   └── model-init/       # Python model downloader + ONNX exporter
├── internal/
│   ├── sanitizer/        # Unicode sanitization pipeline
│   ├── inference/        # ONNX Runtime wrapper (hugot)
│   ├── policy/           # CEL policy engine
│   ├── proxy/            # OpenAI-compatible HTTP proxy
│   ├── routing/          # Route rules engine
│   ├── tenant/           # Multi-tenancy middleware
│   ├── audit/            # ClickHouse audit log writer
│   └── auth/             # API key validation, OIDC
├── api/
│   ├── proto/            # gRPC definitions (gateway <-> control plane)
│   └── openapi/          # REST API schema
├── web/                  # Next.js admin UI
│   ├── app/
│   ├── components/
│   └── lib/
├── models/               # ONNX model files (gitignored, downloaded by init)
├── migrations/           # Postgres migrations (golang-migrate)
├── charts/               # Helm chart
├── docker-compose.yml
├── docker-compose.override.yml   # dev overrides
└── Makefile
```

---

## 6. Roadmap

### Phase 1 — MVP (8 weeks)
- Go gateway with OpenAI-compatible proxy
- Unicode sanitizer pipeline (full spec above)
- ONNX in-process inference (Qwen3Guard-0.6B + DeBERTa-xsmall)
- CEL policy engine with JSON rule builder
- Postgres multi-tenancy + basic RBAC
- docker-compose packaging
- Basic Next.js UI: dashboard + rules config

### Phase 2 — Production Ready (8 weeks)
- Streaming interception + output guard
- MCP tool poisoning detection
- PII NER + redaction
- ClickHouse observability + EU AI Act audit log
- Generic OIDC SSO
- Helm chart + K8s support
- Full admin UI: routing, attack analysis, monitoring, RBAC management

### Phase 3 — Enterprise (8 weeks)
- Granite Guardian 8B integration (GPU path via Triton gRPC)
- SAML 2.0 + SCIM
- Project-level fine-grained RBAC (EE tier)
- Canary token support (Rebuff-style)
- CaMeL-inspired dual-pipeline option
- Benchmark integration (AgentDojo, InjecAgent, BIPIA)
- Dedicated-DB tenancy option (EE)

---

## 7. Key Risks

| Risk | Severity | Mitigation |
|---|---|---|
| hugot is amd64-linux only | High | Provide Triton gRPC fallback for Windows/ARM development |
| DeBERTa-v3-base too slow on CPU (1714ms) | High | Use -xsmall (22M params) or DistilBERT class only |
| Naive truncation = security hole | Critical | Sliding window + max() aggregation |
| PgBouncer transaction mode tenant leak | Critical | set_config(transaction-local=true) + integration test |
| Tokenizer mismatch (ONNX export) | High | Golden-file test suite, pin tokenizer.json hash |
| ONNX attention_mask dropped in export | High | Validate: same text with/without padding must match |
| CEL expression DoS by tenant | Medium | Compile-time cost estimate + runtime CostLimit(10000) |
| Model license drift | High | Pin versions, monitor SPDX identifiers in CI |
| False positive rate 3-5% | Medium | Tunable thresholds, dry-run mode, anomaly logging |

---

## 8. Competitive Positioning

| Product | Status | Gap vs PromptShield |
|---|---|---|
| LLM Guard (Protect AI) | Archived 2026-07-09 | No maintenance |
| Rebuff | Archived 2025-05-16 | No maintenance |
| NeMo Guardrails | Active | Requires Colang DSL, not containerized, no multi-tenancy |
| Guardrails AI | Active | Python library only, no backend service, no UI |
| Azure Prompt Shield | Active (commercial) | Vendor lock-in, not self-hosted |
| Lakera Guard | Active (commercial) | SaaS, not OSS |

**EU AI Act compliance is a free differentiator.** Article 12 (tamper-evident logging) effective August 2, 2026. Ship audit logs free in OSS tier — buys significant goodwill and enterprise evaluation entry point.

---

## 9. License Compliance Checklist

**Project license: Apache-2.0**

| Dependency | License | Status |
|---|---|---|
| Go stdlib | BSD-style | OK |
| knights-analytics/hugot | Apache-2.0 | OK |
| golang.org/x/text | BSD-3-Clause | OK |
| microcosm-cc/bluemonday | BSD-3-Clause | OK |
| google/cel-go | Apache-2.0 | OK |
| IBM Granite Guardian weights | Apache-2.0 | OK |
| Qwen3Guard weights | Apache-2.0 | OK |
| nh3 (Python HTML sanitizer) | MIT | OK |
| Microsoft Presidio (PII) | MIT | OK |
| unidecode (Python) | GPL-2.0 | DO NOT USE |
| Llama Guard 3/4 | Llama Community | BLOCKED |
| ShieldGemma | Gemma Terms | BLOCKED |

---

## References

- Hackett et al., arXiv:2504.11168 — Emoji/char injection: 100% ASR vs all 6 guardrails
- Hines et al., arXiv:2403.14720 — Spotlighting: ASR reduced >50% to <2%
- Debenedetti et al., arXiv:2503.18813 — CaMeL: 77% provable security on AgentDojo
- OWASP LLM Top 10 2025 — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- EU AI Act Article 12 — https://artificialintelligenceact.eu/article/12/
- Qwen3Guard paper — arXiv:2510.14276
- InjecGuard — arXiv:2410.22770
- AgentDojo benchmark — arXiv:2406.13352
- hugot Go library — https://github.com/knights-analytics/hugot
- cel-go — https://github.com/google/cel-go
- CVE-2025-32711 (EchoLeak, CVSS 9.3) — zero-click IPI in Teams
- CVE-2025-55284 — DNS exfiltration in Claude Code
