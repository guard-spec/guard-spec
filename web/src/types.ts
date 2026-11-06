// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Wire types of the control plane API (/v1). See cmd/control-plane and the
// routing/text-rules contract (upstreams, schema, parse/format, simulate,
// config as code).

export type UUID = string;

export type Action = 'allow' | 'block' | 'log' | 'route';
export const ACTIONS: readonly Action[] = ['allow', 'block', 'log', 'route'];

export interface Org {
  id: UUID;
  name: string;
  slug: string;
  tier?: string;
  audit_store_content?: boolean;
  created_at?: string;
  default_upstream_id?: UUID | null;
}

/** An organization the user belongs to (GET /v1/organizations). */
export interface Membership {
  id: UUID;
  name: string;
  slug: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
}

export interface Project {
  id: UUID;
  name: string;
  slug: string;
  created_at?: string;
  default_upstream_id?: UUID | null;
}

export interface ApiKey {
  key_prefix: string;
  alias: string | null;
  project_id: UUID | null;
  rpm_limit: number | null;
  tpm_limit: number | null;
  created_at: string;
  expires_at: string | null;
  revoked: boolean;
}

export interface CreatedApiKey {
  key: string;
  key_prefix: string;
  alias: string;
  project_id: UUID | null;
  rpm_limit: number | null;
  tpm_limit: number | null;
}

export interface NewApiKey {
  alias: string;
  project_id?: UUID | null;
  expires_at?: string | null;
  rpm_limit?: number | null;
  tpm_limit?: number | null;
}

// ── Conditions: the react-querybuilder JSON tree ────────────────────────────

export interface ConditionLeaf {
  id?: string;
  field: string;
  operator: string;
  value: unknown;
  valueSource?: 'value';
}

export interface ConditionGroup {
  id?: string;
  combinator: 'and' | 'or';
  not?: boolean;
  rules: ConditionNode[];
}

export type ConditionNode = ConditionLeaf | ConditionGroup;

export function isGroup(n: ConditionNode): n is ConditionGroup {
  return 'combinator' in n && Array.isArray(n.rules);
}

export interface Rule {
  id?: UUID;
  name: string;
  condition: ConditionNode;
  action: Action;
  route_target?: string;
}

export interface Policy {
  id: UUID;
  project_id: UUID | null;
  name: string;
  description: string | null;
  version: number;
  enabled: boolean;
  rules: Rule[];
  created_at: string;
  updated_at: string;
}

export interface PolicyInput {
  name: string;
  description?: string;
  rules: Rule[];
  project_id?: UUID | null;
  enabled?: boolean;
}

// ── Guard settings ──────────────────────────────────────────────────────────

export type SpotlightMode = 'off' | 'delimit' | 'datamark';
export const SCAN_ROLES = ['user', 'tool', 'system', 'tool_calls', 'tool_descriptions'] as const;
export type ScanRole = (typeof SCAN_ROLES)[number];
// The gateway default (indirect.DefaultRoles).
export const DEFAULT_SCAN_ROLES: Record<ScanRole, boolean> = {
  user: true,
  tool: true,
  system: false,
  tool_calls: false,
  tool_descriptions: true,
};

export interface GuardSettings {
  scan_roles?: Partial<Record<ScanRole, boolean>>;
  spotlight?: SpotlightMode;
}

// ── Exemplars ───────────────────────────────────────────────────────────────

export interface Exemplar {
  id: UUID;
  label: 'block' | 'allow';
  text: string;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface ExemplarInput {
  label?: 'block' | 'allow';
  text?: string;
  source?: string;
}

// ── Audit log ───────────────────────────────────────────────────────────────

export interface AuditRow {
  id: UUID;
  model: string | null;
  action: string;
  rule_id: UUID | null;
  route_target?: string | null;
  injection_label: string | null;
  injection_score: number;
  toxicity_score?: number;
  anomaly_score: number;
  had_tag_chars: boolean;
  had_bidi: boolean;
  latency_ms: number | null;
  request_sha256?: string | null;
  request_bytes?: number | null;
  response_sha256?: string | null;
  response_bytes?: number | null;
  request_content?: string;
  response_content?: string;
  created_at: string;
}

/** A window of GET /organizations/:orgId/dashboard. */
export type DashboardWindow = '24h' | '7d' | '30d';

/** GET /organizations/:orgId/dashboard: aggregates of the request log over a window that ends now. */
export interface DashboardStats {
  window: DashboardWindow;
  from: string;
  to: string;
  /** The series buckets, in UTC. */
  bucket: 'hour' | 'day';
  project_id: UUID | null;
  total: number;
  blocked: number;
  block_rate: number;
  by_action: { action: string; count: number }[];
  /** Latency percentiles in ms; null when no request has a latency. */
  latency_ms: { p50: number | null; p95: number | null; p99: number | null };
  /** One entry per bucket, oldest first, empty buckets included. */
  series: { start: string; count: number; blocked: number }[];
  /** Detector labels other than benign, in lower case. */
  top_labels: { label: string; count: number }[];
  /** The names are null for a rule no longer in the org's policies. */
  top_rules: { rule_id: UUID; rule: string | null; policy: string | null; count: number }[];
  /** project_id and name are null for requests without a project. */
  top_projects: { project_id: UUID | null; name: string | null; count: number; blocked: number }[];
}

// ── Classifier models and shadow comparison ─────────────────────────────────

/** GET /gateway/models: the gateway's classifier models, read by the control plane (instance-wide). */
export interface GatewayModels {
  /** false: the control plane has no GATEWAY_URL. */
  configured: boolean;
  /** false (with configured): the gateway did not answer; see error. */
  reachable: boolean;
  error?: string;
  checked_at: string;
  /** The running L2 classifier, e.g. guardspec-classifier@v3b; null when none is loaded. */
  l2_model: string | null;
  /** Its SHA-256 matched the manifest at the last (re)load. */
  l2_verified: boolean;
  /** The manifest's recommended classifier. */
  recommended: string | null;
  /** Classifier versions in the gateway's model cache. */
  installed: string[];
  /** recommended differs from l2_model. */
  update_available: boolean;
  shadow: { enabled: boolean; model: string | null; error?: string };
  reload: { generation: number; at: string | null; error: string | null };
}

/** A window of the shadow comparison (as the dashboard). */
export type ShadowWindow = DashboardWindow;

/** Which way the shadow model disagrees with the active one. */
export type ShadowDirection = 'would_block' | 'would_allow';
export const SHADOW_DIRECTIONS: readonly ShadowDirection[] = ['would_block', 'would_allow'];

export interface ScoreStats {
  mean: number | null;
  p50: number | null;
  p95: number | null;
}

/** GET /organizations/:orgId/shadow: the active and the shadow classifier over a window. */
export interface ShadowSummary {
  window: ShadowWindow;
  from: string;
  to: string;
  /** The block threshold the decisions are compared at. */
  threshold: number;
  /** Shadow records in the window. */
  total: number;
  /** Records where both models produced a score. */
  compared: number;
  agree: number;
  /** agree / compared; null when nothing was compared. */
  agreement_rate: number | null;
  /** The active model allowed, the shadow would block. */
  shadow_would_block: number;
  /** The active model blocked, the shadow would allow. */
  shadow_would_allow: number;
  not_compared: { timeout: number; skipped: number; error: number };
  pairs: { active_model: string; shadow_model: string; count: number }[];
  scores: {
    active: ScoreStats;
    shadow: ScoreStats;
    /** shadow − active. */
    delta: { mean: number | null; mean_abs: number | null; p95_abs: number | null };
    histogram: { from: number; to: number; active: number; shadow: number }[];
  };
}

/** A row of GET /organizations/:orgId/shadow/disagreements. */
export interface ShadowDisagreement {
  request_id: string;
  created_at: string;
  project_id: UUID | null;
  /** What the gateway did. */
  action: string;
  /** The LLM model of the request. */
  model: string | null;
  active_model: string;
  shadow_model: string;
  active_score: number;
  shadow_score: number;
  active_decision: 'allow' | 'block';
  shadow_decision: 'allow' | 'block';
  direction: ShadowDirection;
}

// ── Upstreams (contract)────────────────────────────────────────────────────

export interface Upstream {
  id: UUID;
  name: string;
  base_url: string;
  model: string;
  api_key_env: string;
  timeout_ms: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
  // Provider fields (identity contract §6, migration 014); absent on older
  // control planes. model stays the alias of default_model for one release.
  provider?: ProviderKind;
  display_name?: string;
  models?: string[];
  default_model?: string;
  headers?: Record<string, string>;
  api_version?: string;
  max_tokens_cap?: number | null;
  retries?: number;
  tags?: string[];
}

export type UpstreamInput = Omit<Upstream, 'id' | 'created_at' | 'updated_at'>;

export const UPSTREAM_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const API_KEY_ENV_RE = /^UPSTREAM_KEY_[A-Z0-9_]{1,64}$/;

// ── Policy schema and text conversion (contract) ────────────────────────────

export type FieldType = 'double' | 'int' | 'string' | 'bool' | 'list';

export interface SchemaField {
  name: string;
  type: FieldType;
  description?: string;
  values?: string[];
}

export interface PolicySchema {
  fields: SchemaField[];
  operators: Partial<Record<FieldType, string[]>>;
  actions: Action[];
}

// ── Simulate (contract) ─────────────────────────────────────────────────────

export type SimValue = string | number | boolean | string[];

export interface SimulateRequest {
  policy_id?: UUID | null;
  rules?: Rule[];
  project_id?: UUID | null;
  vars: Record<string, SimValue>;
}

export interface TraceEntry {
  policy_id?: UUID | null;
  rule_id?: UUID | null;
  rule_name: string;
  matched: boolean;
  action: Action;
  error?: string;
}

export type UpstreamSource = 'rule' | 'project' | 'org' | 'env' | 'stub';

export interface SimulateResponse {
  trace: TraceEntry[];
  /** action is "error" when the gateway would fail closed (503); error says why. */
  decision: {
    action: Action | 'error';
    rule_id?: UUID | null;
    rule_name?: string;
    route_target?: string | null;
    logged?: UUID[];
    error?: string;
  };
  /** error is set when the chosen upstream is missing or disabled (502). */
  upstream?: { source: UpstreamSource; name?: string | null; base_url?: string | null; error?: string } | null;
}

// ── Config as code (contract) ───────────────────────────────────────────────

export interface ConfigChange {
  kind: 'upstream' | 'policy' | 'default';
  name: string;
  op: 'create' | 'update' | 'delete';
}

export interface ConfigApplyResult {
  applied: boolean;
  changes: ConfigChange[];
}

export interface ConfigError {
  path: string;
  message: string;
}

/** Why GET /config refused to export (409): a policy to fix through the policy API. */
export interface ExportProblem {
  policy_id: UUID;
  policy: string;
  message: string;
  fix: string;
}

// ── Pagination (identity contract §0) ───────────────────────────────────────

/** The paginated envelope; older endpoints answer {data: [...]} or a plain array. */
export interface PageEnvelope<T> {
  items: T[];
  next_cursor?: string | null;
  total?: number;
}

// ── Identity, 2FA and SSO (identity contract §1–§3) ─────────────────────────

export type Role = 'viewer' | 'member' | 'admin' | 'owner';
export const ROLES: readonly Role[] = ['viewer', 'member', 'admin', 'owner'];

export interface Me {
  id: UUID;
  email: string;
  display_name: string | null;
  mfa_enabled: boolean;
  has_password: boolean;
  /** provider is the type (google, oidc); provider_id names the identity provider. */
  identities: { provider_id?: string; provider: string; display_name?: string; email: string | null }[];
  is_instance_admin: boolean;
}

/** POST /auth/login and POST /auth/oidc/exchange answer one of these. */
export type LoginResponse =
  | { token: string; user?: Partial<Me> }
  | { mfa_required: true; mfa_token: string; methods?: ('totp' | 'recovery')[] }
  | { mfa_enroll_required: true; mfa_token: string };

export interface TotpSetup {
  secret: string;
  otpauth_url: string;
}

export interface SessionInfo {
  id: string;
  created_at: string;
  last_seen_at: string | null;
  user_agent: string | null;
  ip: string | null;
  current: boolean;
}

/** GET /auth/providers: the buttons of the login page. */
export interface LoginProvider {
  id: string;
  type: 'oidc' | 'google';
  display_name: string;
}

export interface IdentityProvider {
  id: string;
  type: 'google' | 'oidc';
  display_name: string;
  issuer: string;
  client_id: string;
  /** The name of the env var holding the secret; the secret itself never reaches the UI. */
  client_secret_env: string;
  scopes: string[];
  allowed_domains: string[];
  auto_provision: boolean;
  /** Lets this provider sign in to an existing password-less account with the same verified email (off by default). */
  trust_email_for_linking?: boolean;
  enabled: boolean;
}

export type IdentityProviderInput = Omit<IdentityProvider, 'id'>;
export const CLIENT_SECRET_ENV_RE = /^OIDC_SECRET_[A-Z0-9_]{1,64}$/;
export const GOOGLE_ISSUER = 'https://accounts.google.com';

export interface DomainJoinRule {
  domain: string;
  provider_id: string;
  role: Role;
}

export interface OrgSecurity {
  require_mfa: boolean;
  sso_satisfies_mfa: boolean;
  /** null: unrestricted (every method of the instance). */
  allowed_login_methods: string[] | null;
  domain_join: DomainJoinRule[];
  session_lifetime_hours: number;
}

// ── User management (identity contract §4) ──────────────────────────────────

export interface Member {
  user_id: UUID;
  email: string;
  display_name: string | null;
  role: Role;
  mfa_enabled: boolean;
  login_methods: string[];
  last_login_at: string | null;
  joined_at: string | null;
  disabled: boolean;
}

export interface Invite {
  id: UUID;
  email: string;
  role: Role;
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
  expires_at: string;
  created_at: string;
}

export interface CreatedInvite {
  id: UUID;
  email: string;
  role: Role;
  expires_at: string;
  created_at: string;
  /** Shown once. */
  token: string;
}

export interface InstanceUser {
  id: UUID;
  email: string;
  display_name: string | null;
  is_instance_admin: boolean;
  disabled: boolean;
  mfa_enabled?: boolean;
  last_login_at?: string | null;
  created_at?: string;
}

export interface Capability {
  key: string;
  min_role: Role;
  description?: string;
}

export interface PermissionMatrix {
  roles: Role[];
  capabilities: Capability[];
}

// ── Activity log (identity contract §5) ─────────────────────────────────────

export interface ActivityEntry {
  id: string;
  at: string;
  actor: { id: string | null; email: string | null } | null;
  action: string;
  target: string | null;
  /** The user a user-id target names (its email), from the control plane. */
  target_label?: string | null;
  ip: string | null;
  details?: Record<string, unknown> | null;
}

// ── Model providers (identity contract §6) ──────────────────────────────────

export type ProviderKind = 'openai' | 'anthropic' | 'azure_openai' | 'gemini' | 'ollama' | 'vllm' | 'openai_compatible';
export const PROVIDER_KINDS: readonly ProviderKind[] = ['openai', 'anthropic', 'azure_openai', 'gemini', 'ollama', 'vllm', 'openai_compatible'];

/** GET /providers/catalog: one preset (field names of the control plane). */
export interface CatalogEntry {
  id: ProviderKind;
  display_name: string;
  default_base_url: string;
  key_required: boolean;
  key_env_hint?: string;
  known_models: string[];
  docs_url?: string;
  notes?: string;
  needs_api_version?: boolean;
  /** The preset uses the provider's OpenAI-compatible API (Anthropic, Gemini). */
  openai_compatible_endpoint?: boolean;
}

/** POST .../upstreams/:id/test */
export interface ConnectionTest {
  ok: boolean;
  latency_ms: number | null;
  status: number | null;
  models_found: string[] | null;
  error: string | null;
  /** false: the key was not sent (UPSTREAM_KEY_ORGS allows it only through *). */
  key_sent?: boolean;
  note?: string;
}

/** POST /invites/accept: a login answer plus the membership. */
export type InviteAcceptResponse = LoginResponse & { user_id?: UUID; org_id?: UUID; role?: Role };

/** POST /auth/identities/link/complete */
export interface LinkResult {
  provider_id: string;
  display_name?: string;
  email?: string | null;
}
