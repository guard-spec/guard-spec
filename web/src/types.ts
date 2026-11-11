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
  /** Networks the key may be used from (migration 028); empty: any address. */
  allowed_cidrs?: string[];
  /** The successor's prefix after a rotation, and when. */
  rotated_to?: string | null;
  rotated_at?: string | null;
}

export interface CreatedApiKey {
  key: string;
  key_prefix: string;
  alias: string | null;
  project_id: UUID | null;
  rpm_limit: number | null;
  tpm_limit: number | null;
  expires_at?: string | null;
  allowed_cidrs?: string[];
}

/** POST .../api-keys/:prefix/rotate: the successor, shown once. */
export interface RotatedApiKey extends CreatedApiKey {
  rotated_from: string;
  /** When the old key stops working (the end of the overlap). */
  old_expires_at: string;
}

export interface NewApiKey {
  alias: string;
  project_id?: UUID | null;
  expires_at?: string | null;
  rpm_limit?: number | null;
  tpm_limit?: number | null;
  allowed_cidrs?: string[];
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
  /** Decisions are recorded in the request log (policy:would_<action> tags), not applied (migration 026). */
  log_only?: boolean;
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
  log_only?: boolean;
  /** Kept with the version the save creates (at most 500 characters). */
  reason?: string;
}

// ── Policy history (migration 026) ──────────────────────────────────────────

export type PolicyVersionKind = 'create' | 'update' | 'rollback' | 'config';

export interface PolicyVersion {
  version: number;
  kind: PolicyVersionKind;
  name: string;
  description: string | null;
  project_id: UUID | null;
  enabled: boolean;
  log_only: boolean;
  rules: Rule[];
  author: { id: UUID | null; email: string | null } | null;
  reason: string | null;
  /** A rollback: the version it restored. */
  rolled_back_to: number | null;
  created_at: string;
}

/** GET /organizations/:orgId/policies/:id/versions: newest first. */
export interface PolicyVersions {
  items: PolicyVersion[];
  current: number;
}

export interface PolicyFieldChange {
  field: 'name' | 'description' | 'project_id' | 'enabled' | 'log_only';
  from: unknown;
  to: unknown;
}

export interface PolicyRuleChange {
  op: 'added' | 'removed' | 'changed' | 'moved';
  rule_id: UUID;
  name: string;
  from?: Rule;
  to?: Rule;
  /** 0-based positions; -1 when the rule is not in that version. */
  from_index: number;
  to_index: number;
}

/** GET .../versions/diff?from=&to= */
export interface PolicyDiff {
  from: number;
  to: number;
  fields: PolicyFieldChange[];
  rules: PolicyRuleChange[];
}

/** POST .../policies/:id/rollback */
export interface RollbackResult {
  id: UUID;
  version: number;
  rolled_back_to: number;
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
  indirect_action?: IndirectAction;
  /** Blocks at this fused injection score; only lower (stricter) than the gateway's 0.85 counts. */
  injection_threshold?: number;
  /** Blocks or redacts untrusted content at this score; the smaller of this and INDIRECT_BLOCK_THRESHOLD wins. */
  indirect_threshold?: number;
  /** Turns the conversation window on or off; unset: the gateway's CONVERSATION_WINDOW_TURNS. */
  conversation_window?: boolean;
  /** How many recent user turns the window joins (WINDOW_TURNS bounds). */
  conversation_window_turns?: number;
  /** The most bytes of the joined text (WINDOW_BYTES bounds). */
  conversation_window_bytes?: number;
  /** Counts personal data in request text for input.pii.* rules; unset or false: off (the default). */
  input_pii?: boolean;
  /** Keeps personal data from the upstream: off (unset), redact (a label) or tokenize (a token the answer gets the value back for). */
  input_pii_action?: 'off' | 'redact' | 'tokenize';
  /** Kinds the action replaces; unset or empty: every kind. */
  input_pii_kinds?: PiiKind[];
  /** Images, files and audio the gateway cannot read: allow, log or block. Only a stricter mode than the gateway's UNSCANNED_PARTS takes effect. */
  unscanned_parts?: UnscannedMode;
  /** The most tokens the gateway scans for one request; only a value below the gateway's MAX_SCAN_TOKENS counts. */
  max_scan_tokens?: number;
}

/** Bounds of max_scan_tokens (indirect.MaxScanTokensLimit). */
export const SCAN_TOKENS = { min: 1, max: 10_000_000 } as const;

/** What the gateway does with request parts it cannot read (indirect.Unscanned*). */
export type UnscannedMode = 'allow' | 'log' | 'block';
export const UNSCANNED_MODES: UnscannedMode[] = ['allow', 'log', 'block'];
/** Kinds of unscanned parts (indirect.UnscannedKinds), in audit tag order. */
export type UnscannedKind = 'image' | 'file' | 'audio' | 'other';
export const UNSCANNED_KINDS: UnscannedKind[] = ['image', 'file', 'audio', 'other'];

/** Kinds of personal data the gateway finds (outputguard.PIIKinds). */
export type PiiKind = 'email' | 'phone' | 'card' | 'cccd' | 'ipv4';
export const PII_KINDS: PiiKind[] = ['email', 'phone', 'card', 'cccd', 'ipv4'];

/** Bounds of the conversation window sizes (internal/indirect MinWindowTurns...). */
export const WINDOW_TURNS = { min: 2, max: 32, default: 4 } as const;
export const WINDOW_BYTES = { min: 256, max: 24576, default: 8192 } as const;

/** The highest org block threshold the control plane accepts (indirect.BlockThreshold). */
export const MAX_ORG_THRESHOLD = 0.85;

export type IndirectAction = 'block' | 'redact';

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
  /** Identical refused requests folded into this row (retries); null for one. */
  repeat_count?: number | null;
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
  /** Why stored content is not shown (encrypted without a key, key destroyed). */
  content_error?: string;
  /** The row stores the prompt or the answer: read it with readRequestContent (permission, reason, logged). */
  has_content?: boolean;
  /**
   * The row's tags (requests.pii_entities): counts only, such as
   * "input:pii_email=2" or "input:unscanned_image=1". Absent when the
   * control plane does not return them.
   */
  pii_entities?: string[] | null;
  created_at: string;
}

/** A SIEM export sink (GET /organizations/{org}/siem-sinks). */
export type SiemKind = 'splunk_hec' | 'elastic' | 'sentinel' | 'syslog' | 'http';
export interface SiemSink {
  id: string;
  name: string;
  kind: SiemKind;
  config: Record<string, string>;
  secret_env: string | null;
  secret_set: boolean;
  event_types: string[];
  min_severity: 'info' | 'warning' | 'critical';
  allow_private: boolean;
  enabled: boolean;
  cursor_at: string;
  failures: number;
  last_error: string | null;
  last_success_at: string | null;
  delivered: number;
  created_at: string;
}
export type SiemSinkInput = Pick<SiemSink, 'name' | 'kind' | 'config' | 'secret_env' | 'event_types' | 'min_severity' | 'allow_private' | 'enabled'>;

/** POST /organizations/{org}/requests/{id}/content */
export interface StoredContent {
  request_content: string | null;
  response_content: string | null;
  content_error?: string;
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
  /** The detection layers that run (l1, l2, l3); null or absent when the gateway did not say. */
  layers?: string[] | null;
  /** The gateway's version (its /readyz); absent from older control planes or gateways. */
  gateway_version?: string;
  /** The fusion combiner: logreg or max. */
  fusion?: string;
  /** FUSION_L1_FLOOR as applied (0: off); null or absent when the gateway does not report it. */
  l1_floor?: number | null;
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
  /** Matched in a log-only policy: recorded, not applied. */
  log_only?: boolean;
}

/** A rule of a log-only policy that would have decided. */
export interface LogOnlyMatch {
  rule_id: UUID;
  rule_name: string;
  action: Action;
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
    log_only?: LogOnlyMatch[];
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
  type: IdentityProviderType;
  display_name: string;
}

export type IdentityProviderType = 'google' | 'oidc' | 'saml';

/** What the SAML identity provider is configured with (answers only; needs PUBLIC_BASE_URL). */
export interface SamlSpInfo {
  entity_id: string;
  acs_url: string;
  metadata_url: string;
}

export interface IdentityProvider {
  id: string;
  type: IdentityProviderType;
  display_name: string;
  /** OIDC issuer; for SAML the IdP entity id, taken from the metadata by the control plane. */
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
  /** SAML: the IdP metadata XML (at most SAML_METADATA_MAX bytes). */
  saml_metadata?: string;
  /** SAML: accept unsolicited (IdP-initiated) responses; off by default, they cannot be bound to a browser. */
  saml_allow_idp_initiated?: boolean;
  /** SAML attribute names; empty: the usual names (email, mail, displayName, groups, memberOf…). */
  saml_email_attribute?: string;
  saml_name_attribute?: string;
  saml_groups_attribute?: string;
  saml_sp?: SamlSpInfo;
}

export type IdentityProviderInput = Omit<IdentityProvider, 'id' | 'saml_sp'>;
/** The control plane's limit on saml_metadata (256 KiB). */
export const SAML_METADATA_MAX = 262144;
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
  /** Lowest role that may read stored prompt and answer content (default admin). */
  content_read_role?: Role;
  /** Readers must give a reason, which the activity log keeps (default true). */
  content_view_reason?: boolean;
  /** A SCIM deactivation also revokes the API keys the user created in the org (default true). */
  scim_revoke_keys?: boolean;
  /** Disabling a policy and turning content storage on wait for a second admin (migration 027, default false). Deleting the org always does. */
  two_person_approval?: boolean;
  /** How long such a request waits for a decision (default 24, at most 720). */
  approval_expiry_hours?: number;
  /** Every new API key expires within this many days (migration 028); null: no limit. */
  api_key_max_lifetime_days?: number | null;
}

// ── Two-person approval (migrations 027 and 029) ────────────────────────────

/** policy.delete is history only: deleting a policy needs it disabled instead (migration 029). */
/** input_settings.loosen: loosening the input settings (migration 030). */
export type ApprovalKind = 'policy.disable' | 'policy.delete' | 'content_storage.enable' | 'org.delete' | 'input_settings.loosen';
export const APPROVAL_KINDS: readonly ApprovalKind[] = ['policy.disable', 'policy.delete', 'content_storage.enable', 'org.delete', 'input_settings.loosen'];
/** cancelled: what the request was about is gone or already done (migration 029). */
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled';
export const APPROVAL_STATUSES: readonly ApprovalStatus[] = ['pending', 'approved', 'rejected', 'expired', 'cancelled'];

export interface ApprovalRequest {
  id: UUID;
  /** The organization (GET /admin/approvals spans every organization). */
  org_id?: UUID;
  kind: ApprovalKind;
  /** A policy id or the organization id. */
  target: string | null;
  /** The policy's name while it exists. */
  target_label?: string | null;
  payload: Record<string, unknown>;
  reason: string | null;
  status: ApprovalStatus;
  requested_by: { id: UUID | null; email: string | null } | null;
  decided_by: { id: UUID | null; email: string | null } | null;
  decided_at: string | null;
  decision_note: string | null;
  expires_at: string;
  created_at: string;
}

/** A 202 answer of a guarded change: the request that must be approved first. */
export interface ApprovalPending {
  approval_required: true;
  /** The same change was already waiting: this is that request. */
  already_pending?: boolean;
  request: ApprovalRequest;
}

// ── Input settings (migration 030) ─────────────────────────────────────────

export type InputMode = 'text_only' | 'hybrid';
export type UnreadableFileAction = 'block' | 'pass';

/** What the gateway accepts as input for one organization. */
export interface InputSettings {
  input_mode: InputMode;
  /** null: the instance's limit. */
  max_input_tokens: number | null;
  /** hybrid only; among the instance's readable_file_types. */
  allowed_file_types: string[];
  unreadable_file_action: UnreadableFileAction;
}

/** The instance limits the settings stay within, from the gateway's /readyz. */
export interface InstanceInput {
  /** gateway: read from the gateway; default: it could not be read, the short path's limit is assumed. */
  source: 'gateway' | 'default';
  max_input_tokens_ceiling: number;
  max_scan_tokens: number | null;
  pdf_extract: boolean | null;
  unscanned_parts: UnscannedMode | null;
  readable_file_types: string[];
  error?: string;
}

/** GET /organizations/{id}/input-settings. */
export interface InputSettingsState {
  /** No settings: the instance's behaviour applies. */
  inherit: boolean;
  settings: InputSettings | null;
  updated_at: string | null;
  instance: InstanceInput;
  two_person_approval: boolean;
  /** The loosening waiting for a second admin. */
  pending: ApprovalRequest | null;
}

/** A 202 answer of a loosening: the tightening part applied (applied_now), the rest waits. */
export interface InputSettingsPending extends ApprovalPending {
  applied_now: boolean;
  state: InputSettingsState;
}

// ── SCIM provisioning and IdP group roles (migration 025) ──────────────────

export interface ScimToken {
  id: UUID;
  name: string;
  /** The first characters of the token (gss_…). */
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

/** GET /organizations/:orgId/scim/tokens. */
export interface ScimTokenList {
  items: ScimToken[];
  /** The SCIM 2.0 base URL to give the directory (relative when PUBLIC_BASE_URL is not set). */
  base_url: string;
  /** Users and groups the directory provisioned. */
  users: number;
  groups: number;
}

/** POST /organizations/:orgId/scim/tokens: the token is shown once. */
export interface CreatedScimToken {
  token: string;
  item: ScimToken;
}

export type GroupRoleValue = 'viewer' | 'member' | 'admin';
export const GROUP_ROLE_VALUES: readonly GroupRoleValue[] = ['viewer', 'member', 'admin'];

/** An IdP group mapped to an org role: provider_id null for a SCIM group, else a SAML provider. */
export interface GroupRole {
  id?: UUID;
  provider_id: string | null;
  group_key: string;
  role: GroupRoleValue;
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
