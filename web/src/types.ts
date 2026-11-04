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

// ── Upstreams (contract) ────────────────────────────────────────────────────

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
