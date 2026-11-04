// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Typed client for the control plane API under /v1. Every call but login
// sends the session token as a Bearer header; a 401 on an authenticated call
// ends the session (onUnauthorized).

import type {
  ApiKey,
  AuditRow,
  ConditionNode,
  ConfigApplyResult,
  ConfigError,
  CreatedApiKey,
  ExportProblem,
  Exemplar,
  ExemplarInput,
  GuardSettings,
  NewApiKey,
  Org,
  Policy,
  PolicyInput,
  PolicySchema,
  Project,
  SimulateRequest,
  SimulateResponse,
  Upstream,
  UpstreamInput,
  UUID,
} from './types';

/** An error response. message is the server's `error`, or a generic text. */
export class ApiError extends Error {
  readonly status: number;
  /** Character offset of a parse error (POST /policy/parse). */
  readonly position: number | undefined;
  /** Errors by path (PUT /config). */
  readonly errors: ConfigError[] | undefined;
  /** Policies that keep the config from being exported (GET /config, 409). */
  readonly problems: ExportProblem[] | undefined;
  readonly body: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    const b = (body ?? {}) as { position?: unknown; errors?: unknown; problems?: unknown };
    this.position = typeof b.position === 'number' ? b.position : undefined;
    this.errors = Array.isArray(b.errors) ? (b.errors as ConfigError[]) : undefined;
    this.problems = Array.isArray(b.problems) ? (b.problems as ExportProblem[]) : undefined;
  }
}

export interface ClientOptions {
  baseUrl?: string;
  getToken: () => string | null;
  onUnauthorized?: () => void;
  fetch?: typeof fetch;
}

interface RequestOptions {
  body?: unknown;
  /** Send body as this content type, as is (text). */
  rawBody?: { contentType: string; text: string };
  query?: Record<string, string | number | boolean | undefined>;
  /** Read the response as text, not JSON. */
  text?: boolean;
  /** Do not send the token or end the session on 401 (login). */
  anonymous?: boolean;
}

const enc = encodeURIComponent;

export class ApiClient {
  private readonly baseUrl: string;
  private readonly getToken: () => string | null;
  private readonly onUnauthorized: (() => void) | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = (opts.baseUrl ?? '/v1').replace(/\/$/, '');
    this.getToken = opts.getToken;
    this.onUnauthorized = opts.onUnauthorized;
    this.fetchImpl = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    let url = this.baseUrl + path;
    if (opts.query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined) q.set(k, String(v));
      }
      const s = q.toString();
      if (s) url += '?' + s;
    }
    const headers: Record<string, string> = { Accept: opts.text ? 'text/yaml, text/plain, */*' : 'application/json' };
    let body: string | undefined;
    if (opts.rawBody) {
      headers['Content-Type'] = opts.rawBody.contentType;
      body = opts.rawBody.text;
    } else if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    const token = opts.anonymous ? null : this.getToken();
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await this.fetchImpl(url, { method, headers, body, credentials: 'same-origin' });
    if (res.status === 401 && !opts.anonymous) {
      this.onUnauthorized?.();
    }
    if (!res.ok) {
      const raw = await res.text();
      let parsed: unknown = undefined;
      try {
        parsed = raw ? JSON.parse(raw) : undefined;
      } catch {
        parsed = raw;
      }
      const msg =
        parsed && typeof parsed === 'object' && typeof (parsed as { error?: unknown }).error === 'string'
          ? (parsed as { error: string }).error
          : `HTTP ${res.status}`;
      throw new ApiError(res.status, msg, parsed);
    }
    if (res.status === 204) return undefined as T;
    if (opts.text) return (await res.text()) as T;
    const raw = await res.text();
    return (raw ? JSON.parse(raw) : undefined) as T;
  }

  // ── Auth and organizations ────────────────────────────────────────────────

  async login(email: string, password: string): Promise<string> {
    const r = await this.request<{ token: string }>('POST', '/auth/login', { body: { email, password }, anonymous: true });
    return r.token;
  }

  getOrg(orgId: UUID): Promise<Org> {
    return this.request('GET', `/organizations/${enc(orgId)}`);
  }

  createOrg(name: string, slug: string): Promise<Org> {
    return this.request('POST', '/organizations', { body: { name, slug } });
  }

  setOrgDefaultUpstream(orgId: UUID, upstreamId: UUID | null): Promise<unknown> {
    return this.request('PUT', `/organizations/${enc(orgId)}/default-upstream`, { body: { upstream_id: upstreamId } });
  }

  // ── Projects ──────────────────────────────────────────────────────────────

  async listProjects(orgId: UUID): Promise<Project[]> {
    return (await this.request<{ data: Project[] }>('GET', `/organizations/${enc(orgId)}/projects`)).data;
  }

  createProject(orgId: UUID, name: string, slug: string): Promise<Project> {
    return this.request('POST', `/organizations/${enc(orgId)}/projects`, { body: { name, slug } });
  }

  setProjectDefaultUpstream(orgId: UUID, projectId: UUID, upstreamId: UUID | null): Promise<unknown> {
    return this.request('PUT', `/organizations/${enc(orgId)}/projects/${enc(projectId)}/default-upstream`, {
      body: { upstream_id: upstreamId },
    });
  }

  // ── API keys ──────────────────────────────────────────────────────────────

  async listApiKeys(orgId: UUID): Promise<ApiKey[]> {
    return (await this.request<{ data: ApiKey[] }>('GET', `/organizations/${enc(orgId)}/api-keys`)).data;
  }

  createApiKey(orgId: UUID, input: NewApiKey): Promise<CreatedApiKey> {
    return this.request('POST', `/organizations/${enc(orgId)}/api-keys`, { body: input });
  }

  updateApiKey(orgId: UUID, prefix: string, limits: { rpm_limit?: number | null; tpm_limit?: number | null }): Promise<unknown> {
    return this.request('PATCH', `/organizations/${enc(orgId)}/api-keys/${enc(prefix)}`, { body: limits });
  }

  revokeApiKey(orgId: UUID, prefix: string): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/api-keys/${enc(prefix)}`);
  }

  // ── Policies ──────────────────────────────────────────────────────────────

  async listPolicies(orgId: UUID): Promise<Policy[]> {
    const r = await this.request<{ data: Policy[] }>('GET', `/organizations/${enc(orgId)}/policies`);
    return r.data.map((p) => ({ ...p, rules: Array.isArray(p.rules) ? p.rules : [] }));
  }

  createPolicy(orgId: UUID, input: PolicyInput): Promise<{ id: UUID }> {
    return this.request('POST', `/organizations/${enc(orgId)}/policies`, { body: input });
  }

  updatePolicy(orgId: UUID, id: UUID, input: Partial<PolicyInput>): Promise<{ id: UUID; updated: boolean }> {
    return this.request('PUT', `/organizations/${enc(orgId)}/policies/${enc(id)}`, { body: input });
  }

  deletePolicy(orgId: UUID, id: UUID): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/policies/${enc(id)}`);
  }

  simulate(orgId: UUID, req: SimulateRequest): Promise<SimulateResponse> {
    return this.request('POST', `/organizations/${enc(orgId)}/policies/simulate`, { body: req });
  }

  getPolicySchema(): Promise<PolicySchema> {
    return this.request('GET', '/policy/schema');
  }

  async parseCondition(text: string): Promise<ConditionNode> {
    return (await this.request<{ condition: ConditionNode }>('POST', '/policy/parse', { body: { text } })).condition;
  }

  async formatCondition(condition: ConditionNode): Promise<string> {
    return (await this.request<{ text: string }>('POST', '/policy/format', { body: { condition } })).text;
  }

  validateCondition(condition: ConditionNode): Promise<{ valid: boolean; cel_expression?: string; error?: string }> {
    return this.request('POST', '/cel/validate', { body: { condition } });
  }

  // ── Guard settings ────────────────────────────────────────────────────────

  getGuardSettings(orgId: UUID): Promise<GuardSettings> {
    return this.request('GET', `/organizations/${enc(orgId)}/guard-settings`);
  }

  putGuardSettings(orgId: UUID, s: GuardSettings): Promise<GuardSettings> {
    return this.request('PUT', `/organizations/${enc(orgId)}/guard-settings`, { body: s });
  }

  // ── Exemplars ─────────────────────────────────────────────────────────────

  listExemplars(orgId: UUID): Promise<{ data: Exemplar[]; version?: number }> {
    return this.request('GET', `/organizations/${enc(orgId)}/exemplars`);
  }

  createExemplar(orgId: UUID, input: ExemplarInput): Promise<{ id: UUID }> {
    return this.request('POST', `/organizations/${enc(orgId)}/exemplars`, { body: input });
  }

  updateExemplar(orgId: UUID, id: UUID, input: ExemplarInput): Promise<unknown> {
    return this.request('PUT', `/organizations/${enc(orgId)}/exemplars/${enc(id)}`, { body: input });
  }

  deleteExemplar(orgId: UUID, id: UUID): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/exemplars/${enc(id)}`);
  }

  // ── Audit log ─────────────────────────────────────────────────────────────

  async listRequests(orgId: UUID, limit = 100): Promise<AuditRow[]> {
    return (await this.request<{ data: AuditRow[] }>('GET', `/organizations/${enc(orgId)}/requests`, { query: { limit } })).data;
  }

  // ── Upstreams ─────────────────────────────────────────────────────────────

  async listUpstreams(orgId: UUID): Promise<Upstream[]> {
    const r = await this.request<{ data: Upstream[] } | Upstream[]>('GET', `/organizations/${enc(orgId)}/upstreams`);
    return Array.isArray(r) ? r : r.data;
  }

  createUpstream(orgId: UUID, input: UpstreamInput): Promise<Upstream> {
    return this.request('POST', `/organizations/${enc(orgId)}/upstreams`, { body: input });
  }

  updateUpstream(orgId: UUID, id: UUID, input: UpstreamInput): Promise<Upstream> {
    return this.request('PUT', `/organizations/${enc(orgId)}/upstreams/${enc(id)}`, { body: input });
  }

  deleteUpstream(orgId: UUID, id: UUID): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/upstreams/${enc(id)}`);
  }

  // ── Config as code ────────────────────────────────────────────────────────

  getConfig(orgId: UUID): Promise<string> {
    return this.request('GET', `/organizations/${enc(orgId)}/config`, { text: true });
  }

  putConfig(orgId: UUID, yaml: string, dryRun: boolean): Promise<ConfigApplyResult> {
    return this.request('PUT', `/organizations/${enc(orgId)}/config`, {
      rawBody: { contentType: 'application/yaml', text: yaml },
      query: dryRun ? { dry_run: true } : undefined,
    });
  }
}
