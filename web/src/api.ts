// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Typed client for the control plane API under /v1. Every call but login
// sends the session token as a Bearer header; a 401 on an authenticated call
// ends the session (onUnauthorized).

import type {
  ApiKey,
  AuditRow,
  CatalogEntry,
  ConditionNode,
  ConfigApplyResult,
  ConfigError,
  ConnectionTest,
  CreatedApiKey,
  CreatedInvite,
  DashboardStats,
  DashboardWindow,
  ExportProblem,
  Exemplar,
  ExemplarInput,
  GatewayModels,
  GuardSettings,
  IdentityProvider,
  IdentityProviderInput,
  InstanceUser,
  InviteAcceptResponse,
  LinkResult,
  ProviderKind,
  LoginProvider,
  LoginResponse,
  Me,
  Membership,
  NewApiKey,
  Org,
  OrgSecurity,
  PageEnvelope,
  PermissionMatrix,
  Policy,
  PolicyInput,
  PolicySchema,
  Project,
  Role,
  ShadowDirection,
  ShadowDisagreement,
  ShadowSummary,
  ShadowWindow,
  SimulateRequest,
  SimulateResponse,
  TotpSetup,
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
  /**
   * Send this bearer token instead of the session's, and do not end the
   * session on 401: the short-lived mfa_token while signing in.
   */
  bearer?: string;
}

/** The endpoint does not exist on this control plane (yet): 404 or 405. */
export function isNotFound(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 404 || e.status === 405);
}

/** The caller lacks the role for this endpoint (403). */
export function isForbidden(e: unknown): boolean {
  return e instanceof ApiError && e.status === 403;
}

/**
 * A catalog preset in the control plane's field names, also from the
 * contract draft's names (provider, base_url, needs_key, env_hint, models).
 */
export function normalizeCatalogEntry(raw: unknown): CatalogEntry {
  const o = (raw ?? {}) as Record<string, unknown>;
  const str = (...keys: string[]) => {
    for (const k of keys) if (typeof o[k] === 'string') return o[k];
    return undefined;
  };
  const models = Array.isArray(o.known_models) ? o.known_models : Array.isArray(o.models) ? o.models : [];
  const entry: CatalogEntry = {
    id: (str('id', 'provider') ?? '') as ProviderKind,
    display_name: str('display_name', 'name') ?? str('id', 'provider') ?? '',
    default_base_url: str('default_base_url', 'base_url') ?? '',
    key_required: o.key_required === true || o.needs_key === true,
    known_models: models.filter((m): m is string => typeof m === 'string'),
    needs_api_version: o.needs_api_version === true,
    openai_compatible_endpoint: o.openai_compatible_endpoint === true,
  };
  const hint = str('key_env_hint', 'env_hint');
  if (hint) entry.key_env_hint = hint;
  const docs = str('docs_url');
  if (docs) entry.docs_url = docs;
  const notes = str('notes');
  if (notes) entry.notes = notes;
  return entry;
}

/** The rows of a list response: {data}, {items} or a plain array. */
export function listOf<T>(r: unknown): T[] {
  if (Array.isArray(r)) return r as T[];
  const o = (r ?? {}) as { data?: unknown; items?: unknown };
  if (Array.isArray(o.items)) return o.items as T[];
  if (Array.isArray(o.data)) return o.data as T[];
  return [];
}

/** Query of a list page: limit, cursor and filters (identity contract §0). */
export type ListQuery = Record<string, string | number | boolean | undefined>;

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
    const token = opts.bearer ?? (opts.anonymous ? null : this.getToken());
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await this.fetchImpl(url, { method, headers, body, credentials: 'same-origin' });
    if (res.status === 401 && !opts.anonymous && !opts.bearer) {
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

  /** POST /auth/login: a session token, or a 2FA step (identity contract §1). */
  signIn(email: string, password: string): Promise<LoginResponse> {
    return this.request('POST', '/auth/login', { body: { email, password }, anonymous: true });
  }

  /** The second factor of a sign-in: a TOTP code or a recovery code. */
  verifyMfa(mfaToken: string, code: string): Promise<LoginResponse> {
    return this.request('POST', '/auth/mfa/verify', { body: { mfa_token: mfaToken, code }, anonymous: true });
  }

  /** The one-time code of the SSO callback (#/auth/callback?code=). */
  exchangeOidcCode(code: string): Promise<LoginResponse> {
    return this.request('POST', '/auth/oidc/exchange', { body: { code }, anonymous: true });
  }

  /** Enabled SSO providers for the login page (public). */
  async listLoginProviders(): Promise<LoginProvider[]> {
    return listOf<LoginProvider>(await this.request('GET', '/auth/providers', { anonymous: true }));
  }

  /** Where the browser goes to sign in with a provider (a 302 to the provider). */
  oidcStartUrl(providerId: string, redirect = '/ui/'): string {
    return `${this.baseUrl}/auth/oidc/${enc(providerId)}/start?redirect=${enc(redirect)}`;
  }

  getMe(): Promise<Me> {
    return this.request('GET', '/auth/me');
  }

  /** Revokes the current session on the server; the caller forgets the token. */
  logout(): Promise<void> {
    // bearer: a refusal (an expired session) must not report "session ended".
    const token = this.getToken();
    return this.request('POST', '/auth/logout', token ? { bearer: token } : { anonymous: true });
  }

  changePassword(currentPassword: string, newPassword: string): Promise<void> {
    return this.request('POST', '/auth/password', { body: { current_password: currentPassword, new_password: newPassword } });
  }

  /** Starts TOTP enrollment; bearer is the mfa_token during a forced enrollment. */
  setupTotp(bearer?: string): Promise<TotpSetup> {
    return this.request('POST', '/auth/mfa/totp/setup', bearer ? { bearer } : {});
  }

  /** Confirms enrollment: recovery codes (shown once), and a session token while enrolling. */
  confirmTotp(code: string, bearer?: string): Promise<{ recovery_codes: string[]; token?: string }> {
    return this.request('POST', '/auth/mfa/totp/confirm', bearer ? { body: { code }, bearer } : { body: { code } });
  }

  regenerateRecoveryCodes(code: string): Promise<{ recovery_codes: string[] }> {
    return this.request('POST', '/auth/mfa/recovery-codes/regenerate', { body: { code } });
  }

  disableMfa(code: string): Promise<void> {
    return this.request('DELETE', '/auth/mfa', { body: { code } });
  }

  listSessions(): Promise<unknown> {
    return this.request('GET', '/auth/sessions');
  }

  revokeSession(id: string): Promise<void> {
    return this.request('DELETE', `/auth/sessions/${enc(id)}`);
  }

  /**
   * Starts linking a provider to the signed-in user. The control plane
   * answers with the provider URL ({url} or {redirect_url}) to send the
   * browser to.
   */
  async startLinkIdentity(providerId: string, redirect = '/ui/account'): Promise<string> {
    const r = await this.request<{ url?: string; redirect_url?: string } | undefined>('POST', `/auth/identities/${enc(providerId)}/link/start`, {
      body: { redirect },
    });
    const url = r?.url ?? r?.redirect_url;
    if (!url) throw new ApiError(500, 'no redirect URL in the response', r);
    return url;
  }

  /** Binds the identity of a profile link (the code of /ui/account?link_code=) to the caller. */
  completeLink(code: string): Promise<LinkResult> {
    return this.request('POST', '/auth/identities/link/complete', { body: { code } });
  }

  /** Accepts an invite (public): answers like a login, plus the membership. */
  acceptInvite(token: string, password: string, displayName: string): Promise<InviteAcceptResponse> {
    return this.request('POST', '/invites/accept', { body: { token, password, display_name: displayName }, anonymous: true });
  }

  unlinkIdentity(providerId: string): Promise<void> {
    return this.request('DELETE', `/auth/identities/${enc(providerId)}`);
  }

  // ── Permissions, members, invites, security, activity ───────────────────

  getPermissions(): Promise<PermissionMatrix> {
    return this.request('GET', '/permissions');
  }

  listMembers(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/members`, { query: q });
  }

  setMemberRole(orgId: UUID, userId: UUID, role: Role): Promise<unknown> {
    return this.request('PUT', `/organizations/${enc(orgId)}/members/${enc(userId)}`, { body: { role } });
  }

  removeMember(orgId: UUID, userId: UUID): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/members/${enc(userId)}`);
  }

  resetMemberMfa(orgId: UUID, userId: UUID): Promise<unknown> {
    return this.request('POST', `/organizations/${enc(orgId)}/members/${enc(userId)}/reset-mfa`);
  }

  revokeMemberSessions(orgId: UUID, userId: UUID): Promise<unknown> {
    return this.request('POST', `/organizations/${enc(orgId)}/members/${enc(userId)}/revoke-sessions`);
  }

  listInvites(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/invites`, { query: q });
  }

  createInvite(orgId: UUID, email: string, role: Role, ttlHours?: number): Promise<CreatedInvite> {
    return this.request('POST', `/organizations/${enc(orgId)}/invites`, { body: { email, role, ...(ttlHours ? { ttl_hours: ttlHours } : {}) } });
  }

  revokeInvite(orgId: UUID, id: UUID): Promise<void> {
    return this.request('DELETE', `/organizations/${enc(orgId)}/invites/${enc(id)}`);
  }

  getOrgSecurity(orgId: UUID): Promise<OrgSecurity> {
    return this.request('GET', `/organizations/${enc(orgId)}/security`);
  }

  /** allowed_login_methods is sent only when it changes (null: unrestricted). */
  putOrgSecurity(orgId: UUID, s: Partial<OrgSecurity>): Promise<OrgSecurity> {
    return this.request('PUT', `/organizations/${enc(orgId)}/security`, { body: s });
  }

  listActivity(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/activity`, { query: q });
  }

  // ── Instance admin ────────────────────────────────────────────────────────

  listUsers(q: ListQuery): Promise<unknown> {
    return this.request('GET', '/admin/users', { query: q });
  }

  createUser(input: { email: string; display_name: string; password?: string }): Promise<InstanceUser> {
    return this.request('POST', '/admin/users', { body: input });
  }

  updateUser(id: UUID, input: { display_name?: string | null; disabled?: boolean; is_instance_admin?: boolean }): Promise<InstanceUser> {
    return this.request('PUT', `/admin/users/${enc(id)}`, { body: input });
  }

  deleteUser(id: UUID): Promise<void> {
    return this.request('DELETE', `/admin/users/${enc(id)}`);
  }

  listIdentityProvidersPage(q: ListQuery): Promise<unknown> {
    return this.request('GET', '/admin/identity-providers', { query: q });
  }

  /** The redirect URI to register at the provider. */
  oidcCallbackUrl(providerId: string | null): string {
    const id = providerId === null ? '<id>' : enc(providerId);
    return `${typeof window === 'undefined' ? '' : window.location.origin}${this.baseUrl}/auth/oidc/${id}/callback`;
  }

  listAdminActivity(q: ListQuery): Promise<unknown> {
    return this.request('GET', '/admin/activity', { query: q });
  }

  async listIdentityProviders(): Promise<IdentityProvider[]> {
    return listOf<IdentityProvider>(await this.request('GET', '/admin/identity-providers'));
  }

  createIdentityProvider(input: IdentityProviderInput): Promise<IdentityProvider> {
    return this.request('POST', '/admin/identity-providers', { body: input });
  }

  updateIdentityProvider(id: string, input: IdentityProviderInput): Promise<IdentityProvider> {
    return this.request('PUT', `/admin/identity-providers/${enc(id)}`, { body: input });
  }

  deleteIdentityProvider(id: string): Promise<void> {
    return this.request('DELETE', `/admin/identity-providers/${enc(id)}`);
  }

  // ── Model providers ───────────────────────────────────────────────────────

  async getProviderCatalog(): Promise<CatalogEntry[]> {
    const r = await this.request<unknown>('GET', '/providers/catalog');
    const providers = (r as { providers?: unknown } | null)?.providers;
    return (Array.isArray(providers) ? (providers as unknown[]) : listOf<unknown>(r)).map(normalizeCatalogEntry).filter((e) => e.id !== ('' as ProviderKind));
  }

  testUpstream(orgId: UUID, id: UUID): Promise<ConnectionTest> {
    return this.request('POST', `/organizations/${enc(orgId)}/upstreams/${enc(id)}/test`);
  }

  /** One page of upstreams (raw: the envelope or the older {data}). */
  listUpstreamsPage(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/upstreams`, { query: q });
  }

  // ── Pages of the older lists (raw: envelope, {data} or array) ────────────

  listApiKeysPage(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/api-keys`, { query: q });
  }

  listProjectsPage(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/projects`, { query: q });
  }

  listExemplarsPage(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/exemplars`, { query: q });
  }

  listRequestsPage(orgId: UUID, q: ListQuery): Promise<unknown> {
    return this.request('GET', `/organizations/${enc(orgId)}/requests`, { query: q });
  }

  /** The organizations the signed-in user belongs to, with the role. */
  async listMyOrgs(): Promise<Membership[]> {
    return listOf<Membership>(await this.request('GET', '/organizations'));
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
    return listOf<Project>(await this.request('GET', `/organizations/${enc(orgId)}/projects`));
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
    return listOf<ApiKey>(await this.request('GET', `/organizations/${enc(orgId)}/api-keys`));
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
    const r = listOf<Policy>(await this.request('GET', `/organizations/${enc(orgId)}/policies`));
    return r.map((p) => ({ ...p, rules: Array.isArray(p.rules) ? p.rules : [] }));
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
    return listOf<AuditRow>(await this.request('GET', `/organizations/${enc(orgId)}/requests`, { query: { limit } }));
  }

  /** Aggregates of the request log over a window (24h by default), of one project or all. */
  getDashboard(orgId: UUID, q: { window?: DashboardWindow; project_id?: UUID } = {}): Promise<DashboardStats> {
    return this.request('GET', `/organizations/${enc(orgId)}/dashboard`, { query: q });
  }

  // ── Classifier models and shadow comparison ──────────────────────────────

  /** The gateway's classifier models (instance-wide, any signed-in user). */
  getGatewayModels(): Promise<GatewayModels> {
    return this.request('GET', '/gateway/models');
  }

  /** The shadow classifier against the active one over a window (24h by default). */
  getShadowSummary(orgId: UUID, q: { window?: ShadowWindow } = {}): Promise<ShadowSummary> {
    return this.request('GET', `/organizations/${enc(orgId)}/shadow`, { query: q });
  }

  /** Requests where the models decide differently, newest first: {items, next_cursor}. */
  listShadowDisagreements(
    orgId: UUID,
    q: { window?: ShadowWindow; direction?: ShadowDirection; limit?: number; cursor?: string } = {},
  ): Promise<PageEnvelope<ShadowDisagreement>> {
    return this.request('GET', `/organizations/${enc(orgId)}/shadow/disagreements`, { query: q });
  }

  // ── Upstreams ─────────────────────────────────────────────────────────────

  async listUpstreams(orgId: UUID): Promise<Upstream[]> {
    return listOf<Upstream>(await this.request('GET', `/organizations/${enc(orgId)}/upstreams`));
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
