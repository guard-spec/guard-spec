// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError, isForbidden, isNotFound, listOf } from './api';

interface Call {
  url: string;
  init: RequestInit;
}

function fakeFetch(responses: (Response | (() => Response))[]) {
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: input instanceof URL ? input.toString() : typeof input === 'string' ? input : input.url, init: init ?? {} });
    const r = responses.shift();
    if (!r) throw new Error('no more responses');
    return Promise.resolve(typeof r === 'function' ? r() : r);
  });
  return { fetch: fn as unknown as typeof fetch, calls };
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const bodyOf = (c: Call | undefined): unknown => JSON.parse(typeof c?.init.body === 'string' ? c.init.body : 'null');
const headers = (c: Call | undefined) => (c?.init.headers ?? {}) as Record<string, string>;

describe('ApiClient', () => {
  it('logs in without a token and returns the new one', async () => {
    const f = fakeFetch([json(200, { token: 'tok' })]);
    const api = new ApiClient({ getToken: () => 'old', fetch: f.fetch });
    await expect(api.login('a@b.c', 'pw')).resolves.toBe('tok');
    expect(f.calls[0]?.url).toBe('/v1/auth/login');
    expect(f.calls[0]?.init.method).toBe('POST');
    expect(headers(f.calls[0]).Authorization).toBeUndefined();
    expect(bodyOf(f.calls[0])).toEqual({ email: 'a@b.c', password: 'pw' });
  });

  it('does not end the session when the login itself is refused', async () => {
    const onUnauthorized = vi.fn();
    const f = fakeFetch([json(401, { error: 'invalid credentials' })]);
    const api = new ApiClient({ getToken: () => null, onUnauthorized, fetch: f.fetch });
    await expect(api.login('a', 'b')).rejects.toMatchObject({ status: 401, message: 'invalid credentials' });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it('sends the bearer token and unwraps list responses', async () => {
    const f = fakeFetch([json(200, { data: [{ id: 'p1', name: 'P', slug: 'p' }] })]);
    const api = new ApiClient({ getToken: () => 'tok', fetch: f.fetch });
    const projects = await api.listProjects('org/1');
    expect(projects).toEqual([{ id: 'p1', name: 'P', slug: 'p' }]);
    expect(f.calls[0]?.url).toBe('/v1/organizations/org%2F1/projects');
    expect(headers(f.calls[0]).Authorization).toBe('Bearer tok');
  });

  it('ends the session on a 401 from an authenticated call', async () => {
    const onUnauthorized = vi.fn();
    const f = fakeFetch([json(401, { error: 'expired' })]);
    const api = new ApiClient({ getToken: () => 'tok', onUnauthorized, fetch: f.fetch });
    await expect(api.getOrg('o')).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it('reads the position of a parse error', async () => {
    const f = fakeFetch([json(422, { error: 'unexpected token', position: 12 })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    const err = await api.parseCondition('scores.l2 > ').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).position).toBe(12);
    expect((err as ApiError).status).toBe(422);
  });

  it('parses and formats conditions', async () => {
    const tree = { combinator: 'and', rules: [{ field: 'scores.l2', operator: '>', value: '0.8' }] };
    const f = fakeFetch([json(200, { condition: tree }), json(200, { text: 'scores.l2 > 0.8' })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await expect(api.parseCondition('scores.l2 > 0.8')).resolves.toEqual(tree);
    await expect(api.formatCondition(tree as never)).resolves.toBe('scores.l2 > 0.8');
    expect(bodyOf(f.calls[1])).toEqual({ condition: tree });
  });

  it('sends YAML as is for a dry run and reads errors by path', async () => {
    const f = fakeFetch([
      json(200, { applied: false, changes: [{ kind: 'upstream', name: 'main', op: 'create' }] }),
      json(422, { errors: [{ path: 'policies[0].rules[1].when', message: 'bad' }] }),
    ]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    const r = await api.putConfig('o', 'version: 1\n', true);
    expect(r.changes).toHaveLength(1);
    expect(f.calls[0]?.url).toBe('/v1/organizations/o/config?dry_run=true');
    expect(f.calls[0]?.init.body).toBe('version: 1\n');
    expect(headers(f.calls[0])['Content-Type']).toBe('application/yaml');
    const err = (await api.putConfig('o', 'x', false).catch((e: unknown) => e)) as ApiError;
    expect(f.calls[1]?.url).toBe('/v1/organizations/o/config');
    expect(err.errors).toEqual([{ path: 'policies[0].rules[1].when', message: 'bad' }]);
  });

  it('reads the config as text', async () => {
    const f = fakeFetch([new Response('version: 1\n', { status: 200, headers: { 'Content-Type': 'text/yaml' } })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await expect(api.getConfig('o')).resolves.toBe('version: 1\n');
  });

  it('handles 204 and non-JSON errors', async () => {
    const f = fakeFetch([new Response(null, { status: 204 }), new Response('bad gateway', { status: 502 })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await expect(api.deletePolicy('o', 'p')).resolves.toBeUndefined();
    await expect(api.listRequests('o', 5)).rejects.toMatchObject({ status: 502, message: 'HTTP 502' });
    expect(f.calls[1]?.url).toBe('/v1/organizations/o/requests?limit=5');
  });

  it('accepts upstream lists with or without a data wrapper', async () => {
    const u = { id: 'u', name: 'main' };
    const f = fakeFetch([json(200, { data: [u] }), json(200, [u])]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await expect(api.listUpstreams('o')).resolves.toEqual([u]);
    await expect(api.listUpstreams('o')).resolves.toEqual([u]);
  });

  it('sets default upstreams and simulates', async () => {
    const f = fakeFetch([json(200, {}), json(200, {}), json(200, { trace: [], decision: { action: 'allow' } })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await api.setOrgDefaultUpstream('o', null);
    await api.setProjectDefaultUpstream('o', 'p', 'u');
    await api.simulate('o', { policy_id: null, vars: { 'scores.l2': 0.9 } });
    expect(f.calls.map((c) => `${String(c.init.method)} ${c.url}`)).toEqual([
      'PUT /v1/organizations/o/default-upstream',
      'PUT /v1/organizations/o/projects/p/default-upstream',
      'POST /v1/organizations/o/policies/simulate',
    ]);
    expect(bodyOf(f.calls[0])).toEqual({ upstream_id: null });
  });
});

describe('ApiClient, identity contract', () => {
  it('returns the 2FA step of a sign-in as is', async () => {
    const f = fakeFetch([json(200, { mfa_required: true, mfa_token: 'm', methods: ['totp'] })]);
    const api = new ApiClient({ getToken: () => null, fetch: f.fetch });
    await expect(api.signIn('a@b.c', 'pw')).resolves.toEqual({ mfa_required: true, mfa_token: 'm', methods: ['totp'] });
  });

  it('sends the mfa_token as bearer while enrolling, and a 401 there does not end the session', async () => {
    const onUnauthorized = vi.fn();
    const f = fakeFetch([json(200, { secret: 'S', otpauth_url: 'otpauth://x' }), json(401, { error: 'expired' })]);
    const api = new ApiClient({ getToken: () => 'session', onUnauthorized, fetch: f.fetch });
    await api.setupTotp('mfa-tok');
    expect(headers(f.calls[0]).Authorization).toBe('Bearer mfa-tok');
    await expect(api.confirmTotp('123456', 'mfa-tok')).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it('pages list endpoints with limit and cursor', async () => {
    const f = fakeFetch([json(200, { items: [], next_cursor: null })]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await api.listMembers('o', { limit: 25, cursor: 'abc', q: undefined, role: 'admin' });
    expect(f.calls[0]?.url).toBe('/v1/organizations/o/members?limit=25&cursor=abc&role=admin');
  });

  it('unwraps every list shape and recognises a missing endpoint', async () => {
    expect(listOf([1])).toEqual([1]);
    expect(listOf({ data: [2] })).toEqual([2]);
    expect(listOf({ items: [3], next_cursor: null })).toEqual([3]);
    expect(listOf(undefined)).toEqual([]);
    expect(isNotFound(new ApiError(404, 'x'))).toBe(true);
    expect(isNotFound(new ApiError(500, 'x'))).toBe(false);
    const f = fakeFetch([json(200, [{ id: 'g', type: 'google', display_name: 'Google' }])]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    await expect(api.listLoginProviders()).resolves.toHaveLength(1);
    expect(headers(f.calls[0]).Authorization).toBeUndefined();
  });

  it('reads the provider catalog of the control plane, a plain array and the draft names', async () => {
    const backend = {
      items: [
        {
          id: 'openai_compatible',
          display_name: 'OpenAI-compatible',
          default_base_url: '',
          key_required: false,
          key_env_hint: '',
          needs_api_version: false,
          openai_compatible_endpoint: false,
          known_models: null,
          docs_url: '',
          notes: 'Any endpoint',
        },
        { id: 'gemini', display_name: 'Google Gemini', default_base_url: 'https://g/v1', key_required: true, key_env_hint: 'UPSTREAM_KEY_GEMINI', openai_compatible_endpoint: true, known_models: ['gemini-2.5-pro'] },
      ],
    };
    const f = fakeFetch([json(200, backend), json(200, [{ provider: 'openai', base_url: 'https://o/v1', needs_key: true, env_hint: 'UPSTREAM_KEY_OPENAI', models: ['gpt-4o'] }])]);
    const api = new ApiClient({ getToken: () => 't', fetch: f.fetch });
    const cat = await api.getProviderCatalog();
    expect(cat[0]).toEqual({
      id: 'openai_compatible',
      display_name: 'OpenAI-compatible',
      default_base_url: '',
      key_required: false,
      known_models: [], // null on the wire
      needs_api_version: false,
      openai_compatible_endpoint: false,
      notes: 'Any endpoint',
    });
    expect(cat[1]).toMatchObject({ id: 'gemini', key_required: true, key_env_hint: 'UPSTREAM_KEY_GEMINI', openai_compatible_endpoint: true, known_models: ['gemini-2.5-pro'] });
    await expect(api.getProviderCatalog()).resolves.toEqual([
      expect.objectContaining({ id: 'openai', default_base_url: 'https://o/v1', key_required: true, key_env_hint: 'UPSTREAM_KEY_OPENAI', known_models: ['gpt-4o'] }),
    ]);
  });

  it('completes a profile link with the code and the session token', async () => {
    const f = fakeFetch([json(200, { provider_id: 'okta', linked: true })]);
    const api = new ApiClient({ getToken: () => 'tok', fetch: f.fetch });
    await api.completeLink('c1');
    expect(f.calls[0]?.url).toBe('/v1/auth/identities/link/complete');
    expect(headers(f.calls[0]).Authorization).toBe('Bearer tok');
    expect(bodyOf(f.calls[0])).toEqual({ code: 'c1' });
  });

  it('accepts an invite without a token and recognises 403', async () => {
    const f = fakeFetch([json(201, { token: 'tok', org_id: 'o', role: 'member' })]);
    const api = new ApiClient({ getToken: () => 'old', fetch: f.fetch });
    await expect(api.acceptInvite('inv_1', 'pw-pw-pw-pw-pw', 'Ann')).resolves.toMatchObject({ token: 'tok', org_id: 'o' });
    expect(headers(f.calls[0]).Authorization).toBeUndefined();
    expect(bodyOf(f.calls[0])).toEqual({ token: 'inv_1', password: 'pw-pw-pw-pw-pw', display_name: 'Ann' });
    expect(isForbidden(new ApiError(403, 'no'))).toBe(true);
    expect(isForbidden(new ApiError(404, 'no'))).toBe(false);
  });

  it('shows the redirect URI placeholder unencoded', () => {
    const api = new ApiClient({ getToken: () => null, fetch: fakeFetch([]).fetch });
    expect(api.oidcCallbackUrl(null)).toMatch(/\/v1\/auth\/oidc\/<id>\/callback$/);
    expect(api.oidcCallbackUrl('a b')).toMatch(/\/v1\/auth\/oidc\/a%20b\/callback$/);
  });

  it('builds the SSO start URL with a same-origin redirect', () => {
    const api = new ApiClient({ getToken: () => null, fetch: fakeFetch([]).fetch });
    expect(api.oidcStartUrl('google', '/ui/')).toBe('/v1/auth/oidc/google/start?redirect=%2Fui%2F');
  });
});
