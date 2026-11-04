// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError } from './api';

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
