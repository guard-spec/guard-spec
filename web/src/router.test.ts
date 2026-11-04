// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { NAV } from './nav';
import { ALIASES, PATHS, resolve, ROUTES } from './router';

const B = '/ui';

describe('router', () => {
  it('maps every path to its page', () => {
    for (const r of ROUTES) {
      if (r === 'auth-callback') continue;
      expect(resolve(`${B}/${PATHS[r]}`, '', '', B)).toEqual({ route: r, redirect: null });
    }
    expect(resolve(`${B}/admin/identity-providers/`, '', '', B)).toEqual({ route: 'admin-idps', redirect: null });
  });

  it('opens the dashboard at the root and for unknown paths, without a redirect', () => {
    expect(resolve(`${B}/`, '', '', B)).toEqual({ route: 'dashboard', redirect: null });
    expect(resolve(B, '', '', B)).toEqual({ route: 'dashboard', redirect: null });
    expect(resolve(`${B}/nope`, '', '', B)).toEqual({ route: 'dashboard', redirect: null });
  });

  it('redirects the addresses renamed by the new navigation, keeping the query', () => {
    expect(resolve(`${B}/upstreams`, '', '', B)).toEqual({ route: 'providers', redirect: `${B}/providers` });
    expect(resolve(`${B}/audit`, '?x=1', '', B)).toEqual({ route: 'requests', redirect: `${B}/requests?x=1` });
    expect(ALIASES.audit).toBe('requests');
    expect(resolve(`${B}/policies`, '', '', B)).toEqual({ route: 'flow', redirect: `${B}/flow` });
    expect(resolve(`${B}/`, '', '#/policies', B)).toEqual({ route: 'flow', redirect: `${B}/flow` });
  });

  it('opens the invite page and the account page of a link return', () => {
    expect(resolve(`${B}/invite`, '?token=inv_1', '', B)).toEqual({ route: 'invite', redirect: null });
    // N15 builds that return to #/account?link_code= reach the path with the code in the query.
    expect(resolve(`${B}/`, '', '#/account?link_code=c1', B)).toEqual({ route: 'account', redirect: `${B}/account?link_code=c1` });
  });

  it('redirects #/page links to the path, including renamed pages', () => {
    expect(resolve(`${B}/`, '', '#/flow', B)).toEqual({ route: 'flow', redirect: `${B}/flow` });
    expect(resolve(`${B}/`, '', '#/upstreams', B)).toEqual({ route: 'providers', redirect: `${B}/providers` });
    expect(resolve(`${B}/`, '', '#/flow?policy=p1', B)).toEqual({ route: 'flow', redirect: `${B}/flow?policy=p1` });
    expect(resolve(`${B}/`, '', '#/admin/users', B)).toEqual({ route: 'admin-users', redirect: `${B}/admin/users` });
  });

  it('keeps the SSO callback as a hash route (the code stays out of server logs)', () => {
    expect(resolve(`${B}/`, '', '#/auth/callback?code=abc', B)).toEqual({ route: 'auth-callback', redirect: null });
    expect(resolve(`${B}/`, '', '#/auth/callback', B)).toEqual({ route: 'auth-callback', redirect: null });
  });

  it('has a route for every nav item, each listed once', () => {
    const routes = NAV.flatMap((g) => g.items.map((i) => i.route));
    expect(new Set(routes).size).toBe(routes.length);
    for (const r of routes) expect(ROUTES).toContain(r);
  });
});
