// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// A small history router under the Vite base (/ui/). The control plane
// serves index.html for every path under /ui/.
//
// Old addresses keep working: the pages renamed by the new navigation
// (upstreams, audit) and #/page hash links redirect to their page. The SSO
// callback is the one hash route: /ui/#/auth/callback?code=… (identity
// contract §2), so the one-time code never reaches a server log.
//
// A page with unsaved work can set a navigation guard: links, navigate() and
// the browser's back and forward buttons then ask it first.

import { useEffect, useState } from 'react';

const BASE = import.meta.env.BASE_URL.replace(/\/$/, '');
const CHANGED = 'gs:route';
/** The window event sent after an in-app navigation. */
export const ROUTE_CHANGED = CHANGED;

export const PATHS = {
  dashboard: 'dashboard',
  flow: 'flow',
  guard: 'guard',
  exemplars: 'exemplars',
  simulator: 'simulator',
  providers: 'providers',
  projects: 'projects',
  models: 'models',
  requests: 'requests',
  activity: 'activity',
  members: 'members',
  roles: 'roles',
  keys: 'keys',
  security: 'security',
  config: 'config',
  organization: 'organization',
  'alert-rules': 'alerts/rules',
  'alert-channels': 'alerts/channels',
  'alert-groups': 'alerts/groups',
  'alert-history': 'alerts/history',
  'alert-deliveries': 'alerts/deliveries',
  'admin-users': 'admin/users',
  'admin-idps': 'admin/identity-providers',
  'admin-activity': 'admin/activity',
  account: 'account',
  invite: 'invite',
  orgs: 'orgs',
  login: 'login',
  'auth-callback': 'auth/callback',
} as const;

export type Route = keyof typeof PATHS;
export const ROUTES = Object.keys(PATHS) as Route[];

/** Addresses of the first admin UI, and short forms, that now live elsewhere. */
export const ALIASES: Readonly<Record<string, Route>> = {
  upstreams: 'providers',
  audit: 'requests',
  policies: 'flow',
  'audit-log': 'requests',
  users: 'members',
  settings: 'organization',
  profile: 'account',
  alerts: 'alert-rules',
  notifications: 'alert-history',
};

export const DEFAULT_ROUTE: Route = 'dashboard';

export interface Resolved {
  route: Route;
  /** Set when the address is an old one: replace it with this URL. */
  redirect: string | null;
}

const BY_PATH = new Map<string, Route>(ROUTES.map((r) => [PATHS[r], r]));

/** Maps an address to its page; pure, for tests (base is the Vite base without the trailing slash). */
export function resolve(pathname: string, search: string, hash: string, base: string): Resolved {
  if (/^#\/auth\/callback(\?|$)/.test(hash)) return { route: 'auth-callback', redirect: null };
  // A #/page link of an older bookmark: the same page as a path.
  const hm = /^#\/([^?]*)(\?.*)?$/.exec(hash);
  if (hm) {
    const inner = resolve(`${base}/${hm[1] ?? ''}`, hm[2] ?? '', '', base);
    return { route: inner.route, redirect: `${base}/${PATHS[inner.route]}${hm[2] ?? ''}` };
  }
  const rel = (pathname.startsWith(base) ? pathname.slice(base.length) : pathname).replace(/^\/+|\/+$/g, '');
  const exact = BY_PATH.get(rel);
  if (exact) return { route: exact, redirect: null };
  const alias = ALIASES[rel] ?? ALIASES[rel.split('/')[0] ?? ''];
  if (alias) return { route: alias, redirect: `${base}/${PATHS[alias]}${search}` };
  return { route: DEFAULT_ROUTE, redirect: null };
}

function current(): Route {
  const r = resolve(window.location.pathname, window.location.search, window.location.hash, BASE);
  if (r.redirect) {
    window.history.replaceState(null, '', r.redirect);
    shown = r.redirect;
  }
  return r.route;
}

export function href(route: Route): string {
  return `${BASE}/${PATHS[route]}`;
}

/**
 * Asked before leaving the page. Return true to hold the navigation, and
 * call proceed later to complete it (after a confirmation, for instance).
 */
export type NavigationGuard = (proceed: () => void) => boolean;

let guard: NavigationGuard | null = null;
// The URL the app shows, to undo a back or forward the guard holds.
let shown = typeof window === 'undefined' ? '' : window.location.pathname + window.location.search;

export function setNavigationGuard(g: NavigationGuard | null): void {
  guard = g;
}

function go(url: string, replace: boolean): void {
  if (replace) window.history.replaceState(null, '', url);
  else window.history.pushState(null, '', url);
  shown = url;
  window.dispatchEvent(new Event(CHANGED));
}

/**
 * Goes to a page; params become the query string (e.g. a policy to focus).
 * force skips the navigation guard (logging out).
 */
export function navigate(route: Route, replace = false, params?: Record<string, string>, force = false): void {
  const q = params ? new URLSearchParams(params).toString() : '';
  const url = href(route) + (q ? `?${q}` : '');
  if (window.location.pathname + window.location.search === url && !window.location.hash) return;
  if (!force && guard?.(() => go(url, replace))) return;
  go(url, replace);
}

/** onClick of an <a href={href(route)}>: an in-app navigation, unless opened in a new tab. */
export function onLink(route: Route, params?: Record<string, string>) {
  return (e: { metaKey: boolean; ctrlKey: boolean; shiftKey: boolean; button: number; preventDefault: () => void }) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(route, false, params);
  };
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', () => {
    const target = window.location.pathname + window.location.search;
    if (target === shown) return;
    if (guard) {
      // Back or forward: stay until the guard lets go. (Chrome also sends the
      // history step to an open dialog as a close request; Dialog ignores it.)
      window.history.pushState(null, '', shown);
      if (!guard(() => go(target, false))) go(target, false);
      return;
    }
    shown = target;
    window.dispatchEvent(new Event(CHANGED));
  });
}

/** Reads and removes a query parameter of the current page. */
export function takeParam(name: string): string | null {
  const params = new URLSearchParams(window.location.search);
  const v = params.get(name);
  if (v !== null) {
    params.delete(name);
    const q = params.toString();
    shown = window.location.pathname + (q ? `?${q}` : '');
    window.history.replaceState(null, '', shown);
  }
  return v;
}

/** Removes the #/auth/callback hash (and its one-time code) from the address bar. */
export function clearHash(): void {
  shown = window.location.pathname + window.location.search;
  window.history.replaceState(null, '', shown);
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(current);
  useEffect(() => {
    const on = () => setRoute(current());
    window.addEventListener(CHANGED, on);
    window.addEventListener('hashchange', on);
    return () => {
      window.removeEventListener(CHANGED, on);
      window.removeEventListener('hashchange', on);
    };
  }, []);
  return route;
}
