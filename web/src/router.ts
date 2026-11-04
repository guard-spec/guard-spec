// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// A small history router under the Vite base (/ui/). The control plane
// serves index.html for every path under /ui/.

import { useEffect, useState } from 'react';

const BASE = import.meta.env.BASE_URL.replace(/\/$/, '');

export type Route = 'flow' | 'upstreams' | 'config' | 'guard' | 'keys' | 'projects' | 'exemplars' | 'audit' | 'orgs' | 'login';

export const ROUTES: readonly Route[] = ['flow', 'upstreams', 'config', 'guard', 'keys', 'projects', 'exemplars', 'audit', 'orgs', 'login'];

function current(): Route {
  const path = window.location.pathname.startsWith(BASE) ? window.location.pathname.slice(BASE.length) : window.location.pathname;
  const seg = path.replace(/^\/+/, '').split('/')[0] ?? '';
  return (ROUTES as readonly string[]).includes(seg) ? (seg as Route) : 'flow';
}

export function href(route: Route): string {
  return `${BASE}/${route}`;
}

/** Goes to a page; params become the query string (e.g. a policy to focus). */
export function navigate(route: Route, replace = false, params?: Record<string, string>): void {
  const q = params ? new URLSearchParams(params).toString() : '';
  const url = href(route) + (q ? `?${q}` : '');
  if (window.location.pathname + window.location.search === url) return;
  if (replace) window.history.replaceState(null, '', url);
  else window.history.pushState(null, '', url);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

/** Reads and removes a query parameter of the current page. */
export function takeParam(name: string): string | null {
  const params = new URLSearchParams(window.location.search);
  const v = params.get(name);
  if (v !== null) {
    params.delete(name);
    const q = params.toString();
    window.history.replaceState(null, '', window.location.pathname + (q ? `?${q}` : ''));
  }
  return v;
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(current);
  useEffect(() => {
    const on = () => setRoute(current());
    window.addEventListener('popstate', on);
    return () => window.removeEventListener('popstate', on);
  }, []);
  return route;
}
