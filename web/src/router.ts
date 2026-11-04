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

export function navigate(route: Route, replace = false): void {
  const url = href(route);
  if (window.location.pathname === url) return;
  if (replace) window.history.replaceState(null, '', url);
  else window.history.pushState(null, '', url);
  window.dispatchEvent(new PopStateEvent('popstate'));
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
