// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// A small history router under the Vite base (/ui/). The control plane
// serves index.html for every path under /ui/.
//
// A page with unsaved work can set a navigation guard: links, navigate() and
// the browser's back and forward buttons then ask it first.

import { useEffect, useState } from 'react';

const BASE = import.meta.env.BASE_URL.replace(/\/$/, '');
const CHANGED = 'gs:route';

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
  if (window.location.pathname + window.location.search === url) return;
  if (!force && guard?.(() => go(url, replace))) return;
  go(url, replace);
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

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(current);
  useEffect(() => {
    const on = () => setRoute(current());
    window.addEventListener(CHANGED, on);
    return () => window.removeEventListener(CHANGED, on);
  }, []);
  return route;
}
