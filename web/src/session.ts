// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The session token lives in sessionStorage (gone when the tab closes).
// Preferences and recently opened org ids (not secret) live in localStorage.

const TOKEN = 'gs.token';
const ORG = 'gs.org';
const RECENT = 'gs.recentOrgs';

function get(store: Storage | undefined, key: string): string | null {
  try {
    return store?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function set(store: Storage | undefined, key: string, value: string | null): void {
  try {
    if (value === null) store?.removeItem(key);
    else store?.setItem(key, value);
  } catch {
    // Storage blocked: the session lasts until reload.
  }
}

const ss = typeof sessionStorage === 'undefined' ? undefined : sessionStorage;
const ls = typeof localStorage === 'undefined' ? undefined : localStorage;

export const session = {
  token: () => get(ss, TOKEN),
  setToken: (t: string | null) => set(ss, TOKEN, t),
  orgId: () => get(ss, ORG),
  setOrgId: (id: string | null) => set(ss, ORG, id),
  clear: () => {
    set(ss, TOKEN, null);
    set(ss, ORG, null);
  },
};

export interface RecentOrg {
  id: string;
  name: string;
}

export const prefs = {
  get: (key: string) => get(ls, `gs.${key}`),
  set: (key: string, value: string) => set(ls, `gs.${key}`, value),
  recentOrgs(): RecentOrg[] {
    try {
      const v = JSON.parse(get(ls, RECENT) ?? '[]') as unknown;
      return Array.isArray(v) ? (v as RecentOrg[]).filter((o) => typeof o.id === 'string').slice(0, 5) : [];
    } catch {
      return [];
    }
  },
  clearRecentOrgs() {
    set(ls, RECENT, null);
  },
  addRecentOrg(o: RecentOrg) {
    const list = [o, ...prefs.recentOrgs().filter((r) => r.id !== o.id)].slice(0, 5);
    set(ls, RECENT, JSON.stringify(list));
  },
};
