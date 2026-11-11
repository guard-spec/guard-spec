// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Saved filters of the request log (RF-a1dbafea U4): named action and search
// filters, per organization, in this browser.

import { prefs } from '../session';

export interface SavedFilter {
  name: string;
  action: string;
  q: string;
}

/** At most this many per organization. */
export const MAX_FILTERS = 20;

const key = (orgId: string) => `requests.filters.${orgId}`;

function valid(x: unknown): x is SavedFilter {
  const f = x as Partial<SavedFilter> | null;
  return typeof f?.name === 'string' && f.name.trim() !== '' && typeof f.action === 'string' && typeof f.q === 'string';
}

export function loadFilters(orgId: string): SavedFilter[] {
  try {
    const v = JSON.parse(prefs.get(key(orgId)) ?? '[]') as unknown;
    return Array.isArray(v) ? v.filter(valid).slice(0, MAX_FILTERS) : [];
  } catch {
    return [];
  }
}

export function storeFilters(orgId: string, list: readonly SavedFilter[]): void {
  prefs.set(key(orgId), JSON.stringify(list.slice(0, MAX_FILTERS)));
}

/** Adds f, replacing a filter of the same name; newest first. */
export function withFilter(list: readonly SavedFilter[], f: SavedFilter): SavedFilter[] {
  const name = f.name.trim();
  return [{ ...f, name }, ...list.filter((x) => x.name !== name)].slice(0, MAX_FILTERS);
}

export function withoutFilter(list: readonly SavedFilter[], name: string): SavedFilter[] {
  return list.filter((x) => x.name !== name);
}

/** The saved filter the page shows now, if any. */
export function currentFilter(list: readonly SavedFilter[], action: string, q: string): SavedFilter | undefined {
  return list.find((x) => x.action === action && x.q === q);
}
