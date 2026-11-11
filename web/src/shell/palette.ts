// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The command palette's items and matching (RF-a1dbafea U4).

import type { Route } from '../router';

export type PaletteKind = 'page' | 'policy' | 'project' | 'provider' | 'key';

export interface PaletteItem {
  id: string;
  kind: PaletteKind;
  label: string;
  /** A second line: the page's group, or the object's page. */
  hint: string;
  route: Route;
  params?: Record<string, string>;
}

/** Lower case without diacritics, so "chinh sach" finds "Chính sách". */
export function fold(s: string): string {
  return s
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase();
}

/**
 * The items matching query, best first: a label that starts with it, then a
 * word of the label that does, then the label or hint containing it; pages
 * before objects at equal rank. Every word of the query must match.
 */
export function matchItems(items: readonly PaletteItem[], query: string, limit = 50): PaletteItem[] {
  const words = fold(query).split(/\s+/).filter(Boolean);
  if (words.length === 0) return items.slice(0, limit);
  const scored: { item: PaletteItem; rank: number; i: number }[] = [];
  items.forEach((item, i) => {
    const label = fold(item.label);
    const all = `${label} ${fold(item.hint)}`;
    if (!words.every((w) => all.includes(w))) return;
    const q = words.join(' ');
    const rank = label.startsWith(q) ? 0 : label.split(/[\s/._-]+/).some((w) => w.startsWith(words[0] ?? '')) ? 1 : 2;
    scored.push({ item, rank: rank * 2 + (item.kind === 'page' ? 0 : 1), i });
  });
  scored.sort((a, b) => a.rank - b.rank || a.i - b.i);
  return scored.slice(0, limit).map((s) => s.item);
}

/** The next active index for an arrow key, wrapping around; -1 for none. */
export function moveActive(active: number, count: number, key: 'ArrowDown' | 'ArrowUp' | 'Home' | 'End'): number {
  if (count === 0) return -1;
  switch (key) {
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    case 'ArrowDown':
      return active < 0 ? 0 : (active + 1) % count;
    case 'ArrowUp':
      return active <= 0 ? count - 1 : active - 1;
  }
}

/** Whether a key event opens the palette: Ctrl+K, or Cmd+K on a Mac. */
export function isPaletteShortcut(e: { key: string; ctrlKey: boolean; metaKey: boolean; altKey: boolean; shiftKey: boolean }): boolean {
  return e.key.toLowerCase() === 'k' && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
}
