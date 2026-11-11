// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { fold, isPaletteShortcut, matchItems, moveActive, type PaletteItem } from './palette';

const item = (id: string, label: string, kind: PaletteItem['kind'] = 'page', hint = ''): PaletteItem => ({ id, kind, label, hint, route: 'dashboard' });

describe('command palette', () => {
  it('folds case and Vietnamese diacritics', () => {
    expect(fold('Chính sách Đường')).toBe('chinh sach duong');
  });

  it('ranks labels that start with the query first, pages before objects', () => {
    const items = [
      item('a', 'Request log'),
      item('b', 'Policy flow'),
      item('c', 'flow-test', 'policy', 'Policy flow'),
      item('d', 'Policy history'),
      item('e', 'Luồng chính sách'),
    ];
    expect(matchItems(items, 'flow').map((i) => i.id)).toEqual(['c', 'b']);
    expect(matchItems(items, 'pol').map((i) => i.id)).toEqual(['b', 'd', 'c']);
    expect(matchItems(items, 'chinh sach').map((i) => i.id)).toEqual(['e']);
    expect(matchItems(items, 'policy hist').map((i) => i.id)).toEqual(['d']);
    expect(matchItems(items, '').map((i) => i.id)).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(matchItems(items, 'zzz')).toEqual([]);
  });

  it('moves the active option with the arrows, wrapping around', () => {
    expect(moveActive(-1, 3, 'ArrowDown')).toBe(0);
    expect(moveActive(2, 3, 'ArrowDown')).toBe(0);
    expect(moveActive(0, 3, 'ArrowUp')).toBe(2);
    expect(moveActive(1, 3, 'End')).toBe(2);
    expect(moveActive(1, 0, 'ArrowDown')).toBe(-1);
  });

  it('opens on Ctrl+K and Cmd+K only', () => {
    const k = { key: 'k', ctrlKey: false, metaKey: false, altKey: false, shiftKey: false };
    expect(isPaletteShortcut({ ...k, ctrlKey: true })).toBe(true);
    expect(isPaletteShortcut({ ...k, metaKey: true, key: 'K' })).toBe(true);
    expect(isPaletteShortcut(k)).toBe(false);
    expect(isPaletteShortcut({ ...k, ctrlKey: true, shiftKey: true })).toBe(false);
  });
});
