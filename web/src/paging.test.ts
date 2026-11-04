// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { currentCursor, hasNext, initialPaged, normalizePage, pagedReducer, rangeOf, visibleRows, type PagedState } from './paging';

const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: i + 1 }));

describe('normalizePage', () => {
  it('reads the envelope of the contract', () => {
    expect(normalizePage({ items: [{ id: 1 }], next_cursor: 'abc', total: 9 })).toEqual({ items: [{ id: 1 }], nextCursor: 'abc', total: 9, clientSide: false });
  });

  it('treats a null or empty cursor as the last page and total as optional', () => {
    expect(normalizePage({ items: [], next_cursor: null })).toMatchObject({ nextCursor: null, total: null, clientSide: false });
    expect(normalizePage({ items: [], next_cursor: '' }).nextCursor).toBeNull();
  });

  it('accepts the older {data} shape and plain arrays as one client-side list', () => {
    expect(normalizePage({ data: rows(3), version: 1 })).toEqual({ items: rows(3), nextCursor: null, total: 3, clientSide: true });
    expect(normalizePage(rows(2))).toEqual({ items: rows(2), nextCursor: null, total: 2, clientSide: true });
  });

  it('survives an empty or odd body', () => {
    expect(normalizePage(undefined).items).toEqual([]);
    expect(normalizePage({ error: 'x' }).items).toEqual([]);
  });
});

describe('pagedReducer, server mode', () => {
  const loaded = (s: PagedState<{ id: number }>, items: { id: number }[], next: string | null) =>
    pagedReducer(s, { type: 'loaded', page: { items, nextCursor: next, total: null, clientSide: false } });

  it('walks forward with the cursor and back with the cursor stack', () => {
    let s = loaded(initialPaged(25), rows(25), 'c1');
    expect(currentCursor(s)).toBeNull();
    expect(hasNext(s)).toBe(true);
    s = pagedReducer(s, { type: 'next' });
    expect(s.loading).toBe(true);
    expect(currentCursor(s)).toBe('c1');
    s = loaded(s, rows(10), null);
    expect(hasNext(s)).toBe(false);
    expect(rangeOf(s)).toEqual({ from: 26, to: 35, total: null });
    s = pagedReducer(s, { type: 'next' }); // no next page: unchanged
    expect(s.page).toBe(1);
    s = pagedReducer(s, { type: 'prev' });
    expect(s.page).toBe(0);
    expect(currentCursor(s)).toBeNull();
    s = pagedReducer(s, { type: 'prev' });
    expect(s.page).toBe(0);
  });

  it('starts over with a new page size and keeps rows while reloading', () => {
    let s = loaded(initialPaged(25), rows(25), 'c1');
    s = pagedReducer(s, { type: 'next' });
    s = pagedReducer(s, { type: 'reset', pageSize: 100 });
    expect(s.pageSize).toBe(100);
    expect(s.page).toBe(0);
    expect(s.cursors).toEqual([null]);
    expect(s.rows).toHaveLength(25);
  });

  it('marks a missing endpoint as unavailable and other errors as errors', () => {
    let s = pagedReducer(initialPaged(25), { type: 'failed', error: 'HTTP 404', notFound: true });
    expect(s).toMatchObject({ unavailable: true, loading: false, rows: [] });
    s = pagedReducer(initialPaged(25), { type: 'failed', error: 'boom', notFound: false });
    expect(s).toMatchObject({ unavailable: false, error: 'boom' });
  });
});

describe('pagedReducer, client mode (older endpoints)', () => {
  it('pages through a whole list in the browser', () => {
    let s = pagedReducer(initialPaged<{ id: number }>(25), { type: 'loaded', page: normalizePage({ data: rows(60) }) });
    expect(visibleRows(s)).toHaveLength(25);
    expect(rangeOf(s)).toEqual({ from: 1, to: 25, total: 60 });
    s = pagedReducer(s, { type: 'next' });
    s = pagedReducer(s, { type: 'next' });
    expect(s.loading).toBe(false); // no fetch
    expect(currentCursor(s)).toBeNull();
    expect(visibleRows(s).map((r) => r.id)).toEqual([51, 52, 53, 54, 55, 56, 57, 58, 59, 60]);
    expect(hasNext(s)).toBe(false);
    expect(rangeOf(s)).toEqual({ from: 51, to: 60, total: 60 });
  });

  it('clamps the page when a reload returns fewer rows', () => {
    let s = pagedReducer(initialPaged<{ id: number }>(25), { type: 'loaded', page: normalizePage(rows(60)) });
    s = pagedReducer(s, { type: 'next' });
    s = pagedReducer(s, { type: 'next' });
    s = pagedReducer(s, { type: 'loaded', page: normalizePage(rows(30)) });
    expect(s.page).toBe(1);
    expect(visibleRows(s)).toHaveLength(5);
  });

  it('shows an empty range for an empty list', () => {
    const s = pagedReducer(initialPaged(25), { type: 'loaded', page: normalizePage([]) });
    expect(rangeOf(s)).toEqual({ from: 0, to: 0, total: 0 });
    expect(hasNext(s)).toBe(false);
  });
});
