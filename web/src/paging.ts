// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Cursor pagination (identity contract §0). The UI always sends limit; a
// control plane that knows the contract answers {items, next_cursor, total}.
// Older endpoints answer {data: [...]} or a plain array with every row: the
// UI then pages through them in the browser, so every table pages the same.

export const PAGE_SIZES = [25, 50, 100] as const;
export type PageSize = (typeof PAGE_SIZES)[number];

export interface NormalizedPage<T> {
  items: T[];
  nextCursor: string | null;
  total: number | null;
  /** total is a lower bound (the server stopped counting): show "N+". */
  totalCapped?: boolean;
  /** The server sent every row (no envelope): page in the browser. */
  clientSide: boolean;
}

/** Accepts the envelope, {data: [...]} and a plain array. */
export function normalizePage<T>(raw: unknown): NormalizedPage<T> {
  if (Array.isArray(raw)) return { items: raw as T[], nextCursor: null, total: raw.length, clientSide: true };
  if (raw && typeof raw === 'object') {
    const o = raw as { items?: unknown; next_cursor?: unknown; total?: unknown; total_capped?: unknown; data?: unknown };
    if (Array.isArray(o.items)) {
      return {
        items: o.items as T[],
        nextCursor: typeof o.next_cursor === 'string' && o.next_cursor !== '' ? o.next_cursor : null,
        total: typeof o.total === 'number' ? o.total : null,
        totalCapped: o.total_capped === true,
        clientSide: false,
      };
    }
    if (Array.isArray(o.data)) {
      return { items: o.data as T[], nextCursor: null, total: o.data.length, clientSide: true };
    }
  }
  return { items: [], nextCursor: null, total: 0, clientSide: true };
}

export interface PagedState<T> {
  pageSize: PageSize;
  /** The cursor that loaded each visited page; [null] is the first page. */
  cursors: (string | null)[];
  page: number;
  /** Rows of the current server page, or every row when clientSide. */
  rows: T[];
  nextCursor: string | null;
  total: number | null;
  totalCapped?: boolean;
  clientSide: boolean;
  loading: boolean;
  error: string | null;
  /** The endpoint does not exist on this control plane (404). */
  unavailable: boolean;
  /** The caller's role may not read this list (403). */
  forbidden: boolean;
}

export type PagedEvent<T> =
  | { type: 'reset'; pageSize?: PageSize }
  | { type: 'loading' }
  | { type: 'loaded'; page: NormalizedPage<T> }
  | { type: 'failed'; error: string; notFound: boolean; forbidden?: boolean }
  | { type: 'next' }
  | { type: 'prev' };

export function initialPaged<T>(pageSize: PageSize = 25): PagedState<T> {
  return {
    pageSize,
    cursors: [null],
    page: 0,
    rows: [],
    nextCursor: null,
    total: null,
    clientSide: false,
    loading: true,
    error: null,
    unavailable: false,
    forbidden: false,
  };
}

/**
 * The paging state machine. next and prev in server mode change the cursor
 * (the hook then fetches); in client mode they only move the window.
 */
export function pagedReducer<T>(s: PagedState<T>, e: PagedEvent<T>): PagedState<T> {
  switch (e.type) {
    case 'reset':
      return { ...initialPaged<T>(e.pageSize ?? s.pageSize), rows: s.rows };
    case 'loading':
      return { ...s, loading: true };
    case 'loaded':
      return {
        ...s,
        loading: false,
        error: null,
        unavailable: false,
        forbidden: false,
        rows: e.page.items,
        nextCursor: e.page.nextCursor,
        total: e.page.total,
        totalCapped: e.page.totalCapped === true,
        clientSide: e.page.clientSide,
        // A client-side list is one fetch: page 0 of the server.
        cursors: e.page.clientSide ? [null] : s.cursors,
        page: e.page.clientSide ? Math.min(s.page, Math.max(0, Math.ceil(e.page.items.length / s.pageSize) - 1)) : s.page,
      };
    case 'failed':
      return { ...s, loading: false, error: e.error, unavailable: e.notFound, forbidden: e.forbidden === true, rows: e.notFound || e.forbidden ? [] : s.rows };
    case 'next':
      if (!hasNext(s)) return s;
      if (s.clientSide) return { ...s, page: s.page + 1 };
      return { ...s, page: s.page + 1, cursors: [...s.cursors.slice(0, s.page + 1), s.nextCursor], loading: true };
    case 'prev':
      if (s.page === 0) return s;
      return s.clientSide ? { ...s, page: s.page - 1 } : { ...s, page: s.page - 1, loading: true };
  }
}

export function hasNext<T>(s: PagedState<T>): boolean {
  if (s.clientSide) return (s.page + 1) * s.pageSize < s.rows.length;
  return s.nextCursor !== null;
}

/** The cursor to fetch the current page with. */
export function currentCursor<T>(s: PagedState<T>): string | null {
  return s.clientSide ? null : (s.cursors[s.page] ?? null);
}

/** The rows on screen. */
export function visibleRows<T>(s: PagedState<T>): T[] {
  return s.clientSide ? s.rows.slice(s.page * s.pageSize, (s.page + 1) * s.pageSize) : s.rows;
}

/** "26–50 of 120" numbers: first and last row shown (1-based) and the total when known. */
export function rangeOf<T>(s: PagedState<T>): { from: number; to: number; total: number | null; capped: boolean } {
  const shown = visibleRows(s).length;
  const from = shown === 0 ? 0 : s.page * s.pageSize + 1;
  return { from, to: from === 0 ? 0 : from + shown - 1, total: s.clientSide ? s.rows.length : s.total, capped: !s.clientSide && s.totalCapped === true };
}
