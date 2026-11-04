// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useReducer, useRef } from 'react';
import { isNotFound } from '../api';
import { errorText } from '../context';
import {
  currentCursor,
  hasNext,
  initialPaged,
  normalizePage,
  pagedReducer,
  rangeOf,
  visibleRows,
  type PagedState,
  type PageSize,
} from '../paging';

export interface PageQuery {
  limit: number;
  cursor?: string;
}

export interface UsePaged<T> {
  rows: T[];
  state: PagedState<T>;
  hasNext: boolean;
  hasPrev: boolean;
  range: { from: number; to: number; total: number | null };
  next: () => void;
  prev: () => void;
  setPageSize: (n: PageSize) => void;
  reload: () => Promise<void>;
}

/**
 * Loads a list page by page. fetchPage is a memoized loader (useCallback)
 * returning the raw response; when it changes (new filters), paging starts
 * over. clientFilter narrows lists that an older endpoint sent whole.
 */
export function usePaged<T>(
  fetchPage: (q: PageQuery) => Promise<unknown>,
  opts: { pageSize?: PageSize; clientFilter?: (row: T) => boolean } = {},
): UsePaged<T> {
  const [state, dispatch] = useReducer(pagedReducer<T>, opts.pageSize ?? 25, (n: PageSize) => initialPaged<T>(n));
  const filterRef = useRef(opts.clientFilter);
  // Before the load effect below, which reads it.
  useEffect(() => {
    filterRef.current = opts.clientFilter;
  });
  const seq = useRef(0);
  const cursor = currentCursor(state);

  const load = useCallback(
    async (c: string | null, limit: number) => {
      const my = ++seq.current;
      dispatch({ type: 'loading' });
      try {
        const raw = await fetchPage(c ? { limit, cursor: c } : { limit });
        if (my !== seq.current) return;
        const page = normalizePage<T>(raw);
        const f = filterRef.current;
        if (page.clientSide && f) page.items = page.items.filter(f);
        dispatch({ type: 'loaded', page });
      } catch (e) {
        if (my !== seq.current) return;
        dispatch({ type: 'failed', error: errorText(e), notFound: isNotFound(e) });
      }
    },
    [fetchPage],
  );

  // A new loader (filters changed) starts at the first page.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    dispatch({ type: 'reset' });
  }, [fetchPage]);

  // Client-side paging keeps the cursor at null, so moving pages fetches nothing.
  useEffect(() => {
    void load(cursor, state.pageSize);
  }, [load, cursor, state.pageSize]);

  const reload = useCallback(() => load(cursor, state.pageSize), [load, cursor, state.pageSize]);

  return {
    rows: visibleRows(state),
    state,
    hasNext: hasNext(state),
    hasPrev: state.page > 0,
    range: rangeOf(state),
    next: () => dispatch({ type: 'next' }),
    prev: () => dispatch({ type: 'prev' }),
    setPageSize: (n) => dispatch({ type: 'reset', pageSize: n }),
    reload,
  };
}
