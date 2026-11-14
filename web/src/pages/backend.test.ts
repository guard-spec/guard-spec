// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi as viMessages } from '../i18n/vi';
import { BUILTIN_CATALOG, defaultBackend, jsonPathError, prefixValid, validateBackend } from './providerCatalog';

// The same cases as internal/jsonpath and internal/backend, so that the form
// refuses what the control plane refuses.
describe('custom backend JSONPath', () => {
  it('accepts the subset', () => {
    for (const p of ['$', '$.query', '$.messages[*].content', '$.items[0].text', '$.a.b-c.d_e', '$[*]', '$.*', '$.data[12][*].x']) {
      expect(jsonPathError(p), p).toBeNull();
    }
  });

  it('refuses the rest, with a reason', () => {
    const cases: [string, string][] = [
      ['query', 'start'],
      ['', 'start'],
      ['$..query', 'descent'],
      ['$.', 'name'],
      ['$.a b', 'name'],
      ['$[', 'bracket'],
      ["$['a']", 'bracket'],
      ['$[?(@.x)]', 'bracket'],
      ['$[1:2]', 'bracket'],
      ['$[-1]', 'bracket'],
      ['$[01]', 'index'],
      ['$[99999999999]', 'index'],
      ['$' + '.a'.repeat(33), 'length'],
      ['$.' + 'a'.repeat(300), 'length'],
    ];
    for (const [p, reason] of cases) expect(jsonPathError(p), p).toBe(reason);
  });
});

describe('custom backend configuration', () => {
  it('accepts the default and a full one', () => {
    expect(validateBackend(defaultBackend())).toEqual({});
    expect(
      validateBackend({
        path_prefixes: ['/api/v1/', '/orders'],
        methods: ['GET', 'POST'],
        key_header: 'X-Api-Key',
        scan: { request: ['$.query', ''], response: ['$.results[*].snippet'], all_strings: false, raw_text: true },
      }),
    ).toEqual({});
    expect(validateBackend({ path_prefixes: ['/'], methods: ['POST'], scan: { request: [], response: [], all_strings: true, raw_text: false } })).toEqual({});
  });

  it('names what is wrong', () => {
    const b = defaultBackend();
    expect(validateBackend({ ...b, path_prefixes: [] })).toEqual({ prefixes: { path: undefined } });
    expect(validateBackend({ ...b, path_prefixes: ['/ok', 'orders'] })).toEqual({ prefixes: { path: 'orders' } });
    expect(validateBackend({ ...b, methods: [] })).toEqual({ methods: {} });
    expect(validateBackend({ ...b, key_header: 'Host' })).toEqual({ keyHeader: {} });
    expect(validateBackend({ ...b, scan: { ...b.scan, request: ['$.ok', '$..bad'] } })).toEqual({ request: { path: '$..bad', reason: 'descent' } });
    expect(validateBackend({ ...b, scan: { ...b.scan, response: ['x'] } })).toEqual({ response: { path: 'x', reason: 'start' } });
    expect(validateBackend({ ...b, scan: { ...b.scan, request: [' '] } })).toEqual({ scan: {} });
    expect(validateBackend(null)).toEqual({ scan: {} });
  });

  it('checks prefixes like the control plane', () => {
    for (const p of ['/', '/search', '/api/v1/', '/a.b/c~d']) expect(prefixValid(p), p).toBe(true);
    for (const p of ['search', '/a/../b', '/a/./b', '/a//b', '/a?b', '/a b', '/' + 'a'.repeat(300)]) expect(prefixValid(p), p).toBe(false);
  });

  it('is in the built-in catalog and has messages in both languages', () => {
    expect(BUILTIN_CATALOG.some((c) => c.id === 'custom')).toBe(true);
    for (const k of Object.keys(en).filter((k) => k.startsWith('prov.backend') || k.startsWith('prov.jsonPath.'))) {
      const key = k as keyof typeof en;
      expect(viMessages[key], k).toBeTruthy();
      expect(viMessages[key], k).not.toBe(en[key]);
    }
  });
});
