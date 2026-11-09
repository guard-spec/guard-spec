// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The help metadata covers what the backend declares: every CEL variable of
// internal/policy (fieldTypes) has a group, an example and its texts in both
// languages, and the fallback schema matches the backend's.

import { describe, expect, it } from 'vitest';
import policyGo from '../../../internal/policy/policy.go?raw';
import schemaGo from '../../../internal/policy/schema.go?raw';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import { filterFields } from './FieldPicker';
import { allHelpKeys, descKey, FIELD_GROUPS, groupFields, OPERATORS, rangeKey, VARIABLES, whenKey } from './help';
import { FALLBACK_SCHEMA } from './schema';

/** The body of a Go map literal `var name = map[...]...{ ... }`. */
function goMap(src: string, name: string): string {
  const start = src.indexOf(`var ${name} = map[`);
  expect(start, `${name} in the Go source`).toBeGreaterThanOrEqual(0);
  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    if (src[i] === '}' && --depth === 0) return src.slice(open + 1, i);
  }
  throw new Error(`unterminated ${name}`);
}

// Computed keys may be missing at run time: the test is what checks them.
const EN: Readonly<Record<string, string | undefined>> = en;
const VI: Readonly<Record<string, string | undefined>> = vi;

const CEL_TYPES: Record<string, string> = { DoubleType: 'double', IntType: 'int', StringType: 'string', BoolType: 'bool' };

/** internal/policy fieldTypes: name -> schema type. */
function backendFields(): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of goMap(policyGo, 'fieldTypes').matchAll(/"([^"]+)":\s*(?:cel\.(\w+)|listOfStrings)/g)) {
    out.set(m[1] ?? '', CEL_TYPES[m[2] ?? ''] ?? 'list');
  }
  return out;
}

describe('help metadata', () => {
  const fields = backendFields();

  it('reads the backend variable list', () => {
    expect(fields.size).toBeGreaterThanOrEqual(16);
    expect(fields.get('injection.score')).toBe('double');
    expect(fields.get('mcp.is_tool_response')).toBe('bool');
    expect(fields.get('input.pii.kinds')).toBe('list');
    expect(fields.get('input.pii.count')).toBe('int');
    expect(fields.get('input.unscanned.kinds')).toBe('list');
    expect(fields.get('input.unscanned.count')).toBe('int');
  });

  it('has help for every backend variable, and only for those', () => {
    expect(Object.keys(VARIABLES).sort()).toEqual([...fields.keys()].sort());
  });

  it('has every help text in English and Vietnamese', () => {
    for (const name of fields.keys()) {
      for (const key of [descKey(name), rangeKey(name), whenKey(name)]) {
        expect(EN[key]?.trim(), `en ${key}`).toBeTruthy();
        expect(VI[key]?.trim(), `vi ${key}`).toBeTruthy();
      }
    }
    for (const key of allHelpKeys()) {
      expect(EN[key]?.trim(), `en ${key}`).toBeTruthy();
      expect(VI[key]?.trim(), `vi ${key}`).toBeTruthy();
    }
  });

  it('translates the help: Vietnamese differs from English', () => {
    const same = allHelpKeys().filter((k) => en[k] === vi[k] && !/^help\.group\.(mcp|request)$/.test(k));
    expect(same).toEqual([]);
  });

  it('gives each variable an example that names it and a valid range', () => {
    for (const [name, meta] of Object.entries(VARIABLES)) {
      expect(meta.example).toContain(name);
      expect(FIELD_GROUPS).toContain(meta.group);
      if (meta.min !== undefined && meta.max !== undefined) expect(meta.min).toBeLessThan(meta.max);
    }
    // -1 marks a layer that did not run (fusion.Missing).
    expect(VARIABLES['scores.l2']?.min).toBe(-1);
    expect(VARIABLES['scores.l1']?.min).toBe(0);
  });

  it('documents every operator the backend offers', () => {
    const ops = new Set<string>();
    for (const m of goMap(schemaGo, 'operatorsByType').matchAll(/"([^"]+)"/g)) ops.add(m[1] ?? '');
    for (const t of ['double', 'int', 'string', 'bool', 'list']) ops.delete(t);
    for (const op of ops) expect(OPERATORS as readonly string[]).toContain(op);
  });

  it('mentions every known value of a field in its help', () => {
    const block = goMap(schemaGo, 'fieldValues');
    const categories = /categoryValues = \[\]string\{([^}]*)\}/.exec(schemaGo)?.[1] ?? '';
    const cats = [...categories.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? '');
    expect(cats.length).toBeGreaterThan(0);
    for (const c of cats) {
      expect(en[rangeKey('injection.category')]).toContain(c);
      expect(en[rangeKey('injection.label')]).toContain(c);
    }
    for (const line of block.split('\n')) {
      const m = /"([^"]+)":\s*\{([^}]*)\}/.exec(line);
      if (!m) continue;
      for (const v of (m[2] ?? '').matchAll(/"([^"]+)"/g)) {
        expect(en[rangeKey(m[1] ?? '')], `${m[1]} ${v[1]}`).toContain(v[1]);
      }
    }
  });

  it('keeps the fallback schema in step with the backend', () => {
    expect(new Map(FALLBACK_SCHEMA.fields.map((f) => [f.name, f.type]))).toEqual(fields);
  });

  it('groups fields in display order and searches descriptions', () => {
    const groups = groupFields(FALLBACK_SCHEMA.fields);
    expect(groups.map((g) => g.group)).toEqual(['scores', 'anomaly', 'indirect', 'pii', 'unscanned', 'request', 'mcp']);
    expect(groups.flatMap((g) => g.fields).length).toBe(FALLBACK_SCHEMA.fields.length);
    const describe = (n: string) => en[descKey(n)];
    expect(filterFields(FALLBACK_SCHEMA.fields, 'bidirectional', describe).map((f) => f.name)).toEqual(['anomaly.has_bidi']);
    expect(filterFields(FALLBACK_SCHEMA.fields, 'L2', describe).map((f) => f.name)).toContain('scores.l2');
    expect(filterFields(FALLBACK_SCHEMA.fields, '', describe)).toHaveLength(FALLBACK_SCHEMA.fields.length);
    expect(groups.find((g) => g.group === 'unscanned')?.fields.map((f) => f.name)).toEqual(['input.unscanned.kinds', 'input.unscanned.count']);
    expect(FALLBACK_SCHEMA.fields.find((f) => f.name === 'input.unscanned.kinds')?.values).toEqual(['image', 'file', 'audio', 'other']);
  });
});
