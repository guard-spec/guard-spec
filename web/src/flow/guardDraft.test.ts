// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Guard settings staged on the Flow page and saved with the rules.

import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api';
import { SCAN_TOKENS, WINDOW_BYTES, WINDOW_TURNS, type GuardSettings } from '../types';
import { guardBody, guardChanged, parseThreshold, parseWindowSize, saveAll, type SaveAllApi } from './guardDraft';
import { toEditable } from './model';
import { baseline } from './testdata';

function fakeApi(opts: { guardFails?: boolean; policyFails?: boolean } = {}) {
  const order: string[] = [];
  const api: SaveAllApi = {
    putGuardSettings: vi.fn((_org: string, s: GuardSettings) => {
      order.push('guard');
      return opts.guardFails ? Promise.reject(new ApiError(400, 'guard settings: injection_threshold must be a number in (0, 0.85]')) : Promise.resolve(s);
    }),
    updatePolicy: vi.fn(() => {
      order.push('policy');
      return opts.policyFails ? Promise.reject(new ApiError(400, 'rule "x": bad')) : Promise.resolve({ id: 'p', updated: true });
    }),
    createPolicy: vi.fn(() => {
      order.push('create');
      return Promise.resolve({ id: 'n' });
    }),
  };
  return { api, order };
}

describe('staged guard settings', () => {
  it('leaves unset values out of the body', () => {
    expect(guardBody({ scan_roles: {}, spotlight: 'off' })).toEqual({ spotlight: 'off' });
    expect(guardBody({ injection_threshold: 0.7, indirect_threshold: 0.6, indirect_action: 'redact' })).toEqual({
      indirect_action: 'redact',
      injection_threshold: 0.7,
      indirect_threshold: 0.6,
    });
  });

  it('notices changes, not key order or empty role maps', () => {
    const saved: GuardSettings = { scan_roles: { system: true, tool: false }, spotlight: 'delimit' };
    expect(guardChanged(saved, { spotlight: 'delimit', scan_roles: { tool: false, system: true } })).toBe(false);
    expect(guardChanged({}, { scan_roles: {} })).toBe(false);
    expect(guardChanged(saved, { ...saved, injection_threshold: 0.7 })).toBe(true);
    expect(guardChanged(saved, { scan_roles: { system: true }, spotlight: 'delimit' })).toBe(true);
    expect(guardChanged(saved, null)).toBe(false);
    expect(guardChanged(null, {})).toBe(false);
  });

  it('reads thresholds: empty is the default, only (0, 0.85] is valid', () => {
    expect(parseThreshold('')).toBeUndefined();
    expect(parseThreshold(' 0.7 ')).toBe(0.7);
    expect(parseThreshold('0,6')).toBe(0.6);
    expect(parseThreshold('.5')).toBe(0.5);
    expect(parseThreshold('0.85')).toBe(0.85);
    for (const bad of ['0', '0.86', '1', '-0.5', 'abc', '0.7.1', '1e-1']) expect(parseThreshold(bad), bad).toBe('invalid');
  });

  it('keeps the conversation window toggle and sizes, off included', () => {
    expect(guardBody({ conversation_window: false })).toEqual({ conversation_window: false });
    expect(guardBody({ conversation_window: true, conversation_window_turns: 6, conversation_window_bytes: 4096 })).toEqual({
      conversation_window: true,
      conversation_window_turns: 6,
      conversation_window_bytes: 4096,
    });
    expect(guardChanged({}, { conversation_window: false })).toBe(true);
  });

  it('keeps the personal-data switch, off included', () => {
    expect(guardBody({ input_pii: true })).toEqual({ input_pii: true });
    expect(guardBody({ input_pii: false })).toEqual({ input_pii: false });
    expect(guardBody({ spotlight: 'off' })).toEqual({ spotlight: 'off' });
    expect(guardChanged({}, { input_pii: true })).toBe(true);
    expect(guardChanged({ input_pii: true }, { input_pii: true })).toBe(false);
  });

  it('reads window sizes: empty is the default, whole numbers within the bounds', () => {
    expect(parseWindowSize('', WINDOW_TURNS)).toBeUndefined();
    expect(parseWindowSize(' 6 ', WINDOW_TURNS)).toBe(6);
    expect(parseWindowSize('2', WINDOW_TURNS)).toBe(2);
    expect(parseWindowSize('24576', WINDOW_BYTES)).toBe(24576);
    for (const bad of ['1', '33', '0', '4.5', '-4', 'four']) expect(parseWindowSize(bad, WINDOW_TURNS), bad).toBe('invalid');
    for (const bad of ['255', '24577', '8k']) expect(parseWindowSize(bad, WINDOW_BYTES), bad).toBe('invalid');
  });
});

describe('one save for guard settings and rules', () => {
  const policies = () => {
    const p = toEditable(baseline);
    return [{ ...p, dirty: true }];
  };

  it('saves the guard settings first, then the changed policies', async () => {
    const { api, order } = fakeApi();
    const r = await saveAll(api, 'org', { saved: { spotlight: 'off' }, draft: { spotlight: 'off', injection_threshold: 0.7 } }, policies());
    expect(order).toEqual(['guard', 'policy']);
    expect(r.guard).toEqual({ spotlight: 'off', injection_threshold: 0.7 });
    expect(r.guardError).toBeUndefined();
    expect(r.errors).toEqual([]);
    expect(api.putGuardSettings).toHaveBeenCalledWith('org', { spotlight: 'off', injection_threshold: 0.7 });
  });

  it('does not send unchanged guard settings', async () => {
    const { api, order } = fakeApi();
    const r = await saveAll(api, 'org', { saved: { spotlight: 'off' }, draft: { spotlight: 'off' } }, policies());
    expect(order).toEqual(['policy']);
    expect(r.guard).toBeUndefined();
  });

  it('saves only the guard settings when no policy changed', async () => {
    const { api, order } = fakeApi();
    const clean = policies().map((p) => ({ ...p, dirty: false }));
    const r = await saveAll(api, 'org', { saved: {}, draft: { indirect_threshold: 0.5 } }, clean);
    expect(order).toEqual(['guard']);
    expect(r.guard).toEqual({ indirect_threshold: 0.5 });
  });

  it('reports a guard failure and still saves the policies', async () => {
    const { api, order } = fakeApi({ guardFails: true });
    const r = await saveAll(api, 'org', { saved: {}, draft: { injection_threshold: 0.7 } }, policies());
    expect(order).toEqual(['guard', 'policy']);
    expect(r.guard).toBeUndefined();
    expect(r.guardError).toContain('injection_threshold');
    expect(r.errors).toEqual([]);
  });

  it('reports a policy failure and keeps the saved guard settings', async () => {
    const { api } = fakeApi({ policyFails: true });
    const r = await saveAll(api, 'org', { saved: {}, draft: { spotlight: 'datamark' } }, policies());
    expect(r.guard).toEqual({ spotlight: 'datamark' });
    expect(r.errors).toHaveLength(1);
    expect(r.keep).toHaveLength(1);
  });
});

describe('guardBody: personal data action', () => {
  it('keeps the action and the chosen kinds, drops off and empty kinds', () => {
    expect(guardBody({ input_pii_action: 'tokenize', input_pii_kinds: ['email', 'cccd'] })).toEqual({
      input_pii_action: 'tokenize',
      input_pii_kinds: ['email', 'cccd'],
    });
    expect(guardBody({ input_pii_action: 'redact', input_pii_kinds: [] })).toEqual({ input_pii_action: 'redact' });
    expect(guardBody({ input_pii_action: 'off', input_pii_kinds: ['email'] })).toEqual({});
  });

  it('keeps the answer redaction override: off stored, kinds dropped with off, unset left out', () => {
    expect(guardBody({})).toEqual({});
    expect(guardBody({ output_pii_action: 'off', output_pii_kinds: ['email'] })).toEqual({ output_pii_action: 'off' });
    expect(guardBody({ output_pii_action: 'redact', output_pii_kinds: ['email', 'ipv4'] })).toEqual({
      output_pii_action: 'redact',
      output_pii_kinds: ['email', 'ipv4'],
    });
    // Kinds alone keep the gateway's on or off and change what it redacts.
    expect(guardBody({ output_pii_kinds: ['phone'] })).toEqual({ output_pii_kinds: ['phone'] });
    expect(guardBody({ output_pii_action: 'redact', output_pii_kinds: [] })).toEqual({ output_pii_action: 'redact' });
    expect(guardChanged({}, { output_pii_action: 'off' })).toBe(true);
    expect(guardChanged({ output_pii_action: 'off' }, { output_pii_action: 'off', output_pii_kinds: ['email'] })).toBe(false);
  });

  it('keeps unscanned_parts when set and drops it when unset', () => {
    expect(guardBody({ unscanned_parts: 'block' })).toEqual({ unscanned_parts: 'block' });
    expect(guardBody({ unscanned_parts: 'allow' })).toEqual({ unscanned_parts: 'allow' });
    expect(guardBody({})).toEqual({});
    expect(guardChanged({}, { unscanned_parts: 'log' })).toBe(true);
    expect(guardChanged({ unscanned_parts: 'log' }, { unscanned_parts: 'log' })).toBe(false);
  });

  it('keeps max_scan_tokens when set and drops it when unset', () => {
    expect(guardBody({ max_scan_tokens: 20000 })).toEqual({ max_scan_tokens: 20000 });
    expect(guardBody({})).toEqual({});
    expect(guardChanged({}, { max_scan_tokens: 20000 })).toBe(true);
    expect(guardChanged({ max_scan_tokens: 20000 }, { max_scan_tokens: 20000 })).toBe(false);
    expect(parseWindowSize('20000', SCAN_TOKENS)).toBe(20000);
    expect(parseWindowSize('0', SCAN_TOKENS)).toBe('invalid');
    expect(parseWindowSize('10000001', SCAN_TOKENS)).toBe('invalid');
  });
});
