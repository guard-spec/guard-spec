// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api';
import { compareTimes, gatewayChain, makeRule, timeKey, toEditable, type EditablePolicy } from './model';
import { deletable, mergeAfterSave, savePolicies, type SaveApi } from './save';
import { baseline, policy, projectPolicy } from './testdata';

describe('policy order by creation time', () => {
  it('compares times, not strings: Go drops trailing zeros of the fraction', () => {
    // As strings, "...00.12Z" > "...00.123456Z"; as times it is earlier.
    expect(compareTimes('2026-10-01T09:00:00.12Z', '2026-10-01T09:00:00.123456Z')).toBe(-1);
    expect(compareTimes('2026-10-01T09:00:00Z', '2026-10-01T09:00:00.000000001Z')).toBe(-1);
    expect(compareTimes('2026-10-01T09:00:00.5Z', '2026-10-01T09:00:00.500Z')).toBe(0);
    expect(compareTimes('2026-10-01T16:00:00+07:00', '2026-10-01T09:00:00.1Z')).toBe(-1);
    expect(timeKey('2026-10-01T09:00:00.12Z')[1]).toBe(120_000_000);
  });

  it('orders the gateway chain by those times', () => {
    const later = toEditable(policy({ id: 'b-later', created_at: '2026-10-01T09:00:00.123456Z' }));
    const earlier = toEditable(policy({ id: 'z-earlier', created_at: '2026-10-01T09:00:00.12Z' }));
    expect(gatewayChain([later, earlier], null).map((p) => p.key)).toEqual(['z-earlier', 'b-later']);
  });
});

function fakeApi(fail: Partial<Record<'create' | 'update', string>> = {}) {
  const createPolicy = vi.fn((..._args: Parameters<SaveApi['createPolicy']>) =>
    fail.create ? Promise.reject(new ApiError(409, fail.create)) : Promise.resolve({ id: 'new-id' }),
  );
  const updatePolicy = vi.fn((..._args: Parameters<SaveApi['updatePolicy']>) =>
    fail.update ? Promise.reject(new ApiError(400, fail.update)) : Promise.resolve({ id: 'x', updated: true }),
  );
  return { api: { createPolicy, updatePolicy } as unknown as SaveApi, createPolicy, updatePolicy };
}

function draft(over: Partial<EditablePolicy> = {}): EditablePolicy {
  return {
    id: undefined,
    key: 'policy-1',
    name: 'new',
    description: null,
    project_id: null,
    enabled: false,
    log_only: false,
    created_at: '',
    rules: [makeRule('r')],
    dirty: true,
    ...over,
  };
}

describe('savePolicies', () => {
  it('creates a disabled policy in one request, disabled', async () => {
    const f = fakeApi();
    const r = await savePolicies(f.api, 'org', [draft()]);
    expect(r.errors).toEqual([]);
    expect(r.keep).toEqual([]);
    expect(f.createPolicy).toHaveBeenCalledOnce();
    expect(f.createPolicy.mock.calls[0]?.[1]).toMatchObject({ name: 'new', enabled: false, project_id: null });
    expect(f.updatePolicy).not.toHaveBeenCalled();
  });

  it('saves only dirty policies; updates send name, rules and enabled', async () => {
    const f = fakeApi();
    const clean = toEditable(projectPolicy);
    const changed = { ...toEditable(baseline), enabled: false, dirty: true };
    await savePolicies(f.api, 'org', [clean, changed]);
    expect(f.updatePolicy).toHaveBeenCalledOnce();
    expect(f.updatePolicy.mock.calls[0]?.[1]).toBe('p-base');
    expect(f.updatePolicy.mock.calls[0]?.[2]).toMatchObject({ name: 'baseline', enabled: false });
  });

  it('keeps what failed, with rule errors by key', async () => {
    const f = fakeApi({ update: 'rule "high l2": unknown field: x' });
    const changed = { ...toEditable(baseline), dirty: true };
    const r = await savePolicies(f.api, 'org', [changed]);
    expect(r.errors).toEqual([{ policy: 'baseline', message: 'rule "high l2": unknown field: x' }]);
    expect(r.keep).toEqual([changed]);
    expect(Object.keys(r.ruleErrors)).toEqual(['r1']);
  });
});

describe('mergeAfterSave', () => {
  const fresh = [toEditable(baseline), toEditable(policy({ id: 'new-id', name: 'new' }))];

  it('takes the server list when everything was saved: a created policy is not posted again', () => {
    const merged = mergeAfterSave(fresh, []);
    expect(merged.map((p) => [p.key, p.dirty])).toEqual([
      ['p-base', false],
      ['new-id', false],
    ]);
    expect(merged.some((p) => !p.id)).toBe(false);
  });

  it('keeps unsaved edits of an existing policy, dirty, and a draft that was not created', () => {
    const edited = { ...toEditable(baseline), name: 'edited', dirty: true };
    const failedDraft = draft({ key: 'policy-9', name: 'taken' });
    const merged = mergeAfterSave(fresh, [edited, failedDraft]);
    expect(merged.map((p) => [p.key, p.name, p.dirty])).toEqual([
      ['p-base', 'edited', true],
      ['new-id', 'new', false],
      ['policy-9', 'taken', true],
    ]);
  });
});

describe('deletable', () => {
  const on = { ...toEditable(baseline), enabled: true };
  const off = { ...on, enabled: false };
  it('offers to delete a draft, and a saved policy only while it is disabled as saved', () => {
    expect(deletable(draft(), null)).toBe(true);
    expect(deletable(on, [on])).toBe(false);
    expect(deletable(off, [off])).toBe(true);
    // Unchecked but not saved yet: the server still has it enabled.
    expect(deletable(off, [on])).toBe(false);
    // Checked again but not saved: the server has it disabled.
    expect(deletable(on, [off])).toBe(true);
    expect(deletable(on, null)).toBe(false);
  });
});
