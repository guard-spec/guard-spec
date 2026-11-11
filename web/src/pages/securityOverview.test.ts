// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { GatewayModels } from '../types';
import { currentFilter, MAX_FILTERS, withFilter, withoutFilter } from './savedFilters';
import { attackBars, modelHealth } from './securityOverview';

const GW: GatewayModels = {
  configured: true,
  reachable: true,
  checked_at: '2026-11-11T08:00:00Z',
  l2_model: 'guardspec-classifier@v3b',
  l2_verified: true,
  recommended: null,
  installed: [],
  update_available: false,
  shadow: { enabled: false, model: null },
  reload: { generation: 1, at: null, error: null },
  layers: ['l1', 'l2', 'l3'],
};

describe('security overview', () => {
  it('scales the attack trend to the most refused period', () => {
    const { bars, max } = attackBars({
      series: [
        { start: '2026-11-11T00:00:00Z', count: 90, blocked: 3 },
        { start: '2026-11-11T01:00:00Z', count: 10, blocked: 7 },
      ],
    });
    expect(max).toBe(7);
    expect(bars.map((b) => b.blocked)).toEqual([3, 7]);
    expect(attackBars({ series: [] }).max).toBe(1);
  });

  it('sums up the models health', () => {
    expect(modelHealth(GW)).toBe('ok');
    expect(modelHealth(undefined)).toBe('down');
    expect(modelHealth({ ...GW, reachable: false })).toBe('down');
    expect(modelHealth({ ...GW, layers: ['l1', 'l2'] })).toBe('degraded');
    expect(modelHealth({ ...GW, l2_verified: false })).toBe('degraded');
    expect(modelHealth({ ...GW, reload: { generation: 2, at: null, error: 'sha256 mismatch' } })).toBe('degraded');
  });
});

describe('saved filters', () => {
  it('keeps one filter per name, newest first, and finds the current one', () => {
    let list = withFilter([], { name: ' blocked ', action: 'block', q: '' });
    list = withFilter(list, { name: 'mini', action: '', q: 'gpt-4o-mini' });
    list = withFilter(list, { name: 'blocked', action: 'block', q: 'jailbreak' });
    expect(list.map((f) => f.name)).toEqual(['blocked', 'mini']);
    expect(currentFilter(list, 'block', 'jailbreak')?.name).toBe('blocked');
    expect(currentFilter(list, 'block', '')).toBeUndefined();
    expect(withoutFilter(list, 'mini').map((f) => f.name)).toEqual(['blocked']);
    let many = list;
    for (let i = 0; i < 30; i++) many = withFilter(many, { name: `f${i}`, action: '', q: String(i) });
    expect(many).toHaveLength(MAX_FILTERS);
  });
});
