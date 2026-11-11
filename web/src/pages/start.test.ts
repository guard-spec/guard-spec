// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { GettingStarted } from '../types';
import { landOnStart, layerNames, progress, showSetupCard, startSteps } from './start';

function status(over: Partial<GettingStarted> = {}): GettingStarted {
  return {
    upstream: { configured: true, upstreams: 1, env: false, reachable: true, last_answer_at: '2026-11-10T08:00:00Z', last_error_at: null },
    api_keys: 2,
    policies: 1,
    models: { configured: true, reachable: true, layers: ['l1', 'l2', 'l3'], version: '0.8.0' },
    alert_channels: 0,
    input_settings: false,
    complete: true,
    checked_at: '2026-11-11T08:00:00Z',
    ...over,
  };
}

describe('getting started', () => {
  it('lists the required steps first, each with the page that fixes it', () => {
    const steps = startSteps(status());
    expect(steps.map((s) => [s.id, s.state, s.required, s.route])).toEqual([
      ['provider', 'done', true, 'providers'],
      ['key', 'done', true, 'keys'],
      ['policy', 'done', true, 'flow'],
      ['models', 'done', true, 'models'],
      ['alerts', 'todo', false, 'alert-channels'],
      ['input', 'todo', false, 'input'],
    ]);
    expect(progress(steps)).toEqual({ done: 4, total: 6, requiredLeft: 0 });
  });

  it('warns about a failing provider and a gateway it cannot read', () => {
    const s = status({
      upstream: { configured: true, upstreams: 0, env: true, reachable: false, last_answer_at: null, last_error_at: '2026-11-10T08:00:00Z' },
      models: { configured: true, reachable: false, layers: [], error: 'gateway unreachable' },
      complete: false,
    });
    const steps = startSteps(s);
    expect(steps.find((x) => x.id === 'provider')?.state).toBe('warn');
    expect(steps.find((x) => x.id === 'models')?.state).toBe('warn');
    expect(progress(steps).requiredLeft).toBe(2);
    expect(startSteps(status({ models: { configured: false, reachable: false, layers: [] } })).find((x) => x.id === 'models')?.state).toBe('todo');
    // No traffic yet is not a failure.
    expect(startSteps(status({ upstream: { ...status().upstream, reachable: null } }))[0]?.state).toBe('done');
  });

  it('lands a new org on getting started, not one whose gateway is down', () => {
    expect(landOnStart(undefined, false)).toBe(false);
    expect(landOnStart(status({ api_keys: 0, complete: false }), false)).toBe(true);
    expect(landOnStart(status({ api_keys: 0, complete: false }), true)).toBe(false);
    expect(landOnStart(status({ policies: 0, complete: false }), false)).toBe(true);
    const down = status({ models: { configured: true, reachable: false, layers: [] }, complete: false });
    expect(landOnStart(down, false)).toBe(false);
    expect(showSetupCard(down, false)).toBe(true);
    expect(showSetupCard(down, true)).toBe(false);
    expect(showSetupCard(status(), false)).toBe(false);
  });

  it('writes layers in upper case', () => {
    expect(layerNames(['l1', 'l3'])).toBe('L1, L3');
  });
});
