// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Test data for the unit tests of the Flow page logic.

import type { Policy, Upstream } from '../types';

export const t = (key: string, params?: Record<string, string | number>) => (params ? `${key}(${Object.values(params).join(',')})` : key);

export function upstream(name: string, id = `u-${name}`): Upstream {
  return { id, name, base_url: `https://${name}.example.com/v1`, model: '', api_key_env: '', timeout_ms: 60000, enabled: true };
}

export function policy(over: Partial<Policy> & Pick<Policy, 'id'>): Policy {
  return {
    project_id: null,
    name: over.id,
    description: null,
    version: 1,
    enabled: true,
    rules: [],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...over,
  };
}

export const baseline = policy({
  id: 'p-base',
  name: 'baseline',
  rules: [
    {
      id: 'r1',
      name: 'high l2',
      action: 'block',
      condition: {
        combinator: 'and',
        rules: [
          { field: 'scores.l2', operator: '>', value: '0.9' },
          { field: 'injection.category', operator: '!=', value: 'benign' },
        ],
      },
    },
    { id: 'r2', name: 'log tools', action: 'log', condition: { field: 'indirect.score', operator: '>=', value: 0.5 } },
    { id: 'r3', name: 'to safe', action: 'route', route_target: 'safe', condition: { field: 'injection.score', operator: '>', value: '0.5' } },
    { id: 'r4', name: 'trusted', action: 'allow', condition: { field: 'request.model', operator: 'in', value: 'gpt-4o-mini' } },
  ],
});

export const projectPolicy = policy({
  id: 'p-proj',
  name: 'billing',
  project_id: 'proj-1',
  created_at: '2026-02-01T00:00:00Z',
  rules: [{ id: 'r9', name: 'l1', action: 'block', condition: { field: 'scores.l1', operator: '>=', value: '0.7' } }],
});
