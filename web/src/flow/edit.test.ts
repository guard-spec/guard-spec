// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { addRule, connectRule, danglingRoutes, deleteRule, findRule, moveRule, moveRuleByPosition, updateRule } from './edit';
import { NODE } from './ids';
import { gatewayChain, makeRule, toEditable, toWireRules, type EditablePolicy } from './model';
import { baseline, policy, projectPolicy } from './testdata';

const names = (p: EditablePolicy | undefined) => p?.rules.map((r) => r.name);
const fresh = () => [toEditable(baseline), toEditable(projectPolicy)];

describe('moveRule', () => {
  it('moves a rule inside its policy and marks the policy dirty', () => {
    const ps = fresh();
    const out = moveRule(ps, 'p-base', 0, 2);
    expect(names(out[0])).toEqual(['log tools', 'to safe', 'high l2', 'trusted']);
    expect(out[0]?.dirty).toBe(true);
    expect(out[1]).toBe(ps[1]);
    expect(names(ps[0])).toEqual(['high l2', 'log tools', 'to safe', 'trusted']); // input unchanged
  });

  it('clamps the target and ignores no-ops', () => {
    const ps = fresh();
    expect(names(moveRule(ps, 'p-base', 3, 99)[0])).toEqual(names(ps[0]));
    expect(moveRule(ps, 'p-base', 1, 1)).toBe(ps);
    expect(moveRule(ps, 'nope', 0, 1)).toBe(ps);
    expect(names(moveRule(ps, 'p-base', 3, -5)[0])).toEqual(['trusted', 'high l2', 'log tools', 'to safe']);
  });
});

describe('moveRuleByPosition', () => {
  // Top to bottom: y positions of the rule nodes after a drag.
  const coords = (y: Record<string, number>) => new Map(Object.entries(y));

  it('puts a dragged rule where its new coordinate falls', () => {
    const ps = fresh();
    const out = moveRuleByPosition(ps, 'r1', coords({ r1: 250, r2: 100, r3: 200, r4: 300, r9: 0 }));
    expect(names(out[0])).toEqual(['log tools', 'to safe', 'high l2', 'trusted']);
  });

  it('moves a rule to the front and to the end', () => {
    const ps = fresh();
    expect(names(moveRuleByPosition(ps, 'r4', coords({ r1: 100, r2: 200, r3: 300, r4: 50 }))[0])).toEqual([
      'trusted',
      'high l2',
      'log tools',
      'to safe',
    ]);
    expect(names(moveRuleByPosition(ps, 'r1', coords({ r1: 900, r2: 200, r3: 300, r4: 400 }))[0])).toEqual([
      'log tools',
      'to safe',
      'trusted',
      'high l2',
    ]);
  });

  it('keeps the order when the rule is dropped in place; never moves rules between policies', () => {
    const ps = fresh();
    expect(moveRuleByPosition(ps, 'r2', coords({ r1: 100, r2: 210, r3: 300, r4: 400 }))).toBe(ps);
    // r9 is alone in its policy: wherever it is dropped, nothing changes.
    expect(moveRuleByPosition(ps, 'r9', coords({ r9: 1000, r1: 100 }))).toBe(ps);
    expect(moveRuleByPosition(ps, 'missing', coords({}))).toBe(ps);
  });
});

describe('connectRule', () => {
  const ups = ['main', 'safe'];

  it('sets block, allow and log from the terminal nodes', () => {
    const ps = fresh();
    expect(findRule(connectRule(ps, 'r3', NODE.block, ups), 'r3')?.rule).toMatchObject({ action: 'block' });
    expect(findRule(connectRule(ps, 'r3', NODE.block, ups), 'r3')?.rule.route_target).toBeUndefined();
    expect(findRule(connectRule(ps, 'r1', NODE.allow, ups), 'r1')?.rule.action).toBe('allow');
    expect(findRule(connectRule(ps, 'r1', NODE.log, ups), 'r1')?.rule.action).toBe('log');
  });

  it('makes a route rule from an upstream node', () => {
    const out = connectRule(fresh(), 'r1', NODE.upstream('main'), ups);
    expect(findRule(out, 'r1')?.rule).toMatchObject({ action: 'route', route_target: 'main' });
    expect(out[0]?.dirty).toBe(true);
  });

  it('ignores unknown upstreams and other nodes', () => {
    const ps = fresh();
    expect(connectRule(ps, 'r1', NODE.upstream('ghost'), ups)).toBe(ps);
    expect(connectRule(ps, 'r1', NODE.output, ups)).toBe(ps);
    expect(connectRule(ps, 'r1', NODE.envUpstream, ups)).toBe(ps);
  });
});

describe('add, update and delete', () => {
  it('adds a rule at the end or at an index', () => {
    const ps = fresh();
    const a = makeRule('new');
    const out = addRule(ps, 'p-proj', a);
    expect(names(out[1])).toEqual(['l1', 'new']);
    expect(names(addRule(ps, 'p-proj', makeRule('first'), 0)[1])).toEqual(['first', 'l1']);
    expect(out[1]?.dirty).toBe(true);
  });

  it('deletes a rule', () => {
    const out = deleteRule(fresh(), 'r2');
    expect(names(out[0])).toEqual(['high l2', 'to safe', 'trusted']);
  });

  it('drops route_target when the action is no longer route', () => {
    const out = updateRule(fresh(), 'r3', { action: 'block' });
    expect(findRule(out, 'r3')?.rule.route_target).toBeUndefined();
    const back = updateRule(out, 'r3', { action: 'route', route_target: 'main' });
    expect(findRule(back, 'r3')?.rule.route_target).toBe('main');
  });

  it('lists route rules whose target does not exist', () => {
    expect(danglingRoutes(fresh(), ['main']).map((r) => r.name)).toEqual(['to safe']);
    expect(danglingRoutes(fresh(), ['main', 'safe'])).toEqual([]);
  });
});

describe('model', () => {
  it('orders policies like the gateway: project first, then oldest first; skips disabled ones', () => {
    const older = toEditable(policy({ id: 'old', created_at: '2025-01-01T00:00:00Z' }));
    const off = toEditable(policy({ id: 'off', enabled: false }));
    const chain = gatewayChain([toEditable(baseline), off, toEditable(projectPolicy), older], 'proj-1');
    expect(chain.map((p) => p.key)).toEqual(['p-proj', 'old', 'p-base']);
    expect(gatewayChain([toEditable(projectPolicy)], null)).toEqual([]);
  });

  it('strips client keys and builder ids from stored rules', () => {
    const ps = fresh();
    const withIds = updateRule(ps, 'r1', {
      condition: { id: 'g1', combinator: 'and', rules: [{ id: 'x1', field: 'scores.l2', operator: '>', value: '0.8', valueSource: 'value' }] },
    });
    const wire = toWireRules(withIds[0]?.rules ?? []);
    expect(wire[0]).toEqual({ id: 'r1', name: 'high l2', action: 'block', condition: { combinator: 'and', rules: [{ field: 'scores.l2', operator: '>', value: '0.8' }] } });
    expect(wire[2]).toMatchObject({ action: 'route', route_target: 'safe' });
    expect(Object.keys(wire[1] ?? {})).not.toContain('key');
    const fresh1 = toWireRules([makeRule('n')]);
    expect(fresh1[0]?.id).toBeUndefined();
  });
});
