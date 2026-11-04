// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Pure edit operations on the Flow page's policies. Each returns a new array
// (the input is not changed) and marks the policies it touches dirty.

import type { Action } from '../types';
import type { EditablePolicy, EditableRule } from './model';
import { NODE } from './ids';

export interface RuleRef {
  policy: EditablePolicy;
  rule: EditableRule;
  index: number;
}

export function findRule(policies: EditablePolicy[], ruleKey: string): RuleRef | undefined {
  for (const policy of policies) {
    const index = policy.rules.findIndex((r) => r.key === ruleKey);
    const rule = policy.rules[index];
    if (rule) return { policy, rule, index };
  }
  return undefined;
}

function replacePolicy(
  policies: EditablePolicy[],
  key: string,
  f: (p: EditablePolicy) => EditablePolicy,
): EditablePolicy[] {
  return policies.map((p) => (p.key === key ? { ...f(p), dirty: true } : p));
}

/** Applies patch to one rule. route_target is dropped unless the action is route. */
export function updateRule(policies: EditablePolicy[], ruleKey: string, patch: Partial<EditableRule>): EditablePolicy[] {
  const ref = findRule(policies, ruleKey);
  if (!ref) return policies;
  return replacePolicy(policies, ref.policy.key, (p) => ({
    ...p,
    rules: p.rules.map((r) => {
      if (r.key !== ruleKey) return r;
      const next: EditableRule = { ...r, ...patch, key: r.key };
      if (next.action !== 'route') delete next.route_target;
      return next;
    }),
  }));
}

/** Moves the rule at from to index to inside one policy. */
export function moveRule(policies: EditablePolicy[], policyKey: string, from: number, to: number): EditablePolicy[] {
  const policy = policies.find((p) => p.key === policyKey);
  if (!policy) return policies;
  const n = policy.rules.length;
  const target = Math.max(0, Math.min(n - 1, to));
  if (from === target || from < 0 || from >= n) return policies;
  return replacePolicy(policies, policyKey, (p) => {
    const rules = p.rules.slice();
    const [moved] = rules.splice(from, 1);
    if (moved) rules.splice(target, 0, moved);
    return { ...p, rules };
  });
}

/**
 * Reorders a rule after a drag: coords gives each rule node's position along
 * the diagram's main axis (x for left-to-right). The dragged rule takes the
 * place its new coordinate falls into among the other rules of its policy.
 * Rules never move between policies.
 */
export function moveRuleByPosition(
  policies: EditablePolicy[],
  ruleKey: string,
  coords: ReadonlyMap<string, number>,
): EditablePolicy[] {
  const ref = findRule(policies, ruleKey);
  const dropped = coords.get(ruleKey);
  if (!ref || dropped === undefined) return policies;
  const others = ref.policy.rules.filter((r) => r.key !== ruleKey);
  let to = 0;
  for (const r of others) {
    const c = coords.get(r.key);
    if (c !== undefined && c < dropped) to += 1;
  }
  return moveRule(policies, ref.policy.key, ref.index, to);
}

/**
 * Applies a connection drawn from a rule node to a terminal or upstream node:
 * Block, Allow and Log set the action; an upstream sets action route with that
 * upstream as the target. Returns the input unchanged for any other target.
 */
export function connectRule(
  policies: EditablePolicy[],
  ruleKey: string,
  targetNodeId: string,
  upstreamNames: readonly string[],
): EditablePolicy[] {
  const terminal: Partial<Record<string, Action>> = {
    [NODE.block]: 'block',
    [NODE.allow]: 'allow',
    [NODE.log]: 'log',
  };
  const action = terminal[targetNodeId];
  if (action) return updateRule(policies, ruleKey, { action });
  const name = NODE.upstreamName(targetNodeId);
  if (name !== undefined && upstreamNames.includes(name)) {
    return updateRule(policies, ruleKey, { action: 'route', route_target: name });
  }
  return policies;
}

export function addRule(policies: EditablePolicy[], policyKey: string, rule: EditableRule, index?: number): EditablePolicy[] {
  return replacePolicy(policies, policyKey, (p) => {
    const rules = p.rules.slice();
    rules.splice(index ?? rules.length, 0, rule);
    return { ...p, rules };
  });
}

export function deleteRule(policies: EditablePolicy[], ruleKey: string): EditablePolicy[] {
  const ref = findRule(policies, ruleKey);
  if (!ref) return policies;
  return replacePolicy(policies, ref.policy.key, (p) => ({ ...p, rules: p.rules.filter((r) => r.key !== ruleKey) }));
}

/** Rules whose route_target names no upstream of the org. */
export function danglingRoutes(policies: EditablePolicy[], upstreamNames: readonly string[]): EditableRule[] {
  return policies.flatMap((p) =>
    p.rules.filter((r) => r.action === 'route' && (!r.route_target || !upstreamNames.includes(r.route_target))),
  );
}
