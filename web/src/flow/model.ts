// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The Flow page's editing model: the policies that apply to the selected
// scope, in gateway order, with their rules. Rules carry a client key so new,
// unsaved rules can be addressed before the server gives them an id.

import type { Action, ConditionGroup, ConditionNode, Policy, Rule, UUID } from '../types';
import { isGroup } from '../types';
import { cleanCondition } from './schema';

export interface EditableRule extends Rule {
  key: string;
}

export interface EditablePolicy {
  /** Server id; undefined for a policy not saved yet. */
  id: UUID | undefined;
  key: string;
  name: string;
  description: string | null;
  project_id: UUID | null;
  enabled: boolean;
  created_at: string;
  rules: EditableRule[];
  dirty: boolean;
}

let seq = 0;
/** A client key for a new rule or policy. */
export function newKey(prefix = 'new'): string {
  seq += 1;
  return `${prefix}-${seq}`;
}

export function toEditable(p: Policy): EditablePolicy {
  return {
    id: p.id,
    key: p.id,
    name: p.name,
    description: p.description,
    project_id: p.project_id,
    enabled: p.enabled,
    created_at: p.created_at,
    rules: p.rules.map((r) => ({ ...r, key: r.id ?? newKey() })),
    dirty: false,
  };
}

/** Strips client keys: the rule list the API stores. */
export function toWireRules(rules: EditableRule[]): Rule[] {
  return rules.map((r) => {
    const out: Rule = { name: r.name, condition: cleanCondition(r.condition), action: r.action };
    if (r.id) out.id = r.id;
    if (r.action === 'route' && r.route_target) out.route_target = r.route_target;
    return out;
  });
}

/**
 * The policies the gateway evaluates for a project (or for keys without a
 * project when projectId is null), in its order: project policies first, then
 * org-wide ones, each oldest first (cmd/gateway dbPolicyLoader).
 */
export function gatewayChain(policies: EditablePolicy[], projectId: UUID | null): EditablePolicy[] {
  return policies.filter((p) => p.enabled && (p.project_id === null || p.project_id === projectId)).sort(gatewayOrder);
}

/** Project policies first, then org-wide ones; oldest first; unsaved ones last. */
export function gatewayOrder(a: EditablePolicy, b: EditablePolicy): number {
  const ao = a.project_id === null ? 1 : 0;
  const bo = b.project_id === null ? 1 : 0;
  if (ao !== bo) return ao - bo;
  const at = a.id ? a.created_at : '\uffff';
  const bt = b.id ? b.created_at : '\uffff';
  if (at !== bt) return at < bt ? -1 : 1;
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

/** Pulls `rule "name"` out of a server validation error. */
export function ruleNameInError(message: string): string | undefined {
  return /rule "((?:[^"\\]|\\.)*)"/.exec(message)?.[1];
}

/** Whether name is taken by another policy of the org (names are unique per org). */
export function policyNameTaken(policies: readonly EditablePolicy[], name: string, exceptKey?: string): boolean {
  const n = name.trim();
  return policies.some((p) => p.key !== exceptKey && p.name.trim() === n);
}

/** Wraps a single leaf so the visual builder, which needs a root group, can edit it. */
export function asGroup(node: ConditionNode | null | undefined): ConditionGroup {
  if (!node) return { combinator: 'and', rules: [] };
  if (isGroup(node)) return node;
  return { combinator: 'and', rules: [node] };
}

export function defaultCondition(field = 'injection.score'): ConditionGroup {
  return { combinator: 'and', rules: [{ field, operator: '>=', value: '0.8' }] };
}

export function makeRule(name: string, action: Action = 'block'): EditableRule {
  return { key: newKey(), name, condition: defaultCondition(), action };
}
