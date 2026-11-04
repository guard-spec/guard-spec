// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { isGroup, type ConditionNode, type FieldType, type PolicySchema } from '../types';
import type { FieldTypes } from './conditionText';

/**
 * The schema used when the control plane has no GET /policy/schema yet: the
 * fields of policy.fieldTypes and the operators leafToCEL supports today.
 */
export const FALLBACK_SCHEMA: PolicySchema = {
  fields: [
    { name: 'request.model', type: 'string' },
    { name: 'request.tenant_id', type: 'string' },
    { name: 'request.tokens', type: 'int' },
    { name: 'injection.score', type: 'double' },
    { name: 'injection.label', type: 'string' },
    { name: 'injection.category', type: 'string' },
    { name: 'scores.l1', type: 'double' },
    { name: 'scores.l2', type: 'double' },
    { name: 'scores.l3', type: 'double' },
    { name: 'indirect.score', type: 'double' },
    { name: 'indirect.source', type: 'string', values: ['tool', 'document', 'tool_description'] },
    { name: 'injection.source_role', type: 'string', values: ['user', 'system', 'assistant', 'tool', 'tool_description'] },
    { name: 'anomaly.score', type: 'double' },
    { name: 'anomaly.has_tag_chars', type: 'bool' },
    { name: 'anomaly.has_bidi', type: 'bool' },
    { name: 'mcp.is_tool_response', type: 'bool' },
  ],
  operators: {
    double: ['=', '!=', '>', '>=', '<', '<='],
    int: ['=', '!=', '>', '>=', '<', '<='],
    string: ['=', '!=', 'contains', 'in'],
    bool: ['=', '!='],
    list: ['contains'],
  },
  actions: ['allow', 'block', 'log', 'route'],
};

export function fieldTypesOf(schema: PolicySchema): FieldTypes {
  const out: Record<string, FieldType> = {};
  for (const f of schema.fields) out[f.name] = f.type;
  return out;
}

export function operatorsFor(schema: PolicySchema, type: FieldType): string[] {
  return schema.operators[type] ?? [];
}

/** Removes the builder's client ids, so stored rules hold only what the server reads. */
export function cleanCondition(node: ConditionNode): ConditionNode {
  if (isGroup(node)) {
    const out: ConditionNode = { combinator: node.combinator, rules: node.rules.map(cleanCondition) };
    if (node.not) out.not = true;
    return out;
  }
  return { field: node.field, operator: node.operator, value: node.value };
}
