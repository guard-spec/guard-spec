// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Help metadata of the Flow page, in one place: what every condition
// variable means, its values and an example, the operators, the actions, the
// diagram's nodes and edges. The condition builder (field picker), the text
// editor's completion and the Simulator all read it. The texts are message
// keys (en.ts, vi.ts); help.test.ts checks that every variable the backend
// declares (internal/policy fieldTypes) has them in both languages.

import type { MessageKey } from '../i18n';
import type { Action, FieldType, SchemaField } from '../types';

export type FieldGroup = 'scores' | 'anomaly' | 'indirect' | 'pii' | 'unscanned' | 'request' | 'mcp';

/** The groups of the field picker and the Simulator, in display order. */
export const FIELD_GROUPS: readonly FieldGroup[] = ['scores', 'anomaly', 'indirect', 'pii', 'unscanned', 'request', 'mcp'];

export interface VariableHelp {
  group: FieldGroup;
  /** A condition that uses the variable, as the Text tab writes it. */
  example: string;
  /** Lowest and highest value of a number, when the gateway bounds it. */
  min?: number;
  max?: number;
}

/**
 * The variables of internal/policy fieldTypes (the removed ones are not
 * offered). Ranges follow cmd/gateway policyVars and the detectors.
 */
export const VARIABLES: Readonly<Record<string, VariableHelp>> = {
  'injection.score': { group: 'scores', example: 'injection.score >= 0.7', min: 0, max: 1 },
  'injection.label': { group: 'scores', example: 'injection.label != "BENIGN"' },
  'injection.category': { group: 'scores', example: 'injection.category in ["jailbreak", "prompt_extraction"]' },
  'injection.source_role': { group: 'scores', example: 'injection.source_role == "system"' },
  'conversation.score': { group: 'scores', example: 'conversation.score >= 0.7', min: 0, max: 1 },
  'scores.l1': { group: 'scores', example: 'scores.l1 >= 0.7', min: 0, max: 1 },
  'scores.l2': { group: 'scores', example: 'scores.l2 > 0.9', min: -1, max: 1 },
  'scores.l3': { group: 'scores', example: 'scores.l3 >= 0.8', min: -1, max: 1 },
  'anomaly.score': { group: 'anomaly', example: 'anomaly.score >= 0.3', min: 0, max: 1 },
  'anomaly.has_tag_chars': { group: 'anomaly', example: 'anomaly.has_tag_chars == true' },
  'anomaly.has_bidi': { group: 'anomaly', example: 'anomaly.has_bidi == true' },
  'indirect.score': { group: 'indirect', example: 'indirect.score >= 0.5', min: 0, max: 1 },
  'indirect.source': { group: 'indirect', example: 'indirect.source == "tool_description"' },
  'input.pii.kinds': { group: 'pii', example: '"card" in input.pii.kinds' },
  'input.pii.count': { group: 'pii', example: 'input.pii.count > 0', min: 0 },
  'input.unscanned.kinds': { group: 'unscanned', example: '"image" in input.unscanned.kinds' },
  'input.unscanned.count': { group: 'unscanned', example: 'input.unscanned.count > 0', min: 0 },
  'input.pdf.count': { group: 'unscanned', example: 'input.pdf.count > 0', min: 0 },
  'input.pdf.scanned': { group: 'unscanned', example: 'input.pdf.scanned < input.pdf.count', min: 0 },
  'input.pdf.reasons': { group: 'unscanned', example: '"encrypted" in input.pdf.reasons' },
  'request.model': { group: 'request', example: 'request.model.startsWith("gpt-4")' },
  'request.tenant_id': { group: 'request', example: 'request.tenant_id == "00000000-0000-0000-0000-000000000001"' },
  'request.tokens': { group: 'request', example: 'request.tokens > 8000', min: 0 },
  'mcp.is_tool_response': { group: 'mcp', example: 'mcp.is_tool_response == true' },
};

export const groupKey = (g: FieldGroup) => `help.group.${g}` as MessageKey;
/** What the variable means. */
export const descKey = (name: string) => `help.var.${name}.desc` as MessageKey;
/** Its values or range. */
export const rangeKey = (name: string) => `help.var.${name}.range` as MessageKey;
/** When a rule would use it. */
export const whenKey = (name: string) => `help.var.${name}.when` as MessageKey;

export function variableHelp(name: string): VariableHelp | undefined {
  return VARIABLES[name];
}

/** The group of a field; a field the UI does not know yet goes under Request. */
export function groupOf(name: string): FieldGroup {
  return VARIABLES[name]?.group ?? 'request';
}

/** Fields grouped for the picker and the Simulator: known groups in order, schema order inside. */
export function groupFields<T extends Pick<SchemaField, 'name'>>(fields: readonly T[]): { group: FieldGroup; fields: T[] }[] {
  return FIELD_GROUPS.map((group) => ({ group, fields: fields.filter((f) => groupOf(f.name) === group) })).filter(
    (g) => g.fields.length > 0,
  );
}

/** The operators of internal/policy operatorsByType, and the builder's notIn. */
export const OPERATORS = ['=', '!=', '>', '>=', '<', '<=', 'contains', 'beginsWith', 'endsWith', 'in', 'notIn'] as const;

export function operatorKey(op: string): MessageKey {
  const name = op === '==' ? '=' : op;
  return `help.op.${name}` as MessageKey;
}

/** An operator's help depends on the field's type for "in" and "contains" on a list. */
export function operatorHelpKey(op: string, type: FieldType | undefined): MessageKey {
  if (type === 'list' && (op === 'in' || op === 'contains')) return 'help.op.listContains';
  return operatorKey(op);
}

export const actionHelpKey = (a: Action) => `help.action.${a}` as MessageKey;

export type NodeKind = 'request' | 'key' | 'sanitizer' | 'detectors' | 'rule' | 'block' | 'allow' | 'log' | 'upstream' | 'envUpstream' | 'output' | 'client';
export const NODE_KINDS: readonly NodeKind[] = ['request', 'key', 'sanitizer', 'detectors', 'rule', 'block', 'log', 'allow', 'upstream', 'envUpstream', 'output', 'client'];
export const nodeHelpKey = (k: NodeKind) => `help.node.${k}` as MessageKey;

export type EdgeKindHelp = 'match' | 'noMatch' | 'matchContinue' | 'default';
export const EDGE_KINDS: readonly EdgeKindHelp[] = ['match', 'noMatch', 'matchContinue', 'default'];
export const edgeHelpKey = (k: EdgeKindHelp) => `help.edge.${k}` as MessageKey;

/** Every message key the help uses, for the coverage test. */
export function allHelpKeys(): MessageKey[] {
  const keys: MessageKey[] = [];
  for (const name of Object.keys(VARIABLES)) keys.push(descKey(name), rangeKey(name), whenKey(name));
  for (const g of FIELD_GROUPS) keys.push(groupKey(g));
  for (const op of OPERATORS) keys.push(operatorKey(op));
  keys.push('help.op.listContains');
  for (const a of ['allow', 'block', 'log', 'route'] as const) keys.push(actionHelpKey(a));
  for (const n of NODE_KINDS) keys.push(nodeHelpKey(n));
  for (const e of EDGE_KINDS) keys.push(edgeHelpKey(e));
  return keys;
}
