// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Checks a condition tree before it is saved, with messages a person can act
// on. Errors are what the control plane would refuse (internal/policy
// leafToCEL: unknown field, an operator the type does not take, a value of
// the wrong type, an empty group or list); warnings are conditions that are
// valid but cannot do what they seem to (a score outside its range, a value
// a field never has, a score the detectors block before the rules run).

import type { MessageKey } from '../i18n';
import { isGroup, type ConditionNode, type FieldType, type PolicySchema } from '../types';
import { variableHelp } from './help';

export interface Problem {
  severity: 'error' | 'warning';
  key: MessageKey;
  params: Record<string, string | number>;
  /** The builder's id of the leaf or group, when it has one. */
  id?: string;
}

export interface ValidateOptions {
  /** The fused injection score the detectors block at (the org's threshold, or 0.85). */
  injectionThreshold?: number;
}

/** The sanitizer blocks at this anomaly score (cmd/gateway anomalyBlockThreshold). */
export const ANOMALY_BLOCK = 0.6;
/** The gateway's own injection block threshold (cmd/gateway injectionBlockThreshold). */
export const INJECTION_BLOCK = 0.85;

const NUMBER = /^-?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/;

function listItems(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter((s) => s !== '');
  if (typeof v === 'string') return v.split(',').map((s) => s.trim()).filter((s) => s !== '');
  return [];
}

/** A value as the user typed it, for emptiness checks and messages. */
function text(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return v === undefined || v === null ? '' : JSON.stringify(v);
}

function numberOf(v: unknown): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'string' && NUMBER.test(v.trim())) return Number(v.trim());
  return undefined;
}

function idOf(node: ConditionNode): string | undefined {
  const id = (node as { id?: unknown }).id;
  return typeof id === 'string' ? id : undefined;
}

export function validateCondition(root: ConditionNode | null | undefined, schema: PolicySchema, opts: ValidateOptions = {}): Problem[] {
  const out: Problem[] = [];
  const types = new Map<string, FieldType>(schema.fields.map((f) => [f.name, f.type]));
  const values = new Map<string, string[] | undefined>(schema.fields.map((f) => [f.name, f.values]));
  const push = (severity: Problem['severity'], key: MessageKey, params: Problem['params'], node: ConditionNode) => {
    const id = idOf(node);
    out.push(id ? { severity, key, params, id } : { severity, key, params });
  };

  const visit = (node: ConditionNode) => {
    if (isGroup(node)) {
      if (node.rules.length === 0) push('error', 'cond.empty', {}, node);
      node.rules.forEach(visit);
      return;
    }
    const { field, operator, value } = node;
    if (!field) {
      push('error', 'cond.noField', {}, node);
      return;
    }
    const type = types.get(field);
    if (!type) {
      push('error', 'cond.unknownField', { field }, node);
      return;
    }
    const op = operator === '==' ? '=' : operator;
    const allowed = schema.operators[type] ?? [];
    // notIn is the builder's negated "in"; the server takes it as a negated group.
    if (!allowed.includes(op) && !(op === 'notIn' && allowed.includes('in'))) {
      push('error', 'cond.badOperator', { field, operator }, node);
      return;
    }
    switch (type) {
      case 'double':
      case 'int': {
        if (text(value).trim() === '') {
          push('error', 'cond.emptyValue', { field }, node);
          return;
        }
        const n = numberOf(value);
        if (n === undefined) {
          push('error', 'cond.notNumber', { field }, node);
          return;
        }
        if (type === 'int' && !Number.isInteger(n)) {
          push('error', 'cond.notInt', { field }, node);
          return;
        }
        const meta = variableHelp(field);
        if (meta && ((meta.min !== undefined && n < meta.min) || (meta.max !== undefined && n > meta.max))) {
          push('warning', 'cond.range', { field, operator, value: text(value).trim(), min: meta.min ?? '-∞', max: meta.max ?? '∞' }, node);
          return;
        }
        const block = field === 'injection.score' ? (opts.injectionThreshold ?? INJECTION_BLOCK) : field === 'anomaly.score' ? ANOMALY_BLOCK : undefined;
        if (block !== undefined && (op === '>=' || op === '=' || op === '>') && n >= block) {
          push('warning', 'cond.aboveThreshold', { field, threshold: block }, node);
        }
        return;
      }
      case 'bool':
        if (!(value === true || value === false || value === 'true' || value === 'false')) push('error', 'cond.notBool', { field }, node);
        return;
      case 'string': {
        const known = values.get(field);
        if (op === 'in' || op === 'notIn') {
          const items = listItems(value);
          if (items.length === 0) {
            push('error', 'cond.emptyList', { field }, node);
            return;
          }
          const bad = known && known.length > 0 ? items.find((v) => !known.includes(v)) : undefined;
          if (bad !== undefined && known) push('warning', 'cond.unknownValue', { field, value: bad, values: known.join(', ') }, node);
          return;
        }
        if (typeof value !== 'string') {
          push('error', 'cond.emptyValue', { field }, node);
          return;
        }
        // An empty string is a valid value (injection.category == "" means none).
        if (value === '' && op !== '=' && op !== '!=') {
          push('error', 'cond.emptyValue', { field }, node);
          return;
        }
        if ((op === '=' || op === '!=') && value !== '' && known && known.length > 0 && !known.includes(value)) {
          push('warning', 'cond.unknownValue', { field, value, values: known.join(', ') }, node);
        }
        return;
      }
      case 'list':
        if (listItems(value).length === 0) push('error', 'cond.emptyValue', { field }, node);
        return;
    }
  };
  if (root) visit(root);
  return out;
}

export function hasErrors(problems: readonly Problem[]): boolean {
  return problems.some((p) => p.severity === 'error');
}
