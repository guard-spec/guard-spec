// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// A local, display-only rendering of a condition tree as an expression, used
// for the labels of the diagram's rule nodes. It follows policy.JSONASTToCEL
// with redundant parentheses removed. The Text tab of the rule editor uses the
// server's POST /policy/format and /policy/parse, which are authoritative.

import { isGroup, type ConditionLeaf, type ConditionNode, type FieldType } from '../types';

export type FieldTypes = Partial<Record<string, FieldType>>;

function quote(v: unknown): string {
  return JSON.stringify(typeof v === 'string' ? v : String(v));
}

function listItems(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string') {
    return v
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '');
  }
  return [];
}

function literal(v: unknown, type: FieldType | undefined): string {
  switch (type) {
    case 'double': {
      const n = typeof v === 'number' ? v : Number(String(v).trim());
      if (String(v).trim() === '' || !Number.isFinite(n)) return String(v);
      const s = String(n);
      return /[.eE]/.test(s) ? s : s + '.0';
    }
    case 'int': {
      const n = typeof v === 'number' ? v : Number(String(v).trim());
      return Number.isFinite(n) ? String(Math.trunc(n)) : String(v);
    }
    case 'bool':
      return v === true || v === 'true' ? 'true' : 'false';
    case 'string':
    case 'list':
      return quote(v);
    case undefined: {
      if (typeof v === 'number' || typeof v === 'boolean') return String(v);
      if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return v.trim();
      if (v === 'true' || v === 'false') return v;
      return quote(v);
    }
  }
}

export function leafText(leaf: ConditionLeaf, types: FieldTypes = {}): string {
  const { field, operator, value } = leaf;
  const type = types[field];
  switch (operator) {
    case '=':
    case '==':
      return `${field} == ${literal(value, type)}`;
    case '!=':
      return `${field} != ${literal(value, type)}`;
    case '>':
    case '>=':
    case '<':
    case '<=':
      return `${field} ${operator} ${literal(value, type)}`;
    case 'contains':
      return type === 'list' ? `${quote(value)} in ${field}` : `${field}.contains(${quote(value)})`;
    case 'beginsWith':
      return `${field}.startsWith(${quote(value)})`;
    case 'endsWith':
      return `${field}.endsWith(${quote(value)})`;
    case 'in':
      if (type === 'list') return `${quote(value)} in ${field}`;
      return `${field} in [${listItems(value).map(quote).join(', ')}]`;
    case 'notIn':
      return `!(${field} in [${listItems(value).map(quote).join(', ')}])`;
    default:
      return `${field} ${operator} ${literal(value, type)}`;
  }
}

// Precedence: || 1, && 2, unary ! and leaves 3.
function prec(node: ConditionNode): number {
  if (!isGroup(node)) return 3;
  if (node.not) return 3;
  if (node.rules.length === 1 && node.rules[0]) return prec(node.rules[0]);
  return node.combinator === 'or' ? 1 : 2;
}

/** Renders a condition tree as a readable expression. */
export function conditionText(node: ConditionNode | null | undefined, types: FieldTypes = {}): string {
  if (!node) return '';
  if (!isGroup(node)) return leafText(node, types);
  if (node.rules.length === 0) return node.not ? '!(true)' : 'true';
  const op = node.combinator === 'or' ? ' || ' : ' && ';
  const own = node.combinator === 'or' ? 1 : 2;
  const parts = node.rules.map((child) => {
    const s = conditionText(child, types);
    return prec(child) < own ? `(${s})` : s;
  });
  const body = parts.join(op);
  if (node.not) return `!(${body})`;
  return body;
}

/** Shortens text to max characters for a node label. */
export function ellipsize(s: string, max = 90): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}
