// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The condition of an alert rule (contract §2): policy-text syntax over
// {type, severity, project_id, attrs}. The rule stores the text; the visual
// builder edits a tree. POST /policy/parse validates against the request
// fields of policies, not these, so the conversion runs here: the same
// subset as the policy text (comparisons, in [...], "x" in list, contains,
// startsWith, endsWith, !, &&, ||, parentheses). The server validates the text
// again on save (400 with the parse error).

import { conditionText, type FieldTypes } from '../flow/conditionText';
import { fieldTypesOf } from '../flow/schema';
import { isGroup, type ConditionGroup, type ConditionNode, type PolicySchema } from '../types';
import { EVENT_TYPES, SEVERITIES } from './types';

/** The fields of an event a condition may test (contract §1). */
export const ALERT_SCHEMA: PolicySchema = {
  fields: [
    { name: 'type', type: 'string', values: [...EVENT_TYPES] },
    { name: 'severity', type: 'string', values: [...SEVERITIES] },
    { name: 'project_id', type: 'string' },
    { name: 'attrs.categories', type: 'list', description: 'detection.*' },
    { name: 'attrs.score', type: 'double', description: 'detection.*' },
    { name: 'attrs.layer', type: 'string', description: 'detection.*' },
    { name: 'attrs.decision', type: 'string', description: 'detection.*' },
    { name: 'attrs.model', type: 'string', description: 'detection.*' },
    { name: 'attrs.api_key_id', type: 'string', description: 'detection.*' },
    { name: 'attrs.pii_kinds', type: 'list', values: ['email', 'phone', 'card', 'cccd', 'ipv4'], description: 'detection.*' },
    { name: 'attrs.pii_count', type: 'int', description: 'detection.*' },
    { name: 'attrs.upstream_id', type: 'string', description: 'upstream.error' },
    { name: 'attrs.status', type: 'int', description: 'upstream.error' },
    { name: 'attrs.error_kind', type: 'string', values: ['timeout', '5xx', 'model_not_allowed', 'connect'], description: 'upstream.error' },
    { name: 'attrs.reason', type: 'string', description: 'security.login_failed' },
    { name: 'attrs.ip', type: 'string', description: 'security.login_failed' },
    { name: 'attrs.action', type: 'string', description: 'security.sso_changed, config.*' },
    { name: 'attrs.from', type: 'string', description: 'security.role_changed' },
    { name: 'attrs.to', type: 'string', description: 'security.role_changed' },
  ],
  operators: {
    double: ['=', '!=', '>', '>=', '<', '<='],
    int: ['=', '!=', '>', '>=', '<', '<='],
    string: ['=', '!=', 'contains', 'beginsWith', 'endsWith', 'in', 'notIn'],
    bool: ['=', '!='],
    list: ['contains'],
  },
  actions: [],
};

export const ALERT_FIELD_TYPES: FieldTypes = fieldTypesOf(ALERT_SCHEMA);

export class ConditionParseError extends Error {
  constructor(
    message: string,
    readonly position: number,
  ) {
    super(message);
    this.name = 'ConditionParseError';
  }
}

interface Tok {
  kind: 'id' | 'str' | 'num' | 'op' | 'punct' | 'eof';
  text: string;
  pos: number;
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src.charAt(i);
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    const rest = src.slice(i);
    let m: RegExpExecArray | null;
    if ((m = /^"(?:[^"\\]|\\.)*"/.exec(rest))) {
      out.push({ kind: 'str', text: JSON.parse(m[0]) as string, pos: i });
    } else if ((m = /^'(?:[^'\\]|\\.)*'/.exec(rest))) {
      out.push({ kind: 'str', text: m[0].slice(1, -1).replace(/\\(.)/g, '$1'), pos: i });
    } else if ((m = /^-?\d+(\.\d+)?([eE][-+]?\d+)?/.exec(rest))) {
      out.push({ kind: 'num', text: m[0], pos: i });
    } else if ((m = /^(&&|\|\||==|!=|>=|<=|>|<|!)/.exec(rest))) {
      out.push({ kind: 'op', text: m[0], pos: i });
    } else if ((m = /^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*/.exec(rest))) {
      out.push({ kind: 'id', text: m[0], pos: i });
    } else if ((m = /^[()[\],]/.exec(rest))) {
      out.push({ kind: 'punct', text: m[0], pos: i });
    } else {
      throw new ConditionParseError(`unexpected character ${JSON.stringify(c)}`, i);
    }
    i += m[0].length;
  }
  out.push({ kind: 'eof', text: '', pos: src.length });
  return out;
}

const METHODS: Record<string, string> = { contains: 'contains', startsWith: 'beginsWith', endsWith: 'endsWith' };

/**
 * Parses condition text into a tree (a group at the top). Empty text is the
 * empty group: the rule matches every event of its types.
 */
export function parseAlertCondition(src: string, types: FieldTypes = ALERT_FIELD_TYPES): ConditionGroup {
  if (src.trim() === '') return { combinator: 'and', rules: [] };
  const toks = lex(src);
  let p = 0;
  const end: Tok = { kind: 'eof', text: '', pos: src.length };
  const peek = () => toks[p] ?? end;
  const next = () => toks[p++] ?? end;
  const expect = (text: string) => {
    const t = next();
    if (t.text !== text) throw new ConditionParseError(`expected ${text}`, t.pos);
  };
  const group = (combinator: 'and' | 'or', parts: ConditionNode[]): ConditionNode => {
    const rules: ConditionNode[] = [];
    for (const part of parts) {
      if (isGroup(part) && part.combinator === combinator && !part.not) rules.push(...part.rules);
      else rules.push(part);
    }
    return { combinator, rules };
  };
  const literal = (f: string, t: Tok): unknown => {
    const type = types[f];
    if (type === 'double' || type === 'int') {
      if (t.kind !== 'num') throw new ConditionParseError(`${f} is a number`, t.pos);
      return Number(t.text);
    }
    if (type === 'bool') {
      if (t.text !== 'true' && t.text !== 'false') throw new ConditionParseError(`${f} needs true or false`, t.pos);
      return t.text === 'true';
    }
    if (t.kind !== 'str') throw new ConditionParseError(`${f} needs a quoted string`, t.pos);
    return t.text;
  };
  const primary = (): ConditionNode => {
    const t = peek();
    if (t.text === '(') {
      next();
      const e = or();
      expect(')');
      return e;
    }
    if (t.kind === 'str') {
      next();
      const kw = next();
      if (kw.text !== 'in') throw new ConditionParseError('expected in', kw.pos);
      const ft = next();
      if (ft.kind !== 'id' || types[ft.text] !== 'list') throw new ConditionParseError(`expected a list field after in`, ft.pos);
      return { field: ft.text, operator: 'contains', value: t.text };
    }
    const ft = next();
    if (ft.kind !== 'id') throw new ConditionParseError(ft.kind === 'eof' ? 'unexpected end' : `unexpected ${ft.text}`, ft.pos);
    // field.method("x"): the lexer reads the method as part of the name.
    let f = ft.text;
    let method: string | null = null;
    if (!(f in types)) {
      const dot = f.lastIndexOf('.');
      const name = dot > 0 ? f.slice(dot + 1) : '';
      if (dot > 0 && name in METHODS && f.slice(0, dot) in types) {
        method = name;
        f = f.slice(0, dot);
      } else {
        throw new ConditionParseError(`unknown field ${f}`, ft.pos);
      }
    }
    if (method) {
      if (types[f] !== 'string') throw new ConditionParseError(`${method} needs a text field`, ft.pos);
      expect('(');
      const s = next();
      if (s.kind !== 'str') throw new ConditionParseError('expected a quoted string', s.pos);
      expect(')');
      return { field: f, operator: METHODS[method] ?? method, value: s.text };
    }
    const op = next();
    if (op.kind === 'op' && ['==', '!=', '>', '>=', '<', '<='].includes(op.text)) {
      const type = types[f];
      if (['>', '>=', '<', '<='].includes(op.text) && type !== 'double' && type !== 'int') {
        throw new ConditionParseError(`operator ${op.text} is not valid for ${f}`, op.pos);
      }
      return { field: f, operator: op.text === '==' ? '=' : op.text, value: literal(f, next()) };
    }
    if (op.text === 'in') {
      expect('[');
      const items: string[] = [];
      while (peek().text !== ']') {
        const s = next();
        if (s.kind !== 'str') throw new ConditionParseError('expected a quoted string', s.pos);
        items.push(s.text);
        if (peek().text === ',') next();
        else if (peek().text !== ']') throw new ConditionParseError('expected , or ]', peek().pos);
      }
      expect(']');
      return { field: f, operator: 'in', value: items };
    }
    throw new ConditionParseError(`expected a comparison after ${f}`, op.pos);
  };
  const unary = (): ConditionNode => {
    if (peek().text === '!') {
      next();
      const inner = unary();
      if (isGroup(inner) && !inner.not) return { ...inner, not: true };
      return { combinator: 'and', not: true, rules: [inner] };
    }
    return primary();
  };
  const and = (): ConditionNode => {
    const parts = [unary()];
    while (peek().text === '&&') {
      next();
      parts.push(unary());
    }
    return parts.length === 1 && parts[0] ? parts[0] : group('and', parts);
  };
  const or = (): ConditionNode => {
    const parts = [and()];
    while (peek().text === '||') {
      next();
      parts.push(and());
    }
    return parts.length === 1 && parts[0] ? parts[0] : group('or', parts);
  };
  const tree = or();
  const last = peek();
  if (last.kind !== 'eof') throw new ConditionParseError(`unexpected ${last.text}`, last.pos);
  return isGroup(tree) ? tree : { combinator: 'and', rules: [tree] };
}

/** Drops leaves without a usable value (a half-filled builder row). */
function prune(node: ConditionNode): ConditionNode | null {
  if (isGroup(node)) {
    const rules = node.rules.map(prune).filter((r): r is ConditionNode => r !== null);
    if (rules.length === 0) return null;
    return { combinator: node.combinator, ...(node.not ? { not: true } : {}), rules };
  }
  const v = node.value;
  if (v === '' || v === null || v === undefined || (Array.isArray(v) && v.length === 0)) return null;
  return { field: node.field, operator: node.operator, value: v };
}

/** The text of a builder tree ('' when it holds nothing: always matches). */
export function alertConditionText(tree: ConditionNode, types: FieldTypes = ALERT_FIELD_TYPES): string {
  const pruned = prune(tree);
  if (!pruned) return '';
  return conditionText(pruned, types);
}
