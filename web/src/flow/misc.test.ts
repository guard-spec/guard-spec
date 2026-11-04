// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { locatePath, parsePath } from '../pages/yamlPath';
import { conditionText } from './conditionText';
import { ruleNameInError } from './FlowPage';
import { buildGraph } from './graph';
import { NODE } from './ids';
import { bounds, initialViewport, layoutGraph, PIPELINE } from './layout';
import { gatewayChain, toEditable } from './model';
import { FALLBACK_SCHEMA } from './schema';
import { sameCondition } from './RulePanel';
import { decidingIndex, simVars } from './Simulator';
import { baseline, t, upstream } from './testdata';

describe('conditionText', () => {
  const types = { 'scores.l2': 'double', 'request.tokens': 'int', 'request.model': 'string', 'anomaly.has_bidi': 'bool', 'pii.entities': 'list' } as const;

  it('renders leaves like JSONASTToCEL', () => {
    expect(conditionText({ field: 'scores.l2', operator: '>', value: '1' }, types)).toBe('scores.l2 > 1.0');
    expect(conditionText({ field: 'request.tokens', operator: '>=', value: 100 }, types)).toBe('request.tokens >= 100');
    expect(conditionText({ field: 'request.model', operator: '=', value: 'gpt-4o' }, types)).toBe('request.model == "gpt-4o"');
    expect(conditionText({ field: 'request.model', operator: 'contains', value: 'mini' }, types)).toBe('request.model.contains("mini")');
    expect(conditionText({ field: 'request.model', operator: 'in', value: 'a, b' }, types)).toBe('request.model in ["a", "b"]');
    expect(conditionText({ field: 'request.model', operator: 'notIn', value: ['a'] }, types)).toBe('!(request.model in ["a"])');
    expect(conditionText({ field: 'request.model', operator: 'beginsWith', value: 'gpt' }, types)).toBe('request.model.startsWith("gpt")');
    expect(conditionText({ field: 'pii.entities', operator: 'contains', value: 'EMAIL' }, types)).toBe('"EMAIL" in pii.entities');
    expect(conditionText({ field: 'anomaly.has_bidi', operator: '=', value: 'true' }, types)).toBe('anomaly.has_bidi == true');
    expect(conditionText({ field: 'request.model', operator: '=', value: 'say "hi"' }, types)).toBe('request.model == "say \\"hi\\""');
  });

  it('drops redundant parentheses but keeps needed ones', () => {
    const a = { field: 'scores.l2', operator: '>', value: '0.9' };
    const b = { field: 'request.model', operator: '=', value: 'x' };
    expect(conditionText({ combinator: 'and', rules: [a, b] }, types)).toBe('scores.l2 > 0.9 && request.model == "x"');
    expect(conditionText({ combinator: 'or', rules: [{ combinator: 'and', rules: [a, b] }, b] }, types)).toBe(
      'scores.l2 > 0.9 && request.model == "x" || request.model == "x"',
    );
    expect(conditionText({ combinator: 'and', rules: [{ combinator: 'or', rules: [a, b] }, b] }, types)).toBe(
      '(scores.l2 > 0.9 || request.model == "x") && request.model == "x"',
    );
    expect(conditionText({ combinator: 'and', not: true, rules: [a, b] }, types)).toBe('!(scores.l2 > 0.9 && request.model == "x")');
    expect(conditionText({ combinator: 'and', rules: [{ combinator: 'or', rules: [a] }] }, types)).toBe('scores.l2 > 0.9');
    expect(conditionText(null)).toBe('');
  });
});

describe('layout', () => {
  const g = buildGraph({
    chain: gatewayChain([toEditable(baseline)], null),
    upstreams: [upstream('main'), upstream('safe')],
    defaultUpstream: { source: 'org', name: 'main' },
    guard: null,
    scopeLabel: 'any',
    t,
  });

  it('top to bottom: the pipeline is a row above the rules, rules go down', () => {
    const nodes = layoutGraph(g.nodes, g.edges, 'TB');
    const at = (id: string) => nodes.find((n) => n.id === id);
    const row = PIPELINE.map((id) => at(id));
    const ys = row.map((n) => (n?.position.y ?? 0) + (n?.height ?? 0) / 2);
    expect(new Set(ys.map(Math.round)).size).toBe(1); // one row
    for (let i = 1; i < row.length; i++) expect(row[i]?.position.x).toBeGreaterThan(row[i - 1]?.position.x ?? 0);
    const r = ['r1', 'r2', 'r3', 'r4'].map((k) => at(NODE.rule(k))?.position.y ?? 0);
    expect(r).toEqual([...r].sort((a, b) => a - b));
    expect(Math.max(...ys)).toBeLessThan(r[0] ?? 0);
    expect(nodes.every((n) => n.width && n.height)).toBe(true);
  });

  it('left to right: rules go right', () => {
    const nodes = layoutGraph(g.nodes, g.edges, 'LR');
    const x = ['r1', 'r2', 'r3', 'r4'].map((k) => nodes.find((n) => n.id === NODE.rule(k))?.position.x ?? 0);
    expect(x).toEqual([...x].sort((a, b) => a - b));
  });

  it('starts at a readable zoom, top aligned', () => {
    const b = { x: 0, y: 0, width: 2000, height: 3000 };
    expect(initialViewport(b, { width: 1000, height: 700 }).zoom).toBe(0.6);
    expect(initialViewport({ ...b, width: 500 }, { width: 1000, height: 700 }).zoom).toBe(1);
    expect(initialViewport(b, { width: 1000, height: 700 }).y).toBe(24);
    expect(bounds([])).toEqual({ x: 0, y: 0, width: 0, height: 0 });
  });
});

describe('simVars', () => {
  it('types the form values and leaves out empty ones', () => {
    const vars = simVars(FALLBACK_SCHEMA, {
      'request.model': ' gpt-4o ',
      'request.tokens': '12.7',
      'scores.l2': '0.91',
      'anomaly.has_bidi': 'true',
      'mcp.is_tool_response': 'false',
      'scores.l1': '',
      'injection.category': '   ',
    });
    expect(vars).toEqual({
      'request.model': 'gpt-4o',
      'request.tokens': 12,
      'scores.l2': 0.91,
      'anomaly.has_bidi': true,
      'mcp.is_tool_response': false,
    });
  });
});

describe('sameCondition', () => {
  it('ignores builder ids and a leaf wrapped in a group', () => {
    const leaf = { field: 'scores.l2', operator: '>', value: 0.9 };
    expect(sameCondition({ id: 'g', combinator: 'and', not: false, rules: [{ ...leaf, id: 'r', valueSource: 'value' }] }, leaf)).toBe(true);
    expect(sameCondition({ combinator: 'and', rules: [{ ...leaf, value: 0.8 }] }, leaf)).toBe(false);
  });
});

describe('decidingIndex', () => {
  it('finds the first allow, block or route match; log matches do not decide', () => {
    const e = (matched: boolean, action: 'allow' | 'block' | 'log' | 'route') => ({ rule_name: 'r', matched, action });
    expect(decidingIndex([e(false, 'block'), e(true, 'log'), e(true, 'route'), e(true, 'block')])).toBe(2);
    expect(decidingIndex([e(true, 'log'), e(false, 'allow')])).toBe(-1);
  });
});

describe('ruleNameInError', () => {
  it('finds the rule a server error names', () => {
    expect(ruleNameInError('rule "high l2": unknown field: x')).toBe('high l2');
    expect(ruleNameInError('a policy may hold at most 200 rules')).toBeUndefined();
  });
});

describe('locatePath', () => {
  const doc = [
    'version: 1',
    'default_upstream: main',
    'upstreams:',
    '  - name: main',
    '    base_url: https://a',
    'policies:',
    '  - name: p0',
    '    rules:',
    '      - name: r0',
    '        when: a > 1',
    '      - name: r1',
    '        when: bad',
    '        action: block',
    '  - name: p1',
    '    rules:',
    '    - name: q0',
    '      when: x',
  ].join('\n');
  const lineOf = (off: number | undefined) => (off === undefined ? -1 : doc.slice(0, off).split('\n').length);

  it('parses paths', () => {
    expect(parsePath('policies[0].rules[1].when')).toEqual([{ key: 'policies' }, { index: 0 }, { key: 'rules' }, { index: 1 }, { key: 'when' }]);
  });

  it('finds the line of a path', () => {
    expect(lineOf(locatePath(doc, 'default_upstream'))).toBe(2);
    expect(lineOf(locatePath(doc, 'upstreams[0].base_url'))).toBe(5);
    expect(lineOf(locatePath(doc, 'policies[0].rules[1].when'))).toBe(12);
    expect(lineOf(locatePath(doc, 'policies[0].rules[1]'))).toBe(11);
    expect(lineOf(locatePath(doc, 'policies[1].rules[0].when'))).toBe(17);
    expect(lineOf(locatePath(doc, 'policies[1].name'))).toBe(14);
    expect(locatePath(doc, 'policies[5].name')).toBeUndefined();
    expect(locatePath(doc, 'nothing')).toBeUndefined();
  });
});
