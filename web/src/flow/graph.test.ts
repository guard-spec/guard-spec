// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { SimulateResponse } from '../types';
import { applyHighlight, buildGraph, edgeId, effectiveScanRoles, simulationPath, type GraphInput, type RuleData } from './graph';
import { NODE } from './ids';
import { gatewayChain, toEditable } from './model';
import { baseline, projectPolicy, t, upstream } from './testdata';

function input(over: Partial<GraphInput> = {}): GraphInput {
  return {
    chain: gatewayChain([toEditable(baseline), toEditable(projectPolicy)], null),
    upstreams: [upstream('main'), upstream('safe')],
    defaultUpstream: { source: 'org', name: 'main' },
    guard: null,
    scopeLabel: 'any key',
    fieldTypes: { 'scores.l2': 'double', 'injection.score': 'double', 'indirect.score': 'double' },
    t,
    ...over,
  };
}

const ids = (xs: { id: string }[]) => xs.map((x) => x.id);

describe('buildGraph', () => {
  it('builds the pipeline, the rule chain and the terminals', () => {
    const g = buildGraph(input());
    expect(ids(g.nodes)).toEqual(
      expect.arrayContaining([NODE.request, NODE.key, NODE.l0, NODE.detectors, NODE.block, NODE.log, NODE.allow, NODE.output, NODE.client]),
    );
    const rules = g.nodes.filter((n) => n.data.kind === 'rule').map((n) => n.data as RuleData);
    // Org scope: the project policy does not apply.
    expect(rules.map((r) => r.name)).toEqual(['high l2', 'log tools', 'to safe', 'trusted']);
    expect(rules.map((r) => r.position)).toEqual([1, 2, 3, 4]);
    expect(rules[0]?.text).toBe('scores.l2 > 0.9 && injection.category != "benign"');
    expect(rules[1]?.text).toBe('indirect.score >= 0.5');

    const e = ids(g.edges);
    expect(e).toContain(edgeId(NODE.request, NODE.key, 'flow'));
    expect(e).toContain(edgeId(NODE.l0, NODE.detectors, 'flow'));
    expect(e).toContain(edgeId(NODE.detectors, NODE.rule('r1'), 'flow'));
    expect(e).toContain(edgeId(NODE.rule('r1'), NODE.rule('r2'), 'next'));
    expect(e).toContain(edgeId(NODE.rule('r1'), NODE.block, 'match'));
    expect(e).toContain(edgeId(NODE.rule('r2'), NODE.log, 'log'));
    expect(e).toContain(edgeId(NODE.rule('r3'), NODE.upstream('safe'), 'match'));
    expect(e).toContain(edgeId(NODE.rule('r4'), NODE.allow, 'match'));
    // The last rule falls through to Allow, which goes to the default upstream.
    expect(e).toContain(edgeId(NODE.rule('r4'), NODE.allow, 'next'));
    expect(e).toContain(edgeId(NODE.allow, NODE.upstream('main'), 'default'));
    expect(e).toContain(edgeId(NODE.upstream('main'), NODE.output, 'flow'));
    expect(e).toContain(edgeId(NODE.output, NODE.client, 'flow'));
    expect(e).toContain(edgeId(NODE.block, NODE.client, 'flow'));
    // Edges leave rules through their handles.
    expect(g.edges.find((x) => x.id === edgeId(NODE.rule('r1'), NODE.block, 'match'))?.sourceHandle).toBe('match');
    expect(g.edges.find((x) => x.id === edgeId(NODE.rule('r1'), NODE.rule('r2'), 'next'))?.sourceHandle).toBe('next');
    // Edge ids are unique.
    expect(new Set(e).size).toBe(e.length);
  });

  it('puts project policies first for a project scope', () => {
    const g = buildGraph(input({ chain: gatewayChain([toEditable(baseline), toEditable(projectPolicy)], 'proj-1') }));
    const first = g.nodes.find((n) => n.data.kind === 'rule' && n.data.position === 1);
    expect(first?.id).toBe(NODE.rule('r9'));
  });

  it('marks the default upstream and idle upstreams', () => {
    const g = buildGraph(input({ upstreams: [upstream('main'), upstream('safe'), upstream('spare')] }));
    const main = g.nodes.find((n) => n.id === NODE.upstream('main'));
    expect(main?.data).toMatchObject({ kind: 'upstream', isDefault: true });
    expect(g.edges.find((e) => e.source === NODE.upstream('spare'))?.data?.kind).toBe('idle');
    expect(g.edges.find((e) => e.source === NODE.upstream('safe'))?.data?.kind).toBe('flow');
  });

  it('uses the gateway upstream when no default is set', () => {
    const g = buildGraph(input({ defaultUpstream: { source: 'env' } }));
    expect(ids(g.nodes)).toContain(NODE.envUpstream);
    expect(ids(g.edges)).toContain(edgeId(NODE.allow, NODE.envUpstream, 'default'));
  });

  it('adds a missing node for a route target that names no upstream', () => {
    const g = buildGraph(input({ upstreams: [upstream('main')] }));
    expect(g.nodes.find((n) => n.id === NODE.upstream('safe'))?.data).toMatchObject({ missing: true });
  });

  it('goes straight from the detectors to Allow without rules', () => {
    const g = buildGraph(input({ chain: [] }));
    expect(ids(g.edges)).toContain(edgeId(NODE.detectors, NODE.allow, 'flow'));
    expect(g.nodes.filter((n) => n.data.kind === 'rule')).toHaveLength(0);
  });

  it('shows the scan roles and turns the detectors off when nothing is scanned', () => {
    expect(effectiveScanRoles(null)).toEqual(['user', 'tool', 'tool_descriptions']);
    expect(effectiveScanRoles({ scan_roles: { system: true, tool: false } })).toEqual(['user', 'system', 'tool_descriptions']);
    const off = buildGraph(input({ guard: { scan_roles: { user: false, tool: false, tool_descriptions: false } } }));
    const det = off.nodes.find((n) => n.id === NODE.detectors);
    expect(det?.data).toMatchObject({ status: 'off' });
    expect((det?.data as { layers: { on: boolean }[] }).layers.every((l) => !l.on)).toBe(true);
  });

  it('puts rule errors on their nodes', () => {
    const g = buildGraph(input({ ruleErrors: { r3: 'bad target' } }));
    expect(g.nodes.find((n) => n.id === NODE.rule('r3'))?.data).toMatchObject({ error: 'bad target' });
  });
});

describe('simulationPath', () => {
  const g = buildGraph(input());

  it('follows a route decision through the log rule to its upstream', () => {
    const res: SimulateResponse = {
      trace: [
        { rule_id: 'r1', rule_name: 'high l2', matched: false, action: 'block' },
        { rule_id: 'r2', rule_name: 'log tools', matched: true, action: 'log' },
        { rule_id: 'r3', rule_name: 'to safe', matched: true, action: 'route' },
      ],
      decision: { action: 'route', rule_id: 'r3', route_target: 'safe' },
      upstream: { source: 'rule', name: 'safe', base_url: 'x' },
    };
    const p = simulationPath(g, res);
    expect(p.decidedBy).toBe(NODE.rule('r3'));
    expect([...p.edges]).toEqual(
      expect.arrayContaining([
        edgeId(NODE.detectors, NODE.rule('r1'), 'flow'),
        edgeId(NODE.rule('r1'), NODE.rule('r2'), 'next'),
        edgeId(NODE.rule('r2'), NODE.log, 'log'),
        edgeId(NODE.rule('r2'), NODE.rule('r3'), 'next'),
        edgeId(NODE.rule('r3'), NODE.upstream('safe'), 'match'),
        edgeId(NODE.upstream('safe'), NODE.output, 'flow'),
        edgeId(NODE.output, NODE.client, 'flow'),
      ]),
    );
    expect(p.nodes.has(NODE.block)).toBe(false);
    expect(p.nodes.has(NODE.rule('r4'))).toBe(false);
  });

  it('follows a block to the client', () => {
    const p = simulationPath(g, {
      trace: [{ rule_id: 'r1', rule_name: 'high l2', matched: true, action: 'block' }],
      decision: { action: 'block', rule_id: 'r1' },
      upstream: null,
    });
    expect(p.edges.has(edgeId(NODE.rule('r1'), NODE.block, 'match'))).toBe(true);
    expect(p.edges.has(edgeId(NODE.block, NODE.client, 'flow'))).toBe(true);
    expect(p.nodes.has(NODE.output)).toBe(false);
  });

  it('falls through to Allow and the default upstream; matches trace entries by position', () => {
    const p = simulationPath(g, {
      trace: [
        { rule_name: 'high l2', matched: false, action: 'block' },
        { rule_name: 'log tools', matched: false, action: 'log' },
        { rule_name: 'to safe', matched: false, action: 'route' },
        { rule_name: 'trusted', matched: false, action: 'allow' },
      ],
      decision: { action: 'allow' },
      upstream: { source: 'org', name: 'main' },
    });
    expect(p.decidedBy).toBeUndefined();
    expect(p.edges.has(edgeId(NODE.rule('r4'), NODE.allow, 'next'))).toBe(true);
    expect(p.edges.has(edgeId(NODE.allow, NODE.upstream('main'), 'default'))).toBe(true);
    expect(p.edges.has(edgeId(NODE.upstream('main'), NODE.output, 'flow'))).toBe(true);
  });

  it('stops where the gateway would fail closed', () => {
    const p = simulationPath(g, {
      trace: [{ rule_id: 'r1', rule_name: 'high l2', matched: false, action: 'block', error: 'cost budget exceeded' }],
      decision: { action: 'error', error: 'cost budget exceeded' },
    });
    expect(p.nodes.has(NODE.allow)).toBe(false);
    expect(p.nodes.has(NODE.client)).toBe(false);
    expect(p.nodes.has(NODE.rule('r1'))).toBe(true);
  });

  it('matches unsaved rules by position when the server gave them new ids', () => {
    const p = simulationPath(g, {
      trace: [
        { rule_id: 'server-1', rule_name: 'high l2', matched: false, action: 'block' },
        { rule_id: 'server-2', rule_name: 'log tools', matched: false, action: 'log' },
        { rule_id: 'server-3', rule_name: 'to safe', matched: true, action: 'route' },
      ],
      decision: { action: 'route', route_target: 'safe' },
      upstream: { source: 'rule', name: 'safe' },
    });
    expect(p.decidedBy).toBe(NODE.rule('r3'));
  });

  it('marks nodes on and off the path', () => {
    const p = simulationPath(g, {
      trace: [{ rule_id: 'r1', rule_name: 'high l2', matched: true, action: 'block' }],
      decision: { action: 'block', rule_id: 'r1' },
    });
    const h = applyHighlight(g, p);
    expect(h.nodes.find((n) => n.id === NODE.rule('r1'))?.className).toBe('hl-match');
    expect(h.nodes.find((n) => n.id === NODE.block)?.className).toBe('hl-path');
    expect(h.nodes.find((n) => n.id === NODE.rule('r2'))?.className).toBe('hl-dim');
    expect(h.edges.find((e) => e.id === edgeId(NODE.rule('r1'), NODE.block, 'match'))?.className).toBe('hl-path');
    expect(applyHighlight(g, null)).toBe(g);
  });
});
