// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Builds the Flow diagram (nodes and edges, without positions) from the
// policies of a scope, the org's upstreams and guard settings, and computes
// the path a simulated request takes through it.

import type { Edge, Node } from '@xyflow/react';
import {
  DEFAULT_SCAN_ROLES,
  SCAN_ROLES,
  type Action,
  type GuardSettings,
  type ScanRole,
  type SimulateResponse,
  type Upstream,
} from '../types';
import { conditionText, ellipsize, type FieldTypes } from './conditionText';
import { NODE } from './ids';
import type { EditablePolicy } from './model';

export type Highlight = 'path' | 'match' | undefined;

export interface StepData extends Record<string, unknown> {
  kind: 'step';
  role: 'request' | 'key' | 'sanitizer' | 'detector' | 'output' | 'client';
  title: string;
  subtitle: string;
  status: 'on' | 'off';
  /** The detection layers, for the detectors node. */
  layers?: { name: string; on: boolean }[];
  hl?: Highlight;
}

export interface RuleData extends Record<string, unknown> {
  kind: 'rule';
  ruleKey: string;
  policyKey: string;
  policyName: string;
  /** 1-based position in the chain. */
  position: number;
  name: string;
  text: string;
  action: Action;
  routeTarget: string | undefined;
  error: string | undefined;
  hl?: Highlight;
}

export interface TerminalData extends Record<string, unknown> {
  kind: 'terminal';
  variant: 'block' | 'allow' | 'log';
  title: string;
  subtitle: string;
  hl?: Highlight;
}

export interface UpstreamData extends Record<string, unknown> {
  kind: 'upstream';
  name: string;
  title: string;
  subtitle: string;
  enabled: boolean;
  /** This upstream is the default for the scope. */
  isDefault: boolean;
  /** A route rule names it, but the org has no such upstream. */
  missing: boolean;
  hl?: Highlight;
}

export type FlowData = StepData | RuleData | TerminalData | UpstreamData;
export type FlowNode = Node<FlowData>;

export type EdgeKind = 'flow' | 'next' | 'match' | 'log' | 'default' | 'idle';
export interface FlowEdgeData extends Record<string, unknown> {
  kind: EdgeKind;
  hl?: Highlight;
}
export type FlowEdge = Edge<FlowEdgeData>;

export interface DefaultUpstream {
  /** Where the default comes from: the project, the org, or none (the gateway's env/stub). */
  source: 'project' | 'org' | 'env';
  name?: string;
}

export interface GraphInput {
  chain: EditablePolicy[];
  upstreams: Upstream[];
  defaultUpstream: DefaultUpstream;
  guard: GuardSettings | null;
  /** Label of the key/project step, e.g. "Project: billing" or "Any API key". */
  scopeLabel: string;
  fieldTypes?: FieldTypes;
  /** Errors to show on rule nodes, by rule key. */
  ruleErrors?: Readonly<Record<string, string>>;
  t: (key: string, params?: Record<string, string | number>) => string;
}

export function edgeId(source: string, target: string, kind: EdgeKind): string {
  return `e:${source}>${target}:${kind}`;
}

/** The scan roles in effect: the gateway defaults with the org's overrides. */
export function effectiveScanRoles(guard: GuardSettings | null): ScanRole[] {
  return SCAN_ROLES.filter((r) => guard?.scan_roles?.[r] ?? DEFAULT_SCAN_ROLES[r]);
}

export function buildGraph(input: GraphInput): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const { t } = input;
  const nodes: FlowNode[] = [];
  const edges: FlowEdge[] = [];
  const at = { x: 0, y: 0 };

  const step = (id: string, role: StepData['role'], title: string, subtitle: string, status: 'on' | 'off' = 'on', layers?: StepData['layers']) => {
    const data: StepData = { kind: 'step', role, title, subtitle, status };
    if (layers) data.layers = layers;
    nodes.push({ id, type: role === 'detector' ? 'detectors' : 'step', position: at, data });
  };
  const edge = (source: string, target: string, kind: EdgeKind, label?: string, sourceHandle?: string) => {
    const e: FlowEdge = { id: edgeId(source, target, kind), source, target, data: { kind } };
    if (label) e.label = label;
    if (sourceHandle) e.sourceHandle = sourceHandle;
    edges.push(e);
  };

  // Request -> key/project -> L0 -> detectors (L1, L2, L3)
  const roles = effectiveScanRoles(input.guard);
  const scans = roles.length > 0 ? roles.join(', ') : t('flow.scansNothing');
  const detectorStatus = roles.length > 0 ? 'on' : 'off';
  const spotlight = input.guard?.spotlight ?? t('flow.gatewayDefault');
  step(NODE.request, 'request', t('flow.request'), t('flow.requestSub'));
  step(NODE.key, 'key', t('flow.apiKey'), input.scopeLabel);
  step(NODE.l0, 'sanitizer', t('flow.l0'), t('flow.l0Sub', { spotlight }));
  const on = detectorStatus === 'on';
  step(NODE.detectors, 'detector', t('flow.detectors'), t('flow.scans', { roles: scans }), detectorStatus, [
    { name: t('flow.l1'), on },
    { name: t('flow.l2'), on },
    { name: t('flow.l3'), on },
  ]);
  edge(NODE.request, NODE.key, 'flow');
  edge(NODE.key, NODE.l0, 'flow');
  edge(NODE.l0, NODE.detectors, 'flow');

  // Terminals
  nodes.push({
    id: NODE.block,
    type: 'terminal',
    position: at,
    data: { kind: 'terminal', variant: 'block', title: t('flow.block'), subtitle: t('flow.blockSub') },
  });
  nodes.push({
    id: NODE.log,
    type: 'terminal',
    position: at,
    data: { kind: 'terminal', variant: 'log', title: t('flow.log'), subtitle: t('flow.logSub') },
  });
  nodes.push({
    id: NODE.allow,
    type: 'terminal',
    position: at,
    data: { kind: 'terminal', variant: 'allow', title: t('flow.allow'), subtitle: t('flow.allowSub') },
  });

  // Upstreams: every upstream of the org is a target a rule can be connected to.
  const known = new Set(input.upstreams.map((u) => u.name));
  const used = new Set<string>();
  const def = input.defaultUpstream;
  const defaultName = def.source !== 'env' && def.name && known.has(def.name) ? def.name : undefined;
  for (const u of input.upstreams) {
    const isDefault = u.name === defaultName;
    nodes.push({
      id: NODE.upstream(u.name),
      type: 'upstream',
      position: at,
      data: {
        kind: 'upstream',
        name: u.name,
        title: u.name,
        subtitle: (u.model ? `${u.model} · ` : '') + u.base_url,
        enabled: u.enabled,
        isDefault,
        missing: false,
      },
    });
  }
  const missing = new Set<string>();
  const upstreamNode = (name: string): string => {
    if (!known.has(name) && !missing.has(name)) {
      missing.add(name);
      nodes.push({
        id: NODE.upstream(name),
        type: 'upstream',
        position: at,
        data: {
          kind: 'upstream',
          name,
          title: name,
          subtitle: t('flow.missingUpstream'),
          enabled: false,
          isDefault: false,
          missing: true,
        },
      });
    }
    used.add(name);
    return NODE.upstream(name);
  };

  // Rules, in gateway order.
  const rules = input.chain.flatMap((p) => p.rules.map((r) => ({ p, r })));
  let prev: string = NODE.detectors;
  let prevHandle: string | undefined;
  rules.forEach(({ p, r }, i) => {
    const id = NODE.rule(r.key);
    nodes.push({
      id,
      type: 'rule',
      position: at,
      data: {
        kind: 'rule',
        ruleKey: r.key,
        policyKey: p.key,
        policyName: p.name,
        position: i + 1,
        name: r.name || t('flow.unnamedRule'),
        text: ellipsize(conditionText(r.condition, input.fieldTypes)),
        action: r.action,
        routeTarget: r.route_target,
        error: input.ruleErrors?.[r.key],
      },
    });
    edge(prev, id, prev === NODE.detectors ? 'flow' : 'next', prev === NODE.detectors ? undefined : t('flow.noMatch'), prevHandle);
    switch (r.action) {
      case 'block':
        edge(id, NODE.block, 'match', t('flow.match'), 'match');
        break;
      case 'allow':
        edge(id, NODE.allow, 'match', t('flow.match'), 'match');
        break;
      case 'log':
        edge(id, NODE.log, 'log', t('flow.matchContinue'), 'match');
        break;
      case 'route':
        edge(id, upstreamNode(r.route_target ?? ''), 'match', t('flow.match'), 'match');
        break;
    }
    prev = id;
    prevHandle = 'next';
  });
  // No rule decided: allow.
  edge(prev, NODE.allow, prev === NODE.detectors ? 'flow' : 'next', prev === NODE.detectors ? undefined : t('flow.noMatch'), prevHandle);

  // Allow -> the default upstream (project, org, or the gateway's env/stub).
  let defaultTarget: string;
  if (defaultName) {
    defaultTarget = upstreamNode(defaultName);
  } else {
    nodes.push({
      id: NODE.envUpstream,
      type: 'upstream',
      position: at,
      data: {
        kind: 'upstream',
        name: '',
        title: t('flow.envUpstream'),
        subtitle: t('flow.envUpstreamSub'),
        enabled: true,
        isDefault: true,
        missing: false,
      },
    });
    defaultTarget = NODE.envUpstream;
  }
  edge(NODE.allow, defaultTarget, 'default', t('flow.default'));

  // Upstreams -> output guard -> client; Block answers the client directly.
  step(NODE.output, 'output', t('flow.output'), t('flow.outputSub'));
  step(NODE.client, 'client', t('flow.client'), t('flow.clientSub'));
  for (const n of nodes) {
    if (n.data.kind !== 'upstream') continue;
    const active = n.id === defaultTarget || used.has(n.data.name);
    edge(n.id, NODE.output, active ? 'flow' : 'idle');
  }
  edge(NODE.output, NODE.client, 'flow');
  edge(NODE.block, NODE.client, 'flow', t('flow.blockedAnswer'));
  return { nodes, edges };
}

export interface SimPath {
  nodes: Set<string>;
  edges: Set<string>;
  /** The rule that decided, if any. */
  decidedBy: string | undefined;
}

/**
 * The path of a simulated request: the pipeline, every rule the trace shows
 * as evaluated, the edge each one took, and the decision's terminal and
 * upstream. Trace entries are matched to rules by id, then by position.
 */
export function simulationPath(graph: { nodes: FlowNode[]; edges: FlowEdge[] }, res: SimulateResponse): SimPath {
  const nodes = new Set<string>([NODE.request, NODE.key, NODE.l0, NODE.detectors]);
  const edges = new Set<string>();
  const edgeSet = new Set(graph.edges.map((e) => e.id));
  const add = (source: string, target: string, kind: EdgeKind) => {
    const id = edgeId(source, target, kind);
    if (edgeSet.has(id)) edges.add(id);
    nodes.add(target);
  };
  add(NODE.request, NODE.key, 'flow');
  add(NODE.key, NODE.l0, 'flow');
  add(NODE.l0, NODE.detectors, 'flow');

  const ruleNodes = graph.nodes.filter((n): n is Node<RuleData> => n.data.kind === 'rule');
  const byId = new Map<string, Node<RuleData>>();
  for (const n of ruleNodes) byId.set(n.data.ruleKey, n);

  let prev: string = NODE.detectors;
  let decidedBy: string | undefined;
  for (const [i, entry] of res.trace.entries()) {
    const node = (entry.rule_id ? byId.get(entry.rule_id) : undefined) ?? ruleNodes[i];
    if (!node) break;
    add(prev, node.id, prev === NODE.detectors ? 'flow' : 'next');
    if (entry.matched) {
      if (entry.action === 'log') {
        add(node.id, NODE.log, 'log');
      } else {
        decidedBy = node.id;
        break;
      }
    }
    prev = node.id;
  }

  const upstreamTarget = (): string => {
    const name = res.upstream?.name;
    if (res.upstream && res.upstream.source !== 'env' && res.upstream.source !== 'stub' && name) {
      return NODE.upstream(name);
    }
    return NODE.envUpstream;
  };

  const action = res.decision.action;
  // The gateway would fail closed (503): the request stops where the error was.
  if (action === 'error') return { nodes, edges, decidedBy };
  if (decidedBy) {
    const kind: EdgeKind = 'match';
    if (action === 'block') {
      add(decidedBy, NODE.block, kind);
      add(NODE.block, NODE.client, 'flow');
      return { nodes, edges, decidedBy };
    }
    if (action === 'route') {
      const up = res.decision.route_target ? NODE.upstream(res.decision.route_target) : upstreamTarget();
      add(decidedBy, up, kind);
      add(up, NODE.output, 'flow');
      add(NODE.output, NODE.client, 'flow');
      return { nodes, edges, decidedBy };
    }
    add(decidedBy, NODE.allow, kind);
  } else {
    // No rule decided: default allow from the last evaluated rule.
    add(prev, NODE.allow, prev === NODE.detectors ? 'flow' : 'next');
    if (action === 'block') {
      // Should not happen; show the terminal anyway.
      nodes.add(NODE.block);
      return { nodes, edges, decidedBy };
    }
  }
  const up = upstreamTarget();
  const defaultEdge = graph.edges.find((e) => e.source === NODE.allow);
  if (defaultEdge?.target === up) edges.add(defaultEdge.id);
  nodes.add(up);
  add(up, NODE.output, 'flow');
  add(NODE.output, NODE.client, 'flow');
  return { nodes, edges, decidedBy };
}

/** Marks the nodes and edges of a simulated path. */
export function applyHighlight(graph: { nodes: FlowNode[]; edges: FlowEdge[] }, path: SimPath | null): { nodes: FlowNode[]; edges: FlowEdge[] } {
  if (!path) return graph;
  return {
    nodes: graph.nodes.map((n) => {
      const hl: Highlight = n.id === path.decidedBy ? 'match' : path.nodes.has(n.id) ? 'path' : undefined;
      return { ...n, data: { ...n.data, hl }, className: hl ? `hl-${hl}` : 'hl-dim' };
    }),
    edges: graph.edges.map((e) => {
      const on = path.edges.has(e.id);
      return { ...e, className: on ? 'hl-path' : 'hl-dim', data: { kind: e.data?.kind ?? 'flow', hl: on ? 'path' : undefined } };
    }),
  };
}
