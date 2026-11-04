// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Automatic layout of the Flow diagram with dagre (MIT).
//
// Left to right: dagre lays out every node. Top to bottom (the default):
// the request pipeline (request, API key, L0, detectors) is a row on top, and
// dagre lays out the rules, terminals and upstreams below it, so the rule
// chain reads downwards and the diagram stays legible without zooming out.

import { Graph, layout } from '@dagrejs/dagre';
import type { FlowEdge, FlowNode } from './graph';
import { NODE } from './ids';

export type Direction = 'LR' | 'TB';

export const NODE_SIZE: Record<string, { width: number; height: number }> = {
  step: { width: 220, height: 66 },
  detectors: { width: 220, height: 142 },
  rule: { width: 300, height: 108 },
  terminal: { width: 180, height: 66 },
  upstream: { width: 240, height: 66 },
};

/** The pipeline steps that form the top row of the top-to-bottom layout. */
export const PIPELINE: readonly string[] = [NODE.request, NODE.key, NODE.l0, NODE.detectors];

const ROW_GAP = 36;
const RANK_GAP = 46;

export function sizeOf(type: string | undefined): { width: number; height: number } {
  return NODE_SIZE[type ?? 'step'] ?? { width: 170, height: 64 };
}

function dagreLayout(nodes: FlowNode[], edges: FlowEdge[], direction: Direction): FlowNode[] {
  const g = new Graph({ multigraph: true });
  g.setGraph({ rankdir: direction, nodesep: 40, ranksep: direction === 'TB' ? RANK_GAP : 64, edgesep: 14, marginx: 16, marginy: 16 });
  g.setDefaultEdgeLabel(() => ({}));
  const ids = new Set(nodes.map((n) => n.id));
  for (const n of nodes) g.setNode(n.id, { ...sizeOf(n.type) });
  for (const e of edges) {
    if (!ids.has(e.source) || !ids.has(e.target)) continue;
    // The rule chain and the main path weigh more, so they stay straight.
    g.setEdge(e.source, e.target, { weight: e.data?.kind === 'next' || e.data?.kind === 'flow' ? 4 : 1, minlen: 1 }, e.id);
  }
  layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id) as { x: number; y: number } | undefined;
    const { width, height } = sizeOf(n.type);
    return { ...n, width, height, position: p ? { x: p.x - width / 2, y: p.y - height / 2 } : { x: 0, y: 0 } };
  });
}

/** Returns the nodes with positions (top-left corners) and their sizes set. */
export function layoutGraph(nodes: FlowNode[], edges: FlowEdge[], direction: Direction = 'TB'): FlowNode[] {
  if (direction === 'LR') return dagreLayout(nodes, edges, direction);

  const pipeline = nodes.filter((n) => PIPELINE.includes(n.id));
  const rest = dagreLayout(
    nodes.filter((n) => !PIPELINE.includes(n.id)),
    edges,
    direction,
  );
  // The row sits above the node the detectors lead to (the first rule, or Allow).
  const firstId = edges.find((e) => e.source === NODE.detectors)?.target;
  const first = rest.find((n) => n.id === firstId);
  const top = Math.min(...rest.map((n) => n.position.y));
  const rowHeight = Math.max(...pipeline.map((n) => sizeOf(n.type).height));
  const rowWidth = pipeline.reduce((w, n) => w + sizeOf(n.type).width, 0) + ROW_GAP * (pipeline.length - 1);
  // The detectors node (last) ends above the first rule's centre.
  const anchor = first ? first.position.x + (first.width ?? 0) / 2 : rowWidth / 2;
  const lastWidth = sizeOf(pipeline[pipeline.length - 1]?.type).width;
  let x = anchor + lastWidth / 2 - rowWidth;
  const y = top - RANK_GAP - rowHeight;
  const placed = new Map<string, FlowNode>();
  for (const id of PIPELINE) {
    const n = pipeline.find((p) => p.id === id);
    if (!n) continue;
    const { width, height } = sizeOf(n.type);
    placed.set(id, { ...n, width, height, position: { x, y: y + (rowHeight - height) / 2 } });
    x += width + ROW_GAP;
  }
  return nodes.map((n) => placed.get(n.id) ?? rest.find((r) => r.id === n.id) ?? n);
}

/** The bounding box of laid-out nodes. */
export function bounds(nodes: FlowNode[]): { x: number; y: number; width: number; height: number } {
  if (nodes.length === 0) return { x: 0, y: 0, width: 0, height: 0 };
  const xs = nodes.map((n) => n.position.x);
  const ys = nodes.map((n) => n.position.y);
  const x2 = nodes.map((n) => n.position.x + (n.width ?? 0));
  const y2 = nodes.map((n) => n.position.y + (n.height ?? 0));
  const x = Math.min(...xs);
  const y = Math.min(...ys);
  return { x, y, width: Math.max(...x2) - x, height: Math.max(...y2) - y };
}

/**
 * The initial viewport: the diagram's width fits the pane at a zoom between
 * min and 1, aligned to the top, so the start of the flow is readable.
 */
export function initialViewport(
  b: { x: number; y: number; width: number; height: number },
  pane: { width: number; height: number },
  min = 0.6,
): { x: number; y: number; zoom: number } {
  const pad = 24;
  const zoom = Math.max(min, Math.min(1, (pane.width - 2 * pad) / Math.max(b.width, 1)));
  const x = (pane.width - b.width * zoom) / 2 - b.x * zoom;
  const y = pad - b.y * zoom;
  return { x, y, zoom };
}

/**
 * The whole diagram in view, centred (as the fit view control): the opening
 * view of the flow page. The zoom stays between min and 1.
 */
export function fitViewport(
  b: { x: number; y: number; width: number; height: number },
  pane: { width: number; height: number },
  min = 0.2,
): { x: number; y: number; zoom: number } {
  const pad = 24;
  const zoom = Math.max(min, Math.min(1, (pane.width - 2 * pad) / Math.max(b.width, 1), (pane.height - 2 * pad) / Math.max(b.height, 1)));
  const x = (pane.width - b.width * zoom) / 2 - b.x * zoom;
  const y = (pane.height - b.height * zoom) / 2 - b.y * zoom;
  return { x, y, zoom };
}

/** The coordinate along the main axis of the layout, used to reorder rules after a drag. */
export function mainAxis(n: { position: { x: number; y: number } }, direction: Direction): number {
  return direction === 'LR' ? n.position.x : n.position.y;
}
