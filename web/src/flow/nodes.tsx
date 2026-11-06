// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { createContext, useContext } from 'react';
import { useApp } from '../context';
import type { RuleData, StepData, TerminalData, UpstreamData } from './graph';
import type { Direction } from './layout';

export const DirectionContext = createContext<Direction>('LR');

function useHandles(row?: 'pipeline' | 'pipeline-end') {
  const dir = useContext(DirectionContext);
  if (dir === 'LR') return { inPos: Position.Left, nextPos: Position.Right, matchPos: Position.Bottom };
  // Top to bottom: the pipeline is a row on top (see layout.ts); its last
  // step leads down to the rules.
  if (row === 'pipeline') return { inPos: Position.Left, nextPos: Position.Right, matchPos: Position.Right };
  if (row === 'pipeline-end') return { inPos: Position.Left, nextPos: Position.Bottom, matchPos: Position.Right };
  return { inPos: Position.Top, nextPos: Position.Bottom, matchPos: Position.Right };
}

function cls(base: string, hl: string | undefined, extra = ''): string {
  return [base, hl ? `node-hl-${hl}` : '', extra].filter(Boolean).join(' ');
}

const ICON: Record<StepData['role'], string> = {
  request: '→',
  key: '⚿',
  sanitizer: '⌫',
  detector: '◎',
  output: '⛨',
  client: '◉',
};

export function StepNode({ data }: NodeProps<Node<StepData>>) {
  const inRow = data.role === 'request' || data.role === 'key' || data.role === 'sanitizer';
  const { inPos, nextPos } = useHandles(inRow ? 'pipeline' : undefined);
  const { t } = useApp();
  return (
    <div
      className={cls('fnode fnode-step', data.hl, `fnode-${data.role} ${data.status === 'off' ? 'fnode-off' : ''}`)}
      title={t('flow.nodeHint')}
      data-testid={`step-node-${data.role}`}
    >
      {data.role !== 'request' ? <Handle type="target" position={inPos} isConnectable={false} /> : null}
      <div className="fnode-title">
        <span className="fnode-icon" aria-hidden="true">
          {ICON[data.role]}
        </span>
        <span>{data.title}</span>
      </div>
      <div className="fnode-sub">{data.subtitle}</div>
      {data.role !== 'client' ? <Handle type="source" position={nextPos} isConnectable={false} /> : null}
    </div>
  );
}

export function RuleNode({ data, selected }: NodeProps<Node<RuleData>>) {
  const { inPos, nextPos, matchPos } = useHandles();
  const { t } = useApp();
  const target = data.action === 'route' ? <span className="action-target">{` → ${data.routeTarget ?? '?'}`}</span> : null;
  return (
    <div
      className={cls('fnode fnode-rule', data.hl, `${selected ? 'fnode-selected' : ''} ${data.error ? 'fnode-error' : ''}`)}
      data-testid={`rule-node-${data.name}`}
    >
      <Handle type="target" position={inPos} isConnectable={false} />
      <div className="fnode-meta">{t('flow.ruleOf', { n: data.position, policy: data.policyName })}</div>
      <div className="fnode-title">
        <span className="fnode-name">{data.name}</span>
        <span className={`action action-${data.action}`}>
          {data.action}
          {target}
        </span>
      </div>
      <code className="fnode-cond">{data.text}</code>
      {data.error ? <div className="fnode-err">{data.error}</div> : null}
      <Handle type="source" id="next" position={nextPos} isConnectable={false} />
      <Handle type="source" id="match" position={matchPos} className="handle-match" title={t('flow.match')} />
    </div>
  );
}

/**
 * An invisible target handle that covers the whole node, so a connection
 * dragged from a rule's match handle can be dropped anywhere on it.
 */
function DropHandle() {
  return <Handle type="target" id="drop" position={Position.Top} isConnectableStart={false} className="handle-drop" />;
}

export function TerminalNode({ data }: NodeProps<Node<TerminalData>>) {
  const { inPos, nextPos } = useHandles();
  const { t } = useApp();
  return (
    <div className={cls('fnode fnode-terminal', data.hl, `fnode-${data.variant}`)} data-testid={`terminal-${data.variant}`} title={t('flow.nodeHint')}>
      <Handle type="target" position={inPos} isConnectable={false} />
      <DropHandle />
      <div className="fnode-title">
        <span>{data.title}</span>
      </div>
      <div className="fnode-sub">{data.subtitle}</div>
      {data.variant !== 'log' ? <Handle type="source" position={nextPos} isConnectable={false} /> : null}
    </div>
  );
}

export function UpstreamNode({ data }: NodeProps<Node<UpstreamData>>) {
  const { inPos, nextPos } = useHandles();
  const { t } = useApp();
  return (
    <div
      className={cls('fnode fnode-upstream', data.hl, `${data.missing ? 'fnode-error' : ''} ${data.enabled ? '' : 'fnode-off'}`)}
      data-testid={`upstream-node-${data.name || 'gateway'}`}
      title={t('flow.nodeHint')}
    >
      <Handle type="target" position={inPos} isConnectable={false} />
      {data.name && !data.missing ? <DropHandle /> : null}
      <div className="fnode-title">
        <span className="fnode-icon" aria-hidden="true">
          ⇄
        </span>
        <span>{data.title}</span>
        {data.isDefault ? <span className="badge badge-accent">{t('flow.defaultBadge')}</span> : null}
        {!data.enabled && !data.missing ? <span className="badge badge-off">{t('flow.disabledBadge')}</span> : null}
      </div>
      <div className="fnode-sub">{data.subtitle}</div>
      <Handle type="source" position={nextPos} isConnectable={false} />
    </div>
  );
}

export function DetectorsNode({ data }: NodeProps<Node<StepData>>) {
  const { inPos, nextPos } = useHandles('pipeline-end');
  const { t } = useApp();
  return (
    <div className={cls('fnode fnode-step fnode-detector', data.hl, data.status === 'off' ? 'fnode-off' : '')} title={t('flow.nodeHint')} data-testid="detectors-node">
      <Handle type="target" position={inPos} isConnectable={false} />
      <div className="fnode-title">
        <span className="fnode-icon" aria-hidden="true">
          {ICON.detector}
        </span>
        <span>{data.title}</span>
      </div>
      <ul className="fnode-layers">
        {(data.layers ?? []).map((l) => (
          <li key={l.name}>
            <span>{l.name}</span>
            <span className={`badge ${l.on ? 'badge-ok' : 'badge-off'}`}>{l.on ? t('guard.on') : t('guard.off')}</span>
          </li>
        ))}
      </ul>
      <div className="fnode-sub">{data.subtitle}</div>
      <Handle type="source" position={nextPos} isConnectable={false} />
    </div>
  );
}

export const nodeTypes = {
  step: StepNode,
  detectors: DetectorsNode,
  rule: RuleNode,
  terminal: TerminalNode,
  upstream: UpstreamNode,
};
