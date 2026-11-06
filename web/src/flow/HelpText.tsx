// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The help of a condition variable, an operator, an action, a node or an
// edge, as tooltip content (spans: it may sit inside a label).

import { HelpTip } from '../components/HelpTip';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import type { Action, FieldType } from '../types';
import { actionHelpKey, descKey, edgeHelpKey, nodeHelpKey, operatorHelpKey, rangeKey, variableHelp, whenKey, type EdgeKindHelp, type NodeKind } from './help';

/** The description, values, example and use of a variable. */
export function VariableHelpText({ name, fallback }: { name: string; fallback?: string }) {
  const { t } = useApp();
  const meta = variableHelp(name);
  if (!meta) {
    return (
      <span className="help-body">
        <span className="help-title mono">{name}</span>
        <span>{fallback ?? ''}</span>
      </span>
    );
  }
  return (
    <span className="help-body">
      <span className="help-title mono">{name}</span>
      <span>{t(descKey(name))}</span>
      <span>
        <strong>{t('help.values')}:</strong> {t(rangeKey(name))}
      </span>
      <span>
        <strong>{t('help.example')}:</strong> <code>{meta.example}</code>
      </span>
      <span>
        <strong>{t('help.when')}:</strong> {t(whenKey(name))}
      </span>
    </span>
  );
}

export function VariableTip({ name, fallback }: { name: string; fallback?: string }) {
  return (
    <HelpTip name={name} testId={`help-${name}`}>
      <VariableHelpText name={name} fallback={fallback} />
    </HelpTip>
  );
}

export function TextTip({ name, text, testId }: { name: string; text: string; testId?: string }) {
  return (
    <HelpTip name={name} testId={testId}>
      <span className="help-body">{text}</span>
    </HelpTip>
  );
}

export function KeyTip({ name, k, testId }: { name: string; k: MessageKey; testId?: string }) {
  const { t } = useApp();
  return <TextTip name={name} text={t(k)} testId={testId} />;
}

export function OperatorTip({ op, type, label }: { op: string; type: FieldType | undefined; label: string }) {
  return <KeyTip name={label} k={operatorHelpKey(op, type)} testId={`help-op-${op}`} />;
}

/** Help on every action, the selected one first. */
export function ActionTip({ action, label }: { action: Action; label: string }) {
  const { t } = useApp();
  const others = (['allow', 'block', 'log', 'route'] as const).filter((a) => a !== action);
  return (
    <HelpTip name={label} testId="help-action">
      <span className="help-body">
        <strong>{t(actionHelpKey(action))}</strong>
        {others.map((a) => (
          <span key={a}>{t(actionHelpKey(a))}</span>
        ))}
      </span>
    </HelpTip>
  );
}

export function NodeTip({ kind, name }: { kind: NodeKind; name: string }) {
  return <KeyTip name={name} k={nodeHelpKey(kind)} testId={`help-node-${kind}`} />;
}

export function EdgeTip({ kind, name }: { kind: EdgeKindHelp; name: string }) {
  return <KeyTip name={name} k={edgeHelpKey(kind)} testId={`help-edge-${kind}`} />;
}
