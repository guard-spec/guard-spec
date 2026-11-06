// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The side panel of a diagram node other than a rule: what the step does,
// and its settings where the API allows them. The detectors' thresholds and
// the L0 sanitizer's guard settings are edited here and staged with the rule
// edits (Save changes saves both); the other steps are explained, with a link
// to the page that owns their settings.

import { useEffect, useState, type ReactNode } from 'react';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink, type Route } from '../router';
import {
  DEFAULT_SCAN_ROLES,
  SCAN_ROLES,
  type Action,
  type GatewayModels,
  type GuardSettings,
  type IndirectAction,
  type ScanRole,
  type SpotlightMode,
  type Upstream,
} from '../types';
import { effectiveScanRoles, type DefaultUpstream } from './graph';
import { parseThreshold } from './guardDraft';
import type { NodeKind } from './help';
import { KeyTip, NodeTip } from './HelpText';
import { NODE } from './ids';

export interface PanelRule {
  key: string;
  name: string;
  action: Action;
  route_target?: string;
}

export interface NodePanelProps {
  nodeId: string;
  /** The guard settings with the staged edits; null while they load or when they failed. */
  guard: GuardSettings | null;
  /** The settings as the server has them, to mark changed fields. */
  savedGuard: GuardSettings | null;
  guardError: string | null;
  guardWritable: boolean;
  onGuardChange: (next: GuardSettings) => void;
  /** A threshold field holds text that is not a valid threshold: Save waits. */
  onGuardInvalid: (field: string, invalid: boolean) => void;
  models: GatewayModels | null;
  upstreams: readonly Upstream[];
  defaultUpstream: DefaultUpstream;
  scopeLabel: string;
  /** The rules of the scope in gateway order. */
  rules: readonly PanelRule[];
  onSelectRule: (key: string) => void;
  onClose: () => void;
}

/** The kind of help a node id has. */
export function nodeKind(id: string): NodeKind | undefined {
  switch (id) {
    case NODE.request:
      return 'request';
    case NODE.key:
      return 'key';
    case NODE.l0:
      return 'sanitizer';
    case NODE.detectors:
      return 'detectors';
    case NODE.block:
      return 'block';
    case NODE.allow:
      return 'allow';
    case NODE.log:
      return 'log';
    case NODE.envUpstream:
      return 'envUpstream';
    case NODE.output:
      return 'output';
    case NODE.client:
      return 'client';
  }
  if (NODE.upstreamName(id) !== undefined) return 'upstream';
  if (NODE.ruleKey(id) !== undefined) return 'rule';
  return undefined;
}

function PageLink({ route, label, testId }: { route: Route; label: string; testId?: string }) {
  return (
    <a className="btn btn-small panel-link" href={href(route)} onClick={onLink(route)} data-testid={testId}>
      {label} →
    </a>
  );
}

function Shell({ kind, title, children, onClose, links }: { kind: NodeKind; title: string; children: ReactNode; onClose: () => void; links: ReactNode }) {
  const { t } = useApp();
  return (
    <section className="rule-panel node-panel" aria-labelledby="node-panel-title" data-testid={`node-panel-${kind}`}>
      <header className="panel-header">
        <h2 id="node-panel-title">
          {title} <NodeTip kind={kind} name={title} />
        </h2>
        <button type="button" className="btn-icon" aria-label={t('common.close')} onClick={onClose}>
          ×
        </button>
      </header>
      {children}
      <div className="panel-actions panel-links">{links}</div>
    </section>
  );
}

function ReadOnlyGuard({ writable }: { writable: boolean }) {
  const { t } = useApp();
  if (writable) return <p className="small muted">{t('panel.staged')}</p>;
  return (
    <div className="banner banner-info" role="note" data-testid="guard-readonly">
      {t('panel.guardReadOnly')}
    </div>
  );
}

function Changed({ on }: { on: boolean }) {
  const { t } = useApp();
  return on ? <span className="badge badge-warn">{t('panel.changed')}</span> : null;
}

type Tri = 'default' | 'on' | 'off';

function SanitizerPanel(props: NodePanelProps) {
  const { t } = useApp();
  const draft = props.guard ?? {};
  const saved = props.savedGuard ?? {};
  const disabled = !props.guardWritable || props.guard === null;
  const roleValue = (s: GuardSettings, r: ScanRole): Tri => {
    const v = s.scan_roles?.[r];
    return v === undefined ? 'default' : v ? 'on' : 'off';
  };
  const setRole = (r: ScanRole, v: Tri) => {
    const roles = Object.fromEntries(Object.entries(draft.scan_roles ?? {}).filter(([k]) => k !== r));
    if (v !== 'default') roles[r] = v === 'on';
    props.onGuardChange({ ...draft, scan_roles: roles });
  };
  return (
    <>
      <p>{t('panel.l0.intro')}</p>
      <ReadOnlyGuard writable={props.guardWritable} />
      {props.guardError ? <div className="banner banner-error">{t('panel.guardUnavailable', { error: props.guardError })}</div> : null}
      <fieldset className="plain" disabled={disabled}>
        <legend className="panel-legend">{t('guard.roles')}</legend>
        <table className="settings-table compact">
          <tbody>
            {SCAN_ROLES.map((r) => (
              <tr key={r}>
                <th scope="row">
                  <label htmlFor={`np-role-${r}`}>{t(`guard.role.${r}` as MessageKey)}</label>
                  <div className="mono small muted">{r}</div>
                </th>
                <td>
                  <select id={`np-role-${r}`} value={roleValue(draft, r)} onChange={(e) => setRole(r, e.target.value as Tri)}>
                    <option value="default">{t('guard.default', { value: DEFAULT_SCAN_ROLES[r] ? t('guard.on') : t('guard.off') })}</option>
                    <option value="on">{t('guard.on')}</option>
                    <option value="off">{t('guard.off')}</option>
                  </select>{' '}
                  <Changed on={roleValue(draft, r) !== roleValue(saved, r)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="field">
          <span className="label-row">
            <label htmlFor="np-spotlight">{t('guard.spotlight')}</label>
            <KeyTip name={t('guard.spotlight')} k="panel.l0.spotlightHelp" testId="help-spotlight" />
            <Changed on={(draft.spotlight ?? '') !== (saved.spotlight ?? '')} />
          </span>
          <select
            id="np-spotlight"
            value={draft.spotlight ?? ''}
            onChange={(e) => {
              const v = e.target.value as SpotlightMode | '';
              const { spotlight: _old, ...rest } = draft;
              props.onGuardChange(v ? { ...rest, spotlight: v } : rest);
            }}
          >
            <option value="">{t('guard.default', { value: t('flow.gatewayDefault') })}</option>
            {(['off', 'delimit', 'datamark'] as const).map((m) => (
              <option key={m} value={m}>
                {t(`guard.spotlight.${m}` as MessageKey)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <span className="label-row">
            <label htmlFor="np-indirect-action">{t('guard.indirectAction')}</label>
            <KeyTip name={t('guard.indirectAction')} k="guard.indirectAction.help" testId="help-indirect-action" />
            <Changed on={(draft.indirect_action ?? '') !== (saved.indirect_action ?? '')} />
          </span>
          <select
            id="np-indirect-action"
            value={draft.indirect_action ?? ''}
            onChange={(e) => {
              const v = e.target.value as IndirectAction | '';
              const { indirect_action: _old, ...rest } = draft;
              props.onGuardChange(v ? { ...rest, indirect_action: v } : rest);
            }}
          >
            <option value="">{t('guard.default', { value: t('flow.gatewayDefault') })}</option>
            {(['block', 'redact'] as const).map((m) => (
              <option key={m} value={m}>
                {t(`guard.indirectAction.${m}` as MessageKey)}
              </option>
            ))}
          </select>
        </div>
      </fieldset>
    </>
  );
}

type ThresholdField = 'injection_threshold' | 'indirect_threshold';

function ThresholdInput({ field, label, help, props }: { field: ThresholdField; label: string; help: MessageKey; props: NodePanelProps }) {
  const { t } = useApp();
  const value = props.guard?.[field];
  const [text, setText] = useState(value === undefined ? '' : String(value));
  const parsed = parseThreshold(text);
  const invalid = parsed === 'invalid';
  const { onGuardInvalid } = props;
  // Staged edits made elsewhere (Discard) replace the text.
  useEffect(() => {
    const p = parseThreshold(text);
    if (p !== 'invalid' && p !== value) setText(value === undefined ? '' : String(value));
    // Only when the staged value changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  useEffect(() => {
    onGuardInvalid(field, invalid);
  }, [field, invalid, onGuardInvalid]);
  useEffect(() => () => onGuardInvalid(field, false), [field, onGuardInvalid]);
  const id = `np-${field}`;
  const errId = `${id}-error`;
  return (
    <div className="field">
      <span className="label-row">
        <label htmlFor={id}>{label}</label>
        <KeyTip name={label} k={help} testId={`help-${field}`} />
        <Changed on={props.savedGuard?.[field] !== value} />
      </span>
      <input
        id={id}
        inputMode="decimal"
        placeholder={t('panel.detectors.default', { value: field === 'injection_threshold' ? '0.85' : 'INDIRECT_BLOCK_THRESHOLD' })}
        value={text}
        aria-invalid={invalid}
        aria-describedby={invalid ? errId : undefined}
        onChange={(e) => {
          const s = e.target.value;
          setText(s);
          const p = parseThreshold(s);
          if (p === 'invalid' || !props.guard) return;
          const { [field]: _old, ...rest } = props.guard;
          props.onGuardChange(p === undefined ? rest : { ...rest, [field]: p });
        }}
      />
      {invalid ? (
        <p className="field-error" id={errId} role="alert">
          {t('panel.detectors.thresholdError')}
        </p>
      ) : typeof parsed === 'number' && parsed < 0.5 ? (
        <p className="small warn-text">{t('panel.detectors.thresholdLow')}</p>
      ) : null}
    </div>
  );
}

function DetectorsPanel(props: NodePanelProps) {
  const { t } = useApp();
  const m = props.models;
  const known = m && m.configured && m.reachable ? m : null;
  const roles = effectiveScanRoles(props.guard);
  const layer = (name: string) =>
    known?.layers ? (
      known.layers.includes(name) ? (
        <span className="badge badge-ok">{t('guard.on')}</span>
      ) : (
        <span className="badge badge-off">{t('guard.off')}</span>
      )
    ) : null;
  const floor = known?.l1_floor;
  return (
    <>
      <p>{t('panel.detectors.intro')}</p>
      <h3 className="panel-subtitle">{t('panel.detectors.layers')}</h3>
      <dl className="kv layer-list">
        <dt>{t('flow.l1')}</dt>
        <dd>
          {layer('l1')} {t('panel.detectors.l1')}
        </dd>
        <dt>{t('flow.l2')}</dt>
        <dd>
          {layer('l2')} {t('panel.detectors.l2')}{' '}
          {m && m.configured && m.reachable ? (
            <span data-testid="active-model">
              {t('panel.detectors.model')}:{' '}
              {m.l2_model ? (
                <>
                  <code>{m.l2_model}</code> {m.l2_verified ? <span className="badge badge-ok">{t('panel.detectors.verified')}</span> : null}
                </>
              ) : (
                <span className="muted">{t('panel.detectors.noModel')}</span>
              )}
              {m.shadow.enabled && m.shadow.model ? <div className="small muted">{t('panel.detectors.shadow', { model: m.shadow.model })}</div> : null}
            </span>
          ) : (
            <span className="muted small">{t('panel.detectors.modelUnknown')}</span>
          )}
        </dd>
        <dt>{t('flow.l3')}</dt>
        <dd>
          {layer('l3')} {t('panel.detectors.l3')}
        </dd>
        <dt>
          <span className="label-row">
            {t('panel.detectors.floor')}
            <KeyTip name={t('panel.detectors.floor')} k="panel.detectors.floorHelp" testId="help-l1-floor" />
          </span>
        </dt>
        <dd data-testid="l1-floor">
          {floor === undefined || floor === null ? (
            <span className="muted small">{t('panel.detectors.floorUnknown')}</span>
          ) : floor === 0 ? (
            t('panel.detectors.floorOff')
          ) : (
            <code>{floor}</code>
          )}
        </dd>
      </dl>
      <p className="small muted">{t('panel.detectors.layersNote')}</p>
      <h3 className="panel-subtitle">{t('panel.detectors.thresholds')}</h3>
      <ReadOnlyGuard writable={props.guardWritable} />
      {props.guardError ? <div className="banner banner-error">{t('panel.guardUnavailable', { error: props.guardError })}</div> : null}
      <fieldset className="plain" disabled={!props.guardWritable || props.guard === null}>
        <ThresholdInput field="injection_threshold" label={t('panel.detectors.injection')} help="panel.detectors.injectionHelp" props={props} />
        <ThresholdInput field="indirect_threshold" label={t('panel.detectors.indirect')} help="panel.detectors.indirectHelp" props={props} />
      </fieldset>
      <p className="small muted">{t('panel.detectors.anomaly')}</p>
      <p className="small muted">{t('panel.detectors.scans', { roles: roles.length > 0 ? roles.join(', ') : t('flow.scansNothing') })}</p>
      <p className="small muted">{t('panel.detectors.simNote')}</p>
    </>
  );
}

function UpstreamPanel({ name, props }: { name: string; props: NodePanelProps }) {
  const { t } = useApp();
  const u = props.upstreams.find((x) => x.name === name);
  const routes = props.rules.filter((r) => r.action === 'route' && r.route_target === name);
  const def = props.defaultUpstream;
  if (!u) {
    return (
      <div className="banner banner-error" role="note">
        {t('panel.upstream.missing', { name })}
      </div>
    );
  }
  const models = u.models ?? [];
  return (
    <>
      {def.source !== 'env' && def.name === name ? (
        <p>
          <span className="badge badge-accent">{t('flow.defaultBadge')}</span>{' '}
          {t('panel.upstream.isDefault', { source: t(def.source === 'project' ? 'panel.upstream.sourceProject' : 'panel.upstream.sourceOrg') })}
        </p>
      ) : null}
      <dl className="kv">
        <dt>{t('panel.upstream.status')}</dt>
        <dd>{u.enabled ? <span className="badge badge-ok">{t('common.enabled')}</span> : <span className="badge badge-off">{t('common.disabled')}</span>}</dd>
        {u.provider ? (
          <>
            <dt>{t('panel.upstream.provider')}</dt>
            <dd className="mono">{u.provider}</dd>
          </>
        ) : null}
        <dt>{t('panel.upstream.baseUrl')}</dt>
        <dd className="mono small break">{u.base_url}</dd>
        <dt>{t('panel.upstream.defaultModel')}</dt>
        <dd className="mono">{[u.default_model, u.model].find((x) => x) ?? '—'}</dd>
        <dt>{t('panel.upstream.models')}</dt>
        <dd data-testid="upstream-models">
          {models.length > 0 ? (
            <span className="badges">
              {models.map((x) => (
                <code key={x} className="badge badge-neutral">
                  {x}
                </code>
              ))}
            </span>
          ) : (
            t('panel.upstream.anyModel')
          )}
        </dd>
      </dl>
      <p className="small muted">{t('panel.upstream.modelNote')}</p>
      <h3 className="panel-subtitle">{t('panel.upstream.routes')}</h3>
      {routes.length > 0 ? (
        <ul className="plain-list">
          {routes.map((r) => (
            <li key={r.key}>
              <button type="button" className="btn btn-link" onClick={() => props.onSelectRule(r.key)}>
                {r.name || t('flow.unnamedRule')}
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted small">{t('panel.upstream.noRoutes')}</p>
      )}
      <div className="banner banner-info" role="note">
        {t('panel.upstream.editNote')}
      </div>
    </>
  );
}

function TerminalPanel({ action, props }: { action: 'block' | 'allow' | 'log'; props: NodePanelProps }) {
  const { t } = useApp();
  const rules = props.rules.filter((r) => r.action === action);
  return (
    <>
      <p>{t(`panel.${action}.body` as MessageKey)}</p>
      <dl className="kv">
        <dt>{t('panel.statusLabel')}</dt>
        <dd>{t(`panel.${action}.status` as MessageKey)}</dd>
        <dt>{t('panel.audit')}</dt>
        <dd>{t('panel.auditBody')}</dd>
      </dl>
      {rules.length > 0 ? (
        <div className="small">
          {t('panel.rulesHere')}
          <ul className="plain-list">
            {rules.map((r) => (
              <li key={r.key}>
                <button type="button" className="btn btn-link" onClick={() => props.onSelectRule(r.key)}>
                  {r.name || t('flow.unnamedRule')}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="muted small">{t('panel.noRulesHere')}</p>
      )}
    </>
  );
}

export function NodePanel(props: NodePanelProps) {
  const { t } = useApp();
  const kind = nodeKind(props.nodeId);
  if (!kind || kind === 'rule') return null;
  const settings = <PageLink route="guard" label={t('panel.openSettings')} testId="open-settings" />;
  const log = (label: MessageKey = 'panel.logLink') => <PageLink route="requests" label={t(label)} testId="open-settings" />;
  const shell = (title: string, links: ReactNode, body: ReactNode) => (
    <Shell kind={kind} title={title} onClose={props.onClose} links={links}>
      {body}
    </Shell>
  );
  switch (kind) {
    case 'request':
      return shell(t('panel.request.title'), log('panel.request.link'), <p>{t('panel.request.body')}</p>);
    case 'key':
      return shell(
        t('panel.key.title'),
        <PageLink route="keys" label={t('panel.key.link')} testId="open-settings" />,
        <>
          <p>{t('panel.key.body')}</p>
          <p>
            <strong>{t('panel.key.scope', { scope: props.scopeLabel })}</strong>
          </p>
          <p className="small muted">{t('panel.key.limits')}</p>
        </>,
      );
    case 'sanitizer':
      return shell(t('panel.l0.title'), settings, <SanitizerPanel {...props} />);
    case 'detectors':
      return shell(
        t('panel.detectors.title'),
        <>
          {settings}
          <PageLink route="models" label={t('nav.models')} />
        </>,
        <DetectorsPanel {...props} />,
      );
    case 'upstream': {
      const name = NODE.upstreamName(props.nodeId) ?? '';
      return shell(t('panel.upstream.title', { name }), <PageLink route="providers" label={t('panel.upstream.link')} testId="open-settings" />, <UpstreamPanel name={name} props={props} />);
    }
    case 'envUpstream':
      return shell(
        t('panel.env.title'),
        <PageLink route="providers" label={t('panel.upstream.link')} testId="open-settings" />,
        <>
          <p>{t('panel.env.body')}</p>
          <p className="small muted">{t('panel.env.howTo')}</p>
        </>,
      );
    case 'output':
      return shell(
        t('panel.output.title'),
        log('panel.output.link'),
        <>
          <p>{t('panel.output.body')}</p>
          <div className="banner banner-info" role="note">
            {t('panel.output.env')}
          </div>
          <p className="small">{t('panel.output.defaults')}</p>
          <p className="small muted">{t('panel.output.leak')}</p>
        </>,
      );
    case 'block':
    case 'allow':
    case 'log':
      return shell(t(`panel.${kind}.title` as MessageKey), log(), <TerminalPanel action={kind} props={props} />);
    case 'client':
      return shell(
        t('panel.client.title'),
        log(),
        <>
          <p>{t('panel.client.body')}</p>
          <dl className="kv">
            <dt>{t('panel.statusLabel')}</dt>
            <dd>{t('panel.client.status')}</dd>
            <dt>{t('panel.audit')}</dt>
            <dd>{t('panel.auditBody')}</dd>
          </dl>
        </>,
      );
  }
}
