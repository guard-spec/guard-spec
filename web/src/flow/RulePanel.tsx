// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The side panel of a rule: name, action, route target, and the condition as
// a visual builder (react-querybuilder) and as text (CodeMirror). The two tabs
// stay in sync through POST /policy/format and /policy/parse.

import { useEffect, useMemo, useRef, useState } from 'react';
import { QueryBuilder, type Field, type RuleGroupType, type ValidationMap } from 'react-querybuilder';
import 'react-querybuilder/dist/query-builder.css';
import { ApiError } from '../api';
import { CodeEditor, type EditorDiagnostic } from '../components/CodeEditor';
import { errorText, useApp } from '../context';
import type { MessageKey } from '../i18n';
import { ACTIONS, type Action, type ConditionNode, type PolicySchema } from '../types';
import { conditionText } from './conditionText';
import { FieldPicker, OperatorSelect } from './FieldPicker';
import { descKey, variableHelp } from './help';
import { ActionTip } from './HelpText';
import { asGroup, type EditableRule } from './model';
import { cleanCondition, fieldTypesOf, operatorsFor } from './schema';
import { validateCondition, type Problem } from './validate';

/** Equal trees, ignoring the builder's ids and a single leaf wrapped in a group. */
export function sameCondition(a: ConditionNode, b: ConditionNode): boolean {
  return JSON.stringify(cleanCondition(asGroup(a))) === JSON.stringify(cleanCondition(asGroup(b)));
}

const OPERATOR_LABELS: Record<string, string> = {
  '=': '=',
  '==': '=',
  '!=': '≠',
  '>': '>',
  '>=': '≥',
  '<': '<',
  '<=': '≤',
  contains: 'contains',
  beginsWith: 'begins with',
  endsWith: 'ends with',
  in: 'in',
  notIn: 'not in',
};

export function builderFields(schema: PolicySchema): Field[] {
  return schema.fields.map((f) => {
    const operators = operatorsFor(schema, f.type).map((name) => ({ name, value: name, label: OPERATOR_LABELS[name] ?? name }));
    const base = { name: f.name, value: f.name, label: f.name, type: f.type, operators, ...(f.description ? { title: f.description } : {}) };
    switch (f.type) {
      case 'double':
      case 'int':
        // A text input: type=number would show the OS locale's decimal comma.
        return { ...base, inputType: 'text', defaultValue: '0.5' };
      case 'bool':
        return {
          ...base,
          valueEditorType: 'select',
          values: [
            { name: 'true', value: 'true', label: 'true' },
            { name: 'false', value: 'false', label: 'false' },
          ],
          defaultValue: 'true',
        };
      default:
        if (f.values && f.values.length > 0) {
          return {
            ...base,
            valueEditorType: (_op: string) => (_op === 'in' || _op === 'notIn' ? 'multiselect' : 'select'),
            values: f.values.map((v) => ({ name: v, value: v, label: v })),
            defaultValue: f.values[0],
          };
        }
        return base;
    }
  });
}

type Tab = 'visual' | 'text';

export type TextState = 'ok' | 'pending' | 'error';

export interface RulePanelProps {
  rule: EditableRule;
  policyName: string;
  schema: PolicySchema;
  upstreamNames: string[];
  index: number;
  count: number;
  onChange: (patch: Partial<EditableRule>) => void;
  onDelete: () => void;
  onMove: (delta: -1 | 1) => void;
  onClose: () => void;
  /**
   * The Text tab's state: "pending" while an edit is not parsed yet, "error"
   * while it does not parse. The rule's condition is the last text that
   * parsed, so saving then would store something else than the text shows.
   */
  onTextState?: (state: TextState) => void;
  /** Without policies.write: the rule is shown, not edited. */
  readOnly?: boolean;
  /** The org's injection block threshold, for the validation's warnings. */
  injectionThreshold?: number;
}

/** The builder's validation map: the leaves and groups with an error are invalid. */
export function validationMap(problems: readonly Problem[]): ValidationMap {
  const out: ValidationMap = {};
  for (const p of problems) if (p.id && p.severity === 'error') out[p.id] = false;
  return out;
}

const CONTROL_ELEMENTS = { fieldSelector: FieldPicker, operatorSelector: OperatorSelect };

export function RulePanel(props: RulePanelProps) {
  const { api, t } = useApp();
  const { rule, schema } = props;
  const [tab, setTab] = useState<Tab>('visual');
  const [text, setText] = useState<string>(() => conditionText(rule.condition, fieldTypesOf(schema)));
  const [diag, setDiag] = useState<EditorDiagnostic[]>([]);
  const [textError, setTextError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const fields = useMemo(() => builderFields(schema), [schema]);
  const fieldNames = useMemo(() => schema.fields.map((f) => f.name), [schema]);
  const fieldInfo = useMemo(
    () => Object.fromEntries(schema.fields.map((f) => [f.name, variableHelp(f.name) ? t(descKey(f.name)) : (f.description ?? '')])),
    [schema, t],
  );
  const problems = useMemo(
    () => validateCondition(rule.condition, schema, { injectionThreshold: props.injectionThreshold }),
    [rule.condition, schema, props.injectionThreshold],
  );
  const query = useMemo(() => asGroup(rule.condition) as RuleGroupType, [rule.condition]);
  // Separate timers: a format must never cancel a pending parse, or the
  // reverse. seq makes only the newest request's answer count.
  const formatTimer = useRef<number | undefined>(undefined);
  const parseTimer = useRef<number | undefined>(undefined);
  const mounted = useRef(false);
  const seq = useRef(0);
  // Last condition that came from the text tab: not formatted back into it.
  const fromText = useRef<ConditionNode | null>(null);
  const [textState, setTextState] = useState<TextState>('ok');
  const onTextState = useRef(props.onTextState);
  useEffect(() => {
    onTextState.current = props.onTextState;
  });
  useEffect(() => {
    onTextState.current?.(textState);
  }, [textState]);
  // Closing the panel ends the edit.
  useEffect(() => () => onTextState.current?.('ok'), []);

  const format = async (cond: ConditionNode) => {
    const my = ++seq.current;
    setSyncing(true);
    try {
      const s = await api.formatCondition(cond);
      if (my === seq.current) {
        setText(s);
        setDiag([]);
        setTextError(null);
        setTextState('ok');
      }
    } catch (e) {
      if (my === seq.current) {
        // No /policy/format (older control plane) or an invalid tree: show the local rendering.
        setText(conditionText(cond, fieldTypesOf(schema)));
        setTextState('ok');
        setTextError(e instanceof ApiError && e.status === 422 ? t('rule.formatError', { error: e.message }) : null);
      }
    } finally {
      if (my === seq.current) setSyncing(false);
    }
  };

  // The panel is keyed by the rule: format its condition once on mount.
  useEffect(() => {
    void format(rule.condition);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A change from the visual tab or elsewhere (not the mount, not the text
  // tab itself): format it into the text tab.
  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      return;
    }
    if (fromText.current === rule.condition) return;
    window.clearTimeout(formatTimer.current);
    formatTimer.current = window.setTimeout(() => void format(rule.condition), 300);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rule.condition]);

  useEffect(
    () => () => {
      window.clearTimeout(formatTimer.current);
      window.clearTimeout(parseTimer.current);
    },
    [],
  );

  const onText = (value: string) => {
    setText(value);
    setTextState('pending');
    // The user is typing: a pending or running format must not overwrite it.
    window.clearTimeout(formatTimer.current);
    seq.current += 1;
    window.clearTimeout(parseTimer.current);
    parseTimer.current = window.setTimeout(() => {
      const my = ++seq.current;
      setSyncing(true);
      api
        .parseCondition(value)
        .then((cond) => {
          if (my !== seq.current) return;
          fromText.current = cond;
          setDiag([]);
          setTextError(null);
          setTextState('ok');
          props.onChange({ condition: cond });
        })
        .catch((e: unknown) => {
          if (my !== seq.current) return;
          const pos = e instanceof ApiError && e.position !== undefined ? e.position : 0;
          const msg = errorText(e);
          setDiag([{ from: pos, message: msg }]);
          setTextError(t('rule.parseError', { position: pos, error: msg }));
          setTextState('error');
        })
        .finally(() => {
          if (my === seq.current) setSyncing(false);
        });
    }, 400);
  };

  const actionKey = (a: Action) => `rule.action.${a}` as MessageKey;
  const actions = schema.actions.length > 0 ? schema.actions.filter((a) => (ACTIONS as readonly string[]).includes(a)) : ACTIONS;

  return (
    <section className="rule-panel" aria-labelledby="rule-panel-title" data-testid="rule-panel">
      <header className="panel-header">
        <h2 id="rule-panel-title">
          {t('rule.title')}: {rule.name || t('flow.unnamedRule')}
        </h2>
        <button type="button" className="btn-icon" aria-label={t('common.close')} onClick={props.onClose}>
          ×
        </button>
      </header>
      <p className="muted small">
        {t('rule.policy')}: {props.policyName} · #{props.index + 1}
      </p>
      {props.readOnly ? (
        <div className="banner banner-info" role="note">
          {t('flow.readOnly')}
        </div>
      ) : null}
      <fieldset className="plain" disabled={props.readOnly}>
      <div className="field">
        <label htmlFor="rule-name">{t('rule.name')}</label>
        <input id="rule-name" value={rule.name} onChange={(e) => props.onChange({ name: e.target.value })} />
      </div>
      <div className="form-grid">
        <div className="field">
          <span className="label-row">
            <label htmlFor="rule-action">{t('rule.action')}</label>
            <ActionTip action={rule.action} label={t('rule.action')} />
          </span>
          <select
            id="rule-action"
            value={rule.action}
            onChange={(e) => {
              const action = e.target.value as Action;
              props.onChange(action === 'route' ? { action, route_target: rule.route_target ?? props.upstreamNames[0] ?? '' } : { action });
            }}
          >
            {actions.map((a) => (
              <option key={a} value={a}>
                {t(actionKey(a))}
              </option>
            ))}
          </select>
        </div>
        {rule.action === 'route' ? (
          <div className="field">
            <label htmlFor="rule-target">{t('rule.target')}</label>
            <select id="rule-target" value={rule.route_target ?? ''} onChange={(e) => props.onChange({ route_target: e.target.value })}>
              <option value="" disabled>
                {t('rule.chooseTarget')}
              </option>
              {props.upstreamNames.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
              {rule.route_target && !props.upstreamNames.includes(rule.route_target) ? (
                <option value={rule.route_target}>{rule.route_target} (?)</option>
              ) : null}
            </select>
          </div>
        ) : null}
      </div>

      <fieldset className="condition">
        <legend>{t('rule.condition')}</legend>
        <div className="tabs" role="tablist" aria-label={t('rule.condition')}>
          {(['visual', 'text'] as const).map((k) => (
            <button
              key={k}
              type="button"
              role="tab"
              id={`tab-${k}`}
              aria-selected={tab === k}
              aria-controls={`tabpanel-${k}`}
              tabIndex={tab === k ? 0 : -1}
              className={tab === k ? 'tab tab-active' : 'tab'}
              onClick={() => setTab(k)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                  const next = k === 'visual' ? 'text' : 'visual';
                  setTab(next);
                  document.getElementById(`tab-${next}`)?.focus();
                }
              }}
            >
              {k === 'visual' ? t('rule.visual') : t('rule.text')}
            </button>
          ))}
          {syncing ? (
            <span className="muted small sync" role="status">
              {t('rule.syncing')}
            </span>
          ) : null}
        </div>
        <div id="tabpanel-visual" role="tabpanel" aria-labelledby="tab-visual" hidden={tab !== 'visual'} className="qb-wrap">
          <QueryBuilder
            fields={fields}
            query={query}
            onQueryChange={(q) => {
              // The builder reports its prepared query (with ids) on mount:
              // only a real change edits the rule.
              if (sameCondition(q as ConditionNode, rule.condition)) return;
              fromText.current = null;
              props.onChange({ condition: q as ConditionNode });
            }}
            showNotToggle
            resetOnFieldChange
            controlElements={CONTROL_ELEMENTS}
            validator={(q) => validationMap(validateCondition(q as ConditionNode, schema, { injectionThreshold: props.injectionThreshold }))}
            disabled={props.readOnly}
            controlClassnames={{ queryBuilder: 'qb' }}
          />
        </div>
        <ConditionProblems problems={problems} />
        <div id="tabpanel-text" role="tabpanel" aria-labelledby="tab-text" hidden={tab !== 'text'}>
          <CodeEditor
            mode="expression"
            value={text}
            onChange={onText}
            diagnostics={diag}
            fields={fieldNames}
            fieldInfo={fieldInfo}
            ariaLabel={t('rule.condition')}
            testId="condition-text"
          />
          {textError ? (
            <p className="field-error" role="alert" data-testid="parse-error">
              {textError}
            </p>
          ) : (
            <p className="muted small">{t('rule.textHelp')}</p>
          )}
        </div>
      </fieldset>

      <div className="panel-actions">
        <button type="button" className="btn" disabled={props.index === 0} onClick={() => props.onMove(-1)}>
          ↑ {t('rule.moveUp')}
        </button>
        <button type="button" className="btn" disabled={props.index >= props.count - 1} onClick={() => props.onMove(1)}>
          ↓ {t('rule.moveDown')}
        </button>
        <button type="button" className="btn btn-danger" onClick={props.onDelete}>
          {t('rule.delete')}
        </button>
      </div>
      </fieldset>
    </section>
  );
}

/** The condition's errors and warnings, under the builder. */
export function ConditionProblems({ problems }: { problems: readonly Problem[] }) {
  const { t } = useApp();
  if (problems.length === 0) return null;
  const errors = problems.filter((p) => p.severity === 'error');
  const warnings = problems.filter((p) => p.severity === 'warning');
  return (
    <div className="cond-problems" data-testid="condition-problems">
      {errors.length > 0 ? (
        <div className="banner banner-error" role="alert">
          <strong>{t('cond.title')}</strong>
          <ul>
            {errors.map((p, i) => (
              <li key={`e${i}`}>{t(p.key, p.params)}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {warnings.length > 0 ? (
        <div className="banner banner-warn" role="status">
          <strong>{t('cond.warnings')}</strong>
          <ul>
            {warnings.map((p, i) => (
              <li key={`w${i}`}>{t(p.key, p.params)}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
