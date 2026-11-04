// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The condition of an alert rule: the policy editor's visual builder
// (react-querybuilder) and text editor (CodeMirror), over the event fields.
// The text is what the rule stores; an empty condition matches every event.

import { useId, useMemo, useState } from 'react';
import { QueryBuilder, type RuleGroupType } from 'react-querybuilder';
import 'react-querybuilder/dist/query-builder.css';
import { CodeEditor, type EditorDiagnostic } from '../components/CodeEditor';
import { useApp } from '../context';
import { builderFields, sameCondition } from '../flow/RulePanel';
import type { ConditionNode } from '../types';
import { ALERT_SCHEMA, alertConditionText, ConditionParseError, parseAlertCondition } from './condition';

type Tab = 'visual' | 'text';

function tryParse(text: string): { tree: RuleGroupType | null; error: ConditionParseError | null } {
  try {
    return { tree: parseAlertCondition(text) as RuleGroupType, error: null };
  } catch (e) {
    return { tree: null, error: e instanceof ConditionParseError ? e : new ConditionParseError(String(e), 0) };
  }
}

export function ConditionEditor({
  value,
  onChange,
  readOnly,
  serverError,
}: {
  value: string;
  onChange: (text: string) => void;
  readOnly?: boolean;
  /** The 400 of the last save, shown under the editor. */
  serverError?: string | null;
}) {
  const { t } = useApp();
  const uid = useId();
  // The editor is keyed by the rule: the text is parsed once on open.
  const [initial] = useState(() => tryParse(value));
  const [tab, setTab] = useState<Tab>(initial.error ? 'text' : 'visual');
  const [query, setQuery] = useState<RuleGroupType>(initial.tree ?? { combinator: 'and', rules: [] });
  const [error, setError] = useState<ConditionParseError | null>(initial.error);
  const fields = useMemo(() => builderFields(ALERT_SCHEMA), []);
  const fieldNames = useMemo(() => ALERT_SCHEMA.fields.map((f) => f.name), []);
  const diag: EditorDiagnostic[] = error ? [{ from: error.position, message: error.message }] : [];

  const onText = (text: string) => {
    onChange(text);
    const r = tryParse(text);
    setError(r.error);
    if (r.tree) setQuery(r.tree);
  };

  const tabId = (k: Tab) => `${uid}-tab-${k}`;
  const panelId = (k: Tab) => `${uid}-panel-${k}`;
  return (
    <fieldset className="condition alert-condition">
      <legend>{t('alerts.rule.condition')}</legend>
      <div className="tabs" role="tablist" aria-label={t('alerts.rule.condition')}>
        {(['visual', 'text'] as const).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            id={tabId(k)}
            aria-selected={tab === k}
            aria-controls={panelId(k)}
            tabIndex={tab === k ? 0 : -1}
            className={tab === k ? 'tab tab-active' : 'tab'}
            onClick={() => setTab(k)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                const next = k === 'visual' ? 'text' : 'visual';
                setTab(next);
                document.getElementById(tabId(next))?.focus();
              }
            }}
          >
            {k === 'visual' ? t('rule.visual') : t('rule.text')}
          </button>
        ))}
      </div>
      <div id={panelId('visual')} role="tabpanel" aria-labelledby={tabId('visual')} hidden={tab !== 'visual'} className="qb-wrap">
        {error ? (
          <p className="banner banner-warn small">{t('alerts.rule.fixText')}</p>
        ) : (
          <>
            {query.rules.length === 0 ? <p className="muted small">{t('alerts.rule.alwaysMatches')}</p> : null}
            <QueryBuilder
              fields={fields}
              query={query}
              disabled={readOnly}
              onQueryChange={(q) => {
                if (sameCondition(q as ConditionNode, query as ConditionNode)) {
                  setQuery(q);
                  return;
                }
                setQuery(q);
                onChange(alertConditionText(q as ConditionNode));
              }}
              showNotToggle
              resetOnFieldChange
              controlClassnames={{ queryBuilder: 'qb' }}
            />
          </>
        )}
      </div>
      <div id={panelId('text')} role="tabpanel" aria-labelledby={tabId('text')} hidden={tab !== 'text'}>
        <CodeEditor
          mode="expression"
          value={value}
          onChange={readOnly ? undefined : onText}
          readOnly={readOnly}
          diagnostics={diag}
          fields={fieldNames}
          ariaLabel={t('alerts.rule.condition')}
          placeholder={t('alerts.rule.conditionPlaceholder')}
          testId="alert-condition-text"
        />
        {error ? (
          <p className="field-error" role="alert" data-testid="alert-condition-error">
            {t('rule.parseError', { position: error.position, error: error.message })}
          </p>
        ) : (
          <p className="muted small">{t('alerts.rule.conditionHelp')}</p>
        )}
      </div>
      {serverError ? (
        <p className="field-error" role="alert">
          {serverError}
        </p>
      ) : null}
    </fieldset>
  );
}
