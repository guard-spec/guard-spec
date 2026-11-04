// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from 'react';
import { ErrorBanner } from '../components/ui';
import { errorText, useApp } from '../context';
import type { MessageKey } from '../i18n';
import type { PolicySchema, SchemaField, SimulateRequest, SimulateResponse, SimValue } from '../types';

/**
 * The index of the trace entry that decided: the first match of an allow,
 * block or route rule. The control plane lists every rule's outcome, so later
 * entries were not reached by the gateway. -1 when no rule decided.
 */
export function decidingIndex(trace: SimulateResponse['trace']): number {
  return trace.findIndex((e) => e.matched && e.action !== 'log');
}

/** Converts the form's strings to typed vars; empty fields are left out. */
export function simVars(schema: PolicySchema, form: Record<string, string>): Record<string, SimValue> {
  const out: Record<string, SimValue> = {};
  for (const f of schema.fields) {
    const raw = (form[f.name] ?? '').trim();
    if (raw === '') continue;
    switch (f.type) {
      case 'double':
      case 'int': {
        const n = Number(raw);
        if (Number.isFinite(n)) out[f.name] = f.type === 'int' ? Math.trunc(n) : n;
        break;
      }
      case 'bool':
        out[f.name] = raw === 'true';
        break;
      case 'list':
        out[f.name] = raw
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      default:
        out[f.name] = raw;
    }
  }
  return out;
}

function FieldInput({ f, value, onChange }: { f: SchemaField; value: string; onChange: (v: string) => void }) {
  const id = `sim-${f.name}`;
  let input;
  if (f.type === 'bool') {
    input = (
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">—</option>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  } else if (f.values && f.values.length > 0 && f.type === 'string') {
    input = (
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">—</option>
        {f.values.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </select>
    );
  } else if (f.type === 'double' || f.type === 'int') {
    input = (
      // Text, not type=number: Chrome shows numbers in the OS locale (0,5).
      <input
        id={id}
        inputMode={f.type === 'int' ? 'numeric' : 'decimal'}
        pattern="-?[0-9]*[.]?[0-9]*"
        placeholder={f.type === 'int' ? '0' : '0.00'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  } else {
    input = <input id={id} value={value} onChange={(e) => onChange(e.target.value)} />;
  }
  return (
    <div className="field field-compact">
      <label htmlFor={id} className="mono" title={f.description}>
        {f.name}
      </label>
      {input}
    </div>
  );
}

export interface SimulatorProps {
  orgId: string;
  schema: PolicySchema;
  /** Builds the request: the scope, and the unsaved rules when there are edits. */
  makeRequest: (vars: Record<string, SimValue>) => SimulateRequest;
  result: SimulateResponse | null;
  onResult: (r: SimulateResponse | null) => void;
  /** On the simulator page, which has its own title and help. */
  embedded?: boolean;
}

const DEFAULTS: Record<string, string> = {
  'request.model': 'gpt-4o',
  'scores.l1': '0.2',
  'scores.l2': '0.91',
  'injection.score': '0.91',
  'injection.category': 'jailbreak',
};

export function Simulator({ orgId, schema, makeRequest, result, onResult, embedded = false }: SimulatorProps) {
  const { api, t } = useApp();
  const [form, setForm] = useState<Record<string, string>>(DEFAULTS);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onResult(await api.simulate(orgId, makeRequest(simVars(schema, form))));
    } catch (err) {
      onResult(null);
      setError(t('sim.failed', { error: errorText(err) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="simulator" aria-labelledby="sim-title" data-testid="simulator">
      <h2 id="sim-title" className={embedded ? 'sr-only' : undefined}>
        {t('sim.title')}
      </h2>
      {embedded ? null : <p className="muted small">{t('sim.help')}</p>}
      <form onSubmit={run}>
        <div className="sim-grid">
          {schema.fields.map((f) => (
            <FieldInput key={f.name} f={f} value={form[f.name] ?? ''} onChange={(v) => setForm({ ...form, [f.name]: v })} />
          ))}
        </div>
        <div className="panel-actions">
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t('sim.run')}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => {
              setForm({});
              onResult(null);
            }}
          >
            {t('sim.clear')}
          </button>
        </div>
      </form>
      <ErrorBanner error={error} />
      {result ? (
        <div className="sim-result" aria-live="polite" data-testid="sim-result">
          <dl className="kv">
            <dt>{t('sim.decision')}</dt>
            <dd>
              <span className={`action action-${result.decision.action}`}>{result.decision.action}</span>
              {result.decision.route_target ? ` → ${result.decision.route_target}` : ''}
              {result.decision.error ? <div className="field-error">{result.decision.error}</div> : null}
            </dd>
            {result.upstream ? (
              <>
                <dt>{t('sim.upstream')}</dt>
                <dd>
                  <strong>{result.upstream.name ?? '—'}</strong> <span className="muted">({t(`sim.source.${result.upstream.source}` as MessageKey)})</span>
                  {result.upstream.base_url ? <div className="mono small muted">{result.upstream.base_url}</div> : null}
                  {result.upstream.error ? <div className="field-error">{result.upstream.error}</div> : null}
                </dd>
              </>
            ) : null}
          </dl>
          <h3>{t('sim.trace')}</h3>
          {result.trace.length === 0 ? (
            <p className="muted">{t('sim.noTrace')}</p>
          ) : (
            <ol className="trace">
              {result.trace.map((e, i) => {
                const decided = decidingIndex(result.trace);
                const after = decided >= 0 && i > decided;
                return (
                  <li key={`${e.rule_id ?? ''}-${i}`} className={[e.matched && !after ? 'trace-hit' : '', after ? 'trace-after' : ''].join(' ')}>
                    <span className="trace-name">{e.rule_name}</span>{' '}
                    <span className={e.matched ? 'badge badge-accent' : 'badge badge-off'}>{e.matched ? t('sim.matched') : t('sim.notMatched')}</span>{' '}
                    <span className={`action action-${e.action}`}>{e.action}</span>
                    {i === decided ? <span className="badge badge-warn">{t('sim.decides')}</span> : null}
                    {after ? <span className="muted small"> · {t('sim.notReached')}</span> : null}
                    {e.error ? <div className="field-error">{e.error}</div> : null}
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      ) : null}
    </section>
  );
}
