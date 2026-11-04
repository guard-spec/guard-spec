// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Alert history (contract §2, §6): firing and resolved alerts, filtered by
// state and rule, with a detail view. /ui/alerts/history?id=… (the link of a
// notification) opens one alert.

import { BellRing, Eye } from 'lucide-react';
import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { DataTable, EmptyState, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { Dialog, ErrorBanner, formatTime, Loading, PageHeader, RelativeTime } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import { href, navigate, ROUTE_CHANGED, takeParam } from '../router';
import { AlertStateBadge, SeverityBadge, useAlertsApi } from './shared';
import type { Alert, AlertRule } from './types';

export default function HistoryPage() {
  const { t } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const stateId = useId();
  const ruleId = useId();
  const [state, setState] = useState('');
  const [rule, setRule] = useState('');
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [open, setOpen] = useState<string | null>(() => takeParam('id'));

  // A notification link while this page is open (same route: no remount).
  useEffect(() => {
    const on = () => {
      const id = takeParam('id');
      if (id) setOpen(id);
    };
    window.addEventListener(ROUTE_CHANGED, on);
    return () => window.removeEventListener(ROUTE_CHANGED, on);
  }, []);

  useEffect(() => {
    let live = true;
    a.allRules(org.id).then((r) => live && setRules(r), () => undefined);
    return () => {
      live = false;
    };
  }, [a, org.id]);
  const ruleNames = useMemo(() => new Map(rules.map((r) => [r.id, r.name])), [rules]);

  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => a.listAlerts(org.id, { ...p, state: state || undefined, rule_id: rule || undefined }),
    [a, org.id, state, rule],
  );
  const paged = usePaged<Alert>(fetchPage, { clientFilter: state || rule ? (x) => (!state || x.state === state) && (!rule || x.rule_id === rule) : undefined });
  const nameOf = (x: Alert) => x.rule_name ?? ruleNames.get(x.rule_id) ?? x.rule_id.slice(0, 8);

  const columns: Column<Alert>[] = [
    { key: 'state', header: t('alerts.state'), className: 'nowrap', cell: (x) => <AlertStateBadge state={x.state} /> },
    {
      key: 'rule',
      header: t('alerts.rule'),
      className: 'col-rule',
      cell: (x) => (
        <div className="cell-stack">
          <strong className="ellipsis" title={nameOf(x)}>
            {nameOf(x)}
          </strong>
          {x.dedupe_key ? (
            <span className="muted small mono ellipsis" title={x.dedupe_key}>
              {x.dedupe_key}
            </span>
          ) : null}
        </div>
      ),
    },
    { key: 'severity', header: t('alerts.severity'), cell: (x) => <SeverityBadge severity={x.severity} /> },
    { key: 'count', header: t('alerts.count'), className: 'nowrap num', cell: (x) => x.count },
    { key: 'first', header: t('alerts.firstAt'), className: 'nowrap small col-wide-only', cell: (x) => <RelativeTime value={x.first_at} /> },
    { key: 'last', header: t('alerts.lastAt'), className: 'nowrap small', cell: (x) => <RelativeTime value={x.last_at} /> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (x) => (
        <button type="button" className="btn btn-small btn-square" aria-label={t('alerts.history.viewOf', { name: nameOf(x) })} title={t('alerts.view')} onClick={() => setOpen(x.id)}>
          <Eye size={14} aria-hidden="true" />
        </button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader title={t('nav.alertHistory')} help={t('alerts.history.help')} />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(x) => x.id}
        testId="alerts-table"
        feature={t('nav.alertHistory')}
        toolbar={
          <>
            <div className="field field-inline">
              <label htmlFor={stateId}>{t('alerts.state')}</label>
              <select id={stateId} value={state} onChange={(e) => setState(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                <option value="firing">{t('alerts.state.firing')}</option>
                <option value="resolved">{t('alerts.state.resolved')}</option>
              </select>
            </div>
            <div className="field field-inline">
              <label htmlFor={ruleId}>{t('alerts.rule')}</label>
              <select id={ruleId} value={rule} onChange={(e) => setRule(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {rules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={BellRing} title={state || rule ? t('table.noMatch') : t('alerts.history.empty')} body={state || rule ? undefined : t('alerts.history.emptyBody')} />}
      />
      {open ? <AlertDetail id={open} ruleNames={ruleNames} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}

function AlertDetail({ id, ruleNames, onClose }: { id: string; ruleNames: Map<string, string>; onClose: () => void }) {
  const { t } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    a.getAlert(org.id, id).then(
      (x) => live && setAlert(x),
      (e: unknown) => live && setError(errorText(e)),
    );
    return () => {
      live = false;
    };
  }, [a, org.id, id]);
  const name = alert ? (alert.rule_name ?? ruleNames.get(alert.rule_id) ?? alert.rule_id) : '';
  const samples = alert?.samples ?? [];
  return (
    <Dialog
      open
      wide
      title={alert ? t('alerts.history.detailTitle', { name }) : t('alerts.history.detail')}
      onClose={onClose}
      footer={
        <button type="button" className="btn" onClick={onClose}>
          {t('common.close')}
        </button>
      }
    >
      <ErrorBanner error={error} />
      {!alert && !error ? <Loading /> : null}
      {alert ? (
        <div data-testid="alert-detail">
          <dl className="kv">
            <dt>{t('alerts.state')}</dt>
            <dd>
              <AlertStateBadge state={alert.state} />
            </dd>
            <dt>{t('alerts.severity')}</dt>
            <dd>
              <SeverityBadge severity={alert.severity} />
            </dd>
            <dt>{t('alerts.rule')}</dt>
            <dd>
              <a
                href={href('alert-rules')}
                onClick={(e) => {
                  e.preventDefault();
                  navigate('alert-rules');
                }}
              >
                {name}
              </a>
            </dd>
            <dt>{t('alerts.group')}</dt>
            <dd className="mono small">{alert.dedupe_key || t('alerts.history.noGroup')}</dd>
            <dt>{t('alerts.count')}</dt>
            <dd>{alert.count}</dd>
            <dt>{t('alerts.firstAt')}</dt>
            <dd>{formatTime(alert.first_at)}</dd>
            <dt>{t('alerts.lastAt')}</dt>
            <dd>{formatTime(alert.last_at)}</dd>
            {alert.resolved_at ? (
              <>
                <dt>{t('alerts.resolvedAt')}</dt>
                <dd>{formatTime(alert.resolved_at)}</dd>
              </>
            ) : null}
            <dt>{t('alerts.history.id')}</dt>
            <dd className="mono small">{alert.id}</dd>
          </dl>
          <h3>{t('alerts.history.samples')}</h3>
          {samples.length > 0 ? (
            <ul className="sample-list">
              {samples.map((s, i) => (
                <li key={s.event_id ?? s.id ?? i}>
                  <span className="mono small">{s.type}</span> <span className="muted small">{formatTime(s.occurred_at)}</span>
                  {s.attrs && Object.keys(s.attrs).length > 0 ? (
                    <code className="sample-attrs small">
                      {Object.entries(s.attrs)
                        .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
                        .join('  ')}
                    </code>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : alert.sample_event_ids?.length ? (
            <ul className="sample-list">
              {alert.sample_event_ids.map((e) => (
                <li key={e} className="mono small">
                  {e}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted small">{t('alerts.history.noSamples')}</p>
          )}
          <p className="muted small">{t('alerts.history.metadataOnly')}</p>
        </div>
      ) : null}
    </Dialog>
  );
}
