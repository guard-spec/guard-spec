// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useMemo, useState } from 'react';
import { ErrorBanner, formatTime, Loading, PageHeader, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';

export function AuditPage() {
  const { api, t } = useApp();
  const { org } = useOrg();
  const [limit, setLimit] = useState(100);
  const [action, setAction] = useState('');
  const { data, error, loading, reload } = useLoad(useCallback(() => api.listRequests(org.id, limit), [api, org.id, limit]));
  const actions = useMemo(() => [...new Set((data ?? []).map((r) => r.action))].sort(), [data]);
  const rows = (data ?? []).filter((r) => !action || r.action === action);

  return (
    <div>
      <PageHeader
        title={t('audit.title')}
        help={t('audit.help')}
        actions={
          <button type="button" className="btn" onClick={() => void reload()}>
            {t('common.refresh')}
          </button>
        }
      />
      <div className="toolbar">
        <div className="field field-inline">
          <label htmlFor="audit-limit">{t('audit.limit')}</label>
          <select id="audit-limit" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {[50, 100, 500, 1000].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </div>
        <div className="field field-inline">
          <label htmlFor="audit-action">{t('audit.filter')}</label>
          <select id="audit-action" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">{t('audit.all')}</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>
      </div>
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : null}
      <div className="card table-wrap">
        <table data-testid="audit-table">
          <thead>
            <tr>
              <th scope="col">{t('audit.time')}</th>
              <th scope="col">{t('audit.model')}</th>
              <th scope="col">{t('audit.action')}</th>
              <th scope="col">{t('audit.route')}</th>
              <th scope="col">{t('audit.label')}</th>
              <th scope="col">{t('audit.score')}</th>
              <th scope="col">{t('audit.rule')}</th>
              <th scope="col">{t('audit.latency')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !loading ? (
              <tr>
                <td colSpan={8} className="muted">
                  {t('common.empty')}
                </td>
              </tr>
            ) : null}
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="nowrap">{formatTime(r.created_at)}</td>
                <td className="mono small">{r.model ?? '—'}</td>
                <td>
                  <span className={`action action-${r.action}`}>{r.action}</span>
                </td>
                <td className="mono small">{r.route_target ?? '—'}</td>
                <td>{r.injection_label ?? '—'}</td>
                <td>{r.injection_score.toFixed(2)}</td>
                <td className="mono small" title={r.rule_id ?? ''}>
                  {r.rule_id ? r.rule_id.slice(0, 8) : '—'}
                </td>
                <td>{r.latency_ms !== null ? `${r.latency_ms} ms` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
