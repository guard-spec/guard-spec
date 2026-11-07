// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { RefreshCw, ScrollText } from 'lucide-react';
import { useCallback, useId, useMemo, useState } from 'react';
import { DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { CopyButton, Dialog, formatTime, PageHeader, useDebounced, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import { ACTIONS, type AuditRow } from '../types';
import { normLabel, ruleNames } from './dashboard';
import { ReportDialog } from './ReportDialog';

export function RequestLogPage() {
  const { api, t } = useApp();
  const { org } = useOrg();
  const [action, setAction] = useState('');
  const [q, setQ] = useState('');
  const query = useDebounced(q);
  const [open, setOpen] = useState<AuditRow | null>(null);
  const [reporting, setReporting] = useState<AuditRow | null>(null);
  const actionId = useId();

  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listRequestsPage(org.id, { ...p, action: action || undefined, q: query || undefined }),
    [api, org.id, action, query],
  );
  const needle = query.trim().toLowerCase();
  // Rule names: the request log stores rule ids.
  const policies = useLoad(useCallback(() => api.listPolicies(org.id), [api, org.id]));
  const rules = useMemo(() => ruleNames(policies.data ?? []), [policies.data]);
  const ruleLabel = (id: string) => {
    const r = rules.get(id);
    return r ? `${r.rule} (${r.policy})` : id.slice(0, 8);
  };
  const paged = usePaged<AuditRow>(fetchPage, {
    clientFilter:
      action || needle
        ? (r) =>
            (!action || r.action === action) &&
            (!needle || [r.model ?? '', r.route_target ?? '', r.injection_label ?? '', r.rule_id ?? ''].some((s) => s.toLowerCase().includes(needle)))
        : undefined,
  });

  const columns: Column<AuditRow>[] = [
    { key: 'time', header: t('audit.time'), className: 'nowrap', cell: (r) => formatTime(r.created_at) },
    {
      key: 'model',
      header: t('audit.model'),
      className: 'col-model',
      cell: (r) => (
        <span className="mono small ellipsis" title={r.model ?? undefined}>
          {r.model ?? '—'}
        </span>
      ),
    },
    {
      key: 'action',
      header: t('audit.action'),
      className: 'nowrap',
      cell: (r) => (
        <span className="name-line">
          <span className={`action action-${r.action}`}>{r.action}</span>
          {r.repeat_count ? (
            <span className="mono small muted" title={t('audit.repeats', { n: r.repeat_count })}>
              ×{r.repeat_count}
            </span>
          ) : null}
          {r.route_target ? (
            <span className="mono small ellipsis route-target" title={r.route_target}>
              → {r.route_target}
            </span>
          ) : null}
        </span>
      ),
    },
    { key: 'label', header: t('audit.label'), cell: (r) => normLabel(r.injection_label) ?? '—' },
    { key: 'score', header: t('audit.score'), className: 'col-wide-only', cell: (r) => r.injection_score.toFixed(2) },
    {
      key: 'rule',
      header: t('audit.rule'),
      className: 'col-rule',
      cell: (r) => (r.rule_id ? <span className="ellipsis" title={`${ruleLabel(r.rule_id)} · ${r.rule_id}`}>{rules.get(r.rule_id)?.rule ?? r.rule_id.slice(0, 8)}</span> : '—'),
    },
    { key: 'latency', header: t('audit.latency'), className: 'nowrap col-wide-only', cell: (r) => (r.latency_ms !== null ? `${r.latency_ms} ms` : '—') },
    {
      key: 'more',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (r) => (
        <span className="icon-actions">
          <button type="button" className="btn btn-small" aria-label={t('audit.detailsOf', { time: formatTime(r.created_at) })} onClick={() => setOpen(r)}>
            {t('audit.details')}
          </button>
          <button type="button" className="btn btn-small" aria-label={t('report.actionOf', { time: formatTime(r.created_at) })} onClick={() => setReporting(r)}>
            {t('report.action')}
          </button>
        </span>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('audit.title')}
        help={t('audit.help')}
        actions={
          <button type="button" className="btn btn-icon-text" onClick={() => void paged.reload()}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>{t('common.refresh')}</span>
          </button>
        }
      />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(r) => r.id}
        testId="audit-table"
        toolbar={
          <>
            <SearchBox value={q} onChange={setQ} label={t('audit.search')} />
            <div className="field field-inline">
              <label htmlFor={actionId}>{t('audit.filter')}</label>
              <select id={actionId} value={action} onChange={(e) => setAction(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={ScrollText} title={action || needle ? t('table.noMatch') : t('audit.emptyTitle')} body={action || needle ? undefined : t('audit.emptyBody')} />}
      />
      <Dialog
        open={open !== null}
        wide
        title={t('audit.details')}
        onClose={() => setOpen(null)}
        footer={
          open ? (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setReporting(open);
                setOpen(null);
              }}
            >
              {t('report.action')}
            </button>
          ) : undefined
        }
      >
        {open ? (
          <dl className="kv kv-wide">
            <dt>{t('audit.time')}</dt>
            <dd>{formatTime(open.created_at)}</dd>
            <dt>{t('audit.action')}</dt>
            <dd>
              <span className={`action action-${open.action}`}>{open.action}</span>
              {open.route_target ? ` → ${open.route_target}` : ''}
              {open.repeat_count ? ` · ${t('audit.repeats', { n: open.repeat_count })}` : ''}
            </dd>
            <dt>{t('audit.model')}</dt>
            <dd className="mono">{open.model ?? '—'}</dd>
            <dt>{t('audit.rule')}</dt>
            <dd>
              {open.rule_id ? (
                <span className="name-line">
                  <span>{ruleLabel(open.rule_id)}</span>
                  <code className="muted small" title={open.rule_id}>
                    {open.rule_id.slice(0, 8)}
                  </code>
                  <CopyButton text={open.rule_id} />
                </span>
              ) : (
                '—'
              )}
            </dd>
            <dt>{t('audit.label')}</dt>
            <dd>{normLabel(open.injection_label) ?? '—'}</dd>
            <dt>{t('audit.scores')}</dt>
            <dd className="mono small">
              injection {open.injection_score.toFixed(3)} · anomaly {open.anomaly_score.toFixed(3)}
              {open.toxicity_score !== undefined ? ` · toxicity ${open.toxicity_score.toFixed(3)}` : ''}
            </dd>
            <dt>{t('audit.flags')}</dt>
            <dd>
              {open.had_tag_chars ? 'tag chars ' : ''}
              {open.had_bidi ? 'bidi' : ''}
              {!open.had_tag_chars && !open.had_bidi ? '—' : ''}
            </dd>
            <dt>{t('audit.latency')}</dt>
            <dd>{open.latency_ms !== null ? `${open.latency_ms} ms` : '—'}</dd>
            {open.request_sha256 ? (
              <>
                <dt>{t('audit.requestHash')}</dt>
                <dd className="mono small wrap">{open.request_sha256}</dd>
              </>
            ) : null}
            {open.request_content ? (
              <>
                <dt>{t('audit.content')}</dt>
                <dd>
                  <pre className="pre">{open.request_content}</pre>
                </dd>
              </>
            ) : null}
          </dl>
        ) : null}
      </Dialog>
      {reporting ? (
        <ReportDialog
          key={reporting.id}
          row={reporting}
          ruleName={reporting.rule_id && rules.has(reporting.rule_id) ? ruleLabel(reporting.rule_id) : null}
          onClose={() => setReporting(null)}
        />
      ) : null}
    </div>
  );
}
