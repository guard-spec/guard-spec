// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { RefreshCw, ScrollText } from 'lucide-react';
import { useCallback, useId, useMemo, useState } from 'react';
import { DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { CopyButton, Dialog, formatTime, PageHeader, useDebounced, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import { ApiError } from '../api';
import { ACTIONS, type AuditRow, type StoredContent } from '../types';
import { normLabel, ruleNames } from './dashboard';
import { ReportDialog } from './ReportDialog';
import { auditTagLabel, badgeTags, blockReason, unscannedOf } from './auditTags';
import { FalsePositivePanel, WhyRefused } from './FalsePositivePanel';
import { offersFix } from './falsePositive';

export function RequestLogPage() {
  const { api, t } = useApp();
  const { org } = useOrg();
  const [action, setAction] = useState('');
  const [q, setQ] = useState('');
  const query = useDebounced(q);
  const [open, setOpen] = useState<AuditRow | null>(null);
  const [reporting, setReporting] = useState<AuditRow | null>(null);
  // Stored content read in this page (each read is logged on the server).
  const [contents, setContents] = useState<Record<string, StoredContent>>({});
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
          {unscannedOf(r).map((u) => (
            <span key={u.kind} className="badge badge-warn nowrap" data-testid="unscanned-tag">
              {t(`audit.tag.unscanned.${u.kind}`, { n: u.n })}
            </span>
          ))}
        </span>
      ),
    },
    {
      key: 'label',
      header: t('audit.label'),
      cell: (r) =>
        blockReason(r) === 'unscanned_content' ? (
          <span title={t('audit.reason.unscanned_content')}>unscanned_content</span>
        ) : (
          (normLabel(r.injection_label) ?? '—')
        ),
    },
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
                const c = contents[open.id];
                setReporting(c ? { ...open, request_content: c.request_content ?? undefined } : open);
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
            {blockReason(open) ? (
              <>
                <dt>{t('audit.blockReason')}</dt>
                <dd data-testid="block-reason">{t(`audit.reason.${blockReason(open) ?? 'unscanned_content'}`)}</dd>
              </>
            ) : null}
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
            <dt>{t('fp.why')}</dt>
            <dd>
              <WhyRefused row={open} ruleLabel={ruleLabel} />
            </dd>
            <dt>{t('audit.flags')}</dt>
            <dd>
              {open.had_tag_chars ? 'tag chars ' : ''}
              {open.had_bidi ? 'bidi' : ''}
              {!open.had_tag_chars && !open.had_bidi ? '—' : ''}
            </dd>
            {badgeTags(open.pii_entities).length > 0 ? (
              <>
                <dt>{t('audit.tags')}</dt>
                <dd>
                  <span className="name-line wrap" data-testid="audit-tags">
                    {badgeTags(open.pii_entities).map((tag) => (
                      <span key={tag.raw} className={tag.type === 'other' ? 'mono small' : 'badge'} title={tag.raw}>
                        {auditTagLabel(t, tag)}
                      </span>
                    ))}
                  </span>
                </dd>
              </>
            ) : null}
            <dt>{t('audit.latency')}</dt>
            <dd>{open.latency_ms !== null ? `${open.latency_ms} ms` : '—'}</dd>
            {open.request_sha256 ? (
              <>
                <dt>{t('audit.requestHash')}</dt>
                <dd className="mono small wrap">{open.request_sha256}</dd>
              </>
            ) : null}
            {open.has_content ? (
              <>
                <dt>{t('audit.content')}</dt>
                <dd>
                  <ContentReader
                    key={open.id}
                    row={open}
                    loaded={contents[open.id]}
                    onLoaded={(c) => setContents((m) => ({ ...m, [open.id]: c }))}
                  />
                </dd>
              </>
            ) : null}
          </dl>
        ) : null}
        {open && offersFix(open) ? (
          <FalsePositivePanel
            key={open.id}
            row={open}
            storedRequest={contents[open.id]?.request_content ?? null}
            onReport={() => {
              const c = contents[open.id];
              setReporting(c ? { ...open, request_content: c.request_content ?? undefined } : open);
              setOpen(null);
            }}
          />
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

/** Reads one row's stored content on request: the server checks the role
 * and the reason and logs the read, so nothing is fetched by just opening
 * the details. */
function ContentReader({ row, loaded, onLoaded }: { row: AuditRow; loaded?: StoredContent; onLoaded: (c: StoredContent) => void }) {
  const { api, t } = useApp();
  const { org } = useOrg();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reasonId = useId();

  if (loaded) {
    if (loaded.content_error) return <span className="muted">{t('audit.contentUnavailable')}</span>;
    return (
      <div className="stack-sm">
        {loaded.request_content ? <pre className="pre" data-testid="stored-request">{loaded.request_content}</pre> : null}
        {loaded.response_content ? (
          <>
            <div className="small muted">{t('audit.storedAnswer')}</div>
            <pre className="pre" data-testid="stored-response">{loaded.response_content}</pre>
          </>
        ) : null}
      </div>
    );
  }
  const read = async () => {
    setBusy(true);
    setError(null);
    try {
      onLoaded(await api.readRequestContent(org.id, row.id, reason.trim()));
    } catch (e) {
      const code = e instanceof ApiError ? (e.body as { code?: string } | undefined)?.code : undefined;
      setError(code === 'reason_required' ? t('audit.reasonRequired') : code === 'content_read_role' ? t('audit.contentForbidden') : e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack-sm">
      <div className="small muted">{t('audit.contentLogged')}</div>
      <label htmlFor={reasonId} className="small">
        {t('audit.reason')}
      </label>
      <input id={reasonId} value={reason} maxLength={500} placeholder={t('audit.reasonPlaceholder')} onChange={(e) => setReason(e.target.value)} />
      {error ? (
        <div className="field-error" role="alert">
          {error}
        </div>
      ) : null}
      <div>
        <button type="button" className="btn btn-small" disabled={busy} onClick={() => void read()}>
          {t('audit.showContent')}
        </button>
      </div>
    </div>
  );
}
