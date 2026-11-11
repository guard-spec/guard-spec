// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The history of a policy (migration 026): every saved version with its
// author, time and reason; the changes between two versions; and a rollback
// to any of them, which is itself a new version.

import { History } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Badge, EmptyState } from '../components/DataTable';
import { Dialog, ErrorBanner, Field, Loading, PageHeader, RelativeTime, formatTime, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey, Translate } from '../i18n';
import { href, onLink, takeParam } from '../router';
import type { Policy, PolicyDiff, PolicyFieldChange, PolicyRuleChange, PolicyVersion, Rule } from '../types';
import { conditionText } from '../flow/conditionText';

/** The "from" of a diff whose "to" is version: the one before it, or nothing for the first. */
export function previousVersion(items: readonly Pick<PolicyVersion, 'version'>[], version: number): number | null {
  const older = items.map((v) => v.version).filter((v) => v < version);
  return older.length ? Math.max(...older) : null;
}

/** One line per changed field, in the user's language. */
export function fieldChangeText(t: Translate, c: PolicyFieldChange, projectName: (id: string | null) => string): string {
  const show = (v: unknown): string => {
    if (c.field === 'project_id') return projectName(typeof v === 'string' ? v : null);
    if (typeof v === 'boolean') return v ? t('guard.on') : t('guard.off');
    return v === null || v === undefined || v === '' ? '—' : typeof v === 'string' ? v : JSON.stringify(v);
  };
  return t('history.fieldChange', { field: t(`history.field.${c.field}` as MessageKey), from: show(c.from), to: show(c.to) });
}

function ruleLine(r: Rule): string {
  const target = r.action === 'route' && r.route_target ? ` → ${r.route_target}` : '';
  return `${r.action}${target}: ${conditionText(r.condition)}`;
}

export function PolicyHistoryPage() {
  const { api, t, notify } = useApp();
  const { org, projects, can } = useOrg();
  const writable = can('policies.write');
  const [policyId, setPolicyId] = useState<string>(() => takeParam('policy') ?? '');
  const { data: policies, error: policiesError, loading: policiesLoading } = useLoad(useCallback(() => api.listPolicies(org.id), [api, org.id]));
  const [versions, setVersions] = useState<{ items: PolicyVersion[]; current: number } | null>(null);
  const [versionsError, setVersionsError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [compareFrom, setCompareFrom] = useState<number | null>(null);
  const [diff, setDiff] = useState<PolicyDiff | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [rollback, setRollback] = useState<PolicyVersion | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);

  useEffect(() => {
    if (!policyId && policies?.length) setPolicyId(policies[0]?.id ?? '');
  }, [policies, policyId]);

  const load = useCallback(async () => {
    if (!policyId) return;
    setVersionsError(null);
    try {
      const v = await api.listPolicyVersions(org.id, policyId);
      setVersions(v);
      setSelected(v.current);
      setCompareFrom(previousVersion(v.items, v.current));
    } catch (e) {
      setVersions(null);
      setVersionsError(errorText(e));
    }
  }, [api, org.id, policyId]);
  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!policyId || selected === null || compareFrom === null) {
      setDiff(null);
      return;
    }
    let cancelled = false;
    setDiffError(null);
    api.diffPolicyVersions(org.id, policyId, compareFrom, selected).then(
      (d) => {
        if (!cancelled) setDiff(d);
      },
      (e: unknown) => {
        if (!cancelled) setDiffError(errorText(e));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [api, org.id, policyId, selected, compareFrom]);

  const projectName = (id: string | null) => (id ? (projects.find((p) => p.id === id)?.name ?? id) : t('common.orgWide'));
  const policy: Policy | undefined = policies?.find((p) => p.id === policyId);
  const items = versions?.items ?? [];
  const selectedVersion = items.find((v) => v.version === selected);

  const doRollback = async () => {
    if (!rollback || !policyId) return;
    setBusy(true);
    setRollbackError(null);
    try {
      const r = await api.rollbackPolicy(org.id, policyId, { version: rollback.version, reason: reason.trim() || undefined });
      setRollback(null);
      setReason('');
      if ('approval_required' in r) notify(t('history.rolledBackDisablePending', { from: rollback.version }), 'error');
      else notify(t('history.rolledBack', { from: r.rolled_back_to, to: r.version }));
      await load();
    } catch (e) {
      setRollbackError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (policiesLoading && !policies) return <Loading />;

  return (
    <div>
      <PageHeader
        title={t('history.title')}
        help={t('history.help')}
        actions={
          <a className="btn" href={href('flow')} onClick={onLink('flow')}>
            {t('nav.flow')}
          </a>
        }
      />
      <ErrorBanner error={policiesError} />
      {policies?.length === 0 ? (
        <EmptyState icon={History} title={t('history.noPolicies')} body={t('history.noPoliciesBody')} />
      ) : (
        <>
          <div className="toolbar">
            <Field label={t('history.policy')}>
              {(p) => (
                <select {...p} value={policyId} onChange={(e) => setPolicyId(e.target.value)} data-testid="history-policy">
                  {(policies ?? []).map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name} ({projectName(x.project_id)})
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {policy ? (
              <div className="muted small">
                {t('history.current', { version: policy.version })}
                {policy.log_only ? (
                  <>
                    {' '}
                    <Badge tone="warn">{t('policy.logOnlyBadge')}</Badge>
                  </>
                ) : null}
                {!policy.enabled ? (
                  <>
                    {' '}
                    <Badge tone="off">{t('flow.disabledBadge')}</Badge>
                  </>
                ) : null}
              </div>
            ) : null}
          </div>
          <ErrorBanner error={versionsError} />
          <div className="history-layout">
            <section className="card" aria-labelledby="versions-title">
              <h2 id="versions-title">{t('history.versions')}</h2>
              <ol className="history-list" data-testid="history-versions">
                {items.map((v) => (
                  <li key={v.version} className={v.version === selected ? 'is-selected' : ''}>
                    <button type="button" className="history-row" aria-pressed={v.version === selected} onClick={() => {
                      setSelected(v.version);
                      setCompareFrom(previousVersion(items, v.version));
                    }}>
                      <span className="history-version">
                        <strong>v{v.version}</strong>
                        {v.version === versions?.current ? <Badge tone="ok">{t('history.currentBadge')}</Badge> : null}
                        <Badge tone={v.kind === 'rollback' ? 'warn' : 'neutral'}>
                          {v.kind === 'rollback' && v.rolled_back_to !== null ? t('history.kind.rollbackTo', { version: v.rolled_back_to }) : t(`history.kind.${v.kind}` as MessageKey)}
                        </Badge>
                        {v.log_only ? <Badge tone="warn">{t('policy.logOnlyBadge')}</Badge> : null}
                        {!v.enabled ? <Badge tone="off">{t('flow.disabledBadge')}</Badge> : null}
                      </span>
                      <span className="muted small">
                        <RelativeTime value={v.created_at} /> · {v.author?.email ?? t('history.noAuthor')} · {t('policy.rules', { count: v.rules.length })}
                      </span>
                      {v.reason ? <span className="small history-reason">“{v.reason}”</span> : null}
                    </button>
                  </li>
                ))}
              </ol>
            </section>
            <section className="card" aria-labelledby="diff-title">
              <h2 id="diff-title">{t('history.changes')}</h2>
              {selectedVersion ? (
                <>
                  <div className="toolbar">
                    <Field label={t('history.compareWith')}>
                      {(p) => (
                        <select {...p} value={compareFrom ?? ''} onChange={(e) => setCompareFrom(e.target.value === '' ? null : Number(e.target.value))} data-testid="history-compare">
                          <option value="">{t('history.compareNone')}</option>
                          {items
                            .filter((v) => v.version !== selected)
                            .map((v) => (
                              <option key={v.version} value={v.version}>
                                v{v.version} · {formatTime(v.created_at)}
                              </option>
                            ))}
                        </select>
                      )}
                    </Field>
                    <span className="spacer" />
                    {writable && selected !== versions?.current ? (
                      <button type="button" className="btn btn-primary" onClick={() => setRollback(selectedVersion)}>
                        {t('history.rollbackTo', { version: selectedVersion.version })}
                      </button>
                    ) : null}
                  </div>
                  <ErrorBanner error={diffError} />
                  {compareFrom === null ? (
                    <div data-testid="history-rules">
                      <p className="muted small">{t('history.contents', { version: selectedVersion.version })}</p>
                      <dl className="kv">
                        <dt>{t('policy.name')}</dt>
                        <dd>{selectedVersion.name}</dd>
                        <dt>{t('policy.project')}</dt>
                        <dd>{projectName(selectedVersion.project_id)}</dd>
                      </dl>
                      <ol className="history-rules">
                        {selectedVersion.rules.map((r) => (
                          <li key={r.id ?? r.name}>
                            <strong>{r.name}</strong> <code className="small">{ruleLine(r)}</code>
                          </li>
                        ))}
                      </ol>
                    </div>
                  ) : diff ? (
                    <div data-testid="history-diff">
                      <p className="muted small">{t('history.diffOf', { from: diff.from, to: diff.to })}</p>
                      {diff.fields.length === 0 && diff.rules.length === 0 ? <p className="muted">{t('history.noChanges')}</p> : null}
                      <ul className="history-changes">
                        {diff.fields.map((c) => (
                          <li key={c.field} className="diff-field">
                            {fieldChangeText(t, c, projectName)}
                          </li>
                        ))}
                        {diff.rules.map((c: PolicyRuleChange) => (
                          <li key={c.rule_id} className={`diff-${c.op}`}>
                            <Badge tone={c.op === 'added' ? 'ok' : c.op === 'removed' ? 'danger' : 'warn'}>{t(`history.op.${c.op}` as MessageKey)}</Badge> <strong>{c.name}</strong>
                            {c.op === 'moved' ? <span className="muted small"> {t('history.moved', { from: c.from_index + 1, to: c.to_index + 1 })}</span> : null}
                            {c.from && c.op !== 'moved' ? (
                              <div className="diff-line diff-from">
                                <code className="small">− {ruleLine(c.from)}</code>
                              </div>
                            ) : null}
                            {c.to && c.op !== 'moved' ? (
                              <div className="diff-line diff-to">
                                <code className="small">+ {ruleLine(c.to)}</code>
                              </div>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <Loading />
                  )}
                </>
              ) : (
                <p className="muted">{t('history.pick')}</p>
              )}
            </section>
          </div>
        </>
      )}

      <Dialog
        open={rollback !== null}
        title={rollback ? t('history.rollbackTo', { version: rollback.version }) : ''}
        onClose={() => setRollback(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setRollback(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void doRollback()}>
              {busy ? t('common.saving') : t('history.rollback')}
            </button>
          </>
        }
      >
        <ErrorBanner error={rollbackError} />
        <p>{rollback ? t('history.rollbackBody', { version: rollback.version, current: versions?.current ?? 0 }) : null}</p>
        <Field label={t('history.reason')} help={t('history.reasonHelp')}>
          {(p) => <input {...p} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </Dialog>
    </div>
  );
}

export default PolicyHistoryPage;
