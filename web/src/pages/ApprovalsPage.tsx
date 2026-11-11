// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Two-person approval (migrations 027 and 029): the requests waiting for a
// second admin, and the decided ones. The requester cannot approve their own.
// Instance administrators also see every organization's pending deletion,
// which they may approve.

import { ClipboardCheck } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Badge, EmptyState, Forbidden, NotAvailable } from '../components/DataTable';
import { Dialog, ErrorBanner, Field, Loading, PageHeader, RelativeTime, formatTime, useLoad } from '../components/ui';
import { ApiError } from '../api';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey, Translate } from '../i18n';
import { href, onLink } from '../router';
import { APPROVAL_STATUSES, type ApprovalRequest, type ApprovalStatus } from '../types';

/** The request in words: what it asks for, naming the policy when known. */
export function approvalText(t: Translate, r: Pick<ApprovalRequest, 'kind' | 'target' | 'target_label'>): string {
  const name = r.target_label ?? r.target ?? '';
  return t(`approvals.kind.${r.kind}` as MessageKey, { name });
}

/** Whether a request may still be decided (pending and not past its time). */
export function decidable(r: Pick<ApprovalRequest, 'status' | 'expires_at'>, now = Date.now()): boolean {
  return r.status === 'pending' && Date.parse(r.expires_at) > now;
}

const TONES: Record<ApprovalStatus, 'warn' | 'ok' | 'danger' | 'off'> = { pending: 'warn', approved: 'ok', rejected: 'danger', expired: 'off', cancelled: 'off' };

/** The organization a request of GET /admin/approvals is about, by its payload. */
export function orgLabel(r: Pick<ApprovalRequest, 'payload' | 'org_id'>): string {
  const p = r.payload as { name?: unknown; slug?: unknown };
  const name = typeof p.name === 'string' ? p.name : '';
  const slug = typeof p.slug === 'string' ? p.slug : '';
  if (name && slug && name !== slug) return `${name} (${slug})`;
  if (name) return name;
  if (slug) return slug;
  return r.org_id ?? '';
}

/** Whether a failed approval cancelled the request (its change no longer applies). */
export function cancelledOnApprove(e: unknown): boolean {
  return e instanceof ApiError && (e.body as { code?: unknown } | undefined)?.code === 'approval_cancelled';
}

export function ApprovalsPage() {
  const { api, t, notify, me } = useApp();
  const { org, can } = useOrg();
  const [status, setStatus] = useState<ApprovalStatus | 'all'>('pending');
  const { data, error, loading, notFound, forbidden, reload } = useLoad(useCallback(() => api.listApprovals(org.id, status), [api, org.id, status]));
  const instanceAdmin = me?.is_instance_admin === true;
  const deletions = useLoad(useCallback(() => (instanceAdmin ? api.listInstanceApprovals() : Promise.resolve([])), [api, instanceAdmin]));
  // orgId: the organization of the request (another one for an instance-wide deletion).
  const [decision, setDecision] = useState<{ request: ApprovalRequest; approve: boolean; orgId: string } | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const mayDecide = can('approvals.decide');

  const decide = async () => {
    if (!decision) return;
    setBusy(true);
    setDecisionError(null);
    try {
      if (decision.approve) await api.approveRequest(decision.orgId, decision.request.id, note.trim() || undefined);
      else await api.rejectRequest(decision.orgId, decision.request.id, note.trim() || undefined);
      notify(decision.approve ? t('approvals.approved') : t('approvals.rejected'));
      setDecision(null);
      setNote('');
      await Promise.all([reload(), deletions.reload()]);
    } catch (e) {
      if (cancelledOnApprove(e)) {
        // Nothing left to apply (the policy is gone or already disabled).
        notify(t('approvals.cancelledOnApprove', { reason: errorText(e) }), 'error');
        setDecision(null);
        setNote('');
        await reload();
      } else setDecisionError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (loading && !data) return <Loading />;
  if (error && !data) {
    return (
      <div className="narrow">
        <PageHeader title={t('approvals.title')} help={t('approvals.help')} />
        {notFound ? <NotAvailable feature={t('approvals.title')} /> : forbidden ? <Forbidden /> : <ErrorBanner error={error} />}
      </div>
    );
  }
  const items = data ?? [];
  return (
    <div>
      <PageHeader
        title={t('approvals.title')}
        help={t('approvals.help')}
        actions={
          <a className="btn" href={href('security')} onClick={onLink('security')}>
            {t('approvals.settings')}
          </a>
        }
      />
      <div className="toolbar">
        <Field label={t('approvals.status')}>
          {(p) => (
            <select {...p} value={status} onChange={(e) => setStatus(e.target.value as ApprovalStatus | 'all')} data-testid="approvals-status">
              {[...APPROVAL_STATUSES, 'all' as const].map((s) => (
                <option key={s} value={s}>
                  {t(`approvals.status.${s}` as MessageKey)}
                </option>
              ))}
            </select>
          )}
        </Field>
      </div>
      <ErrorBanner error={error} />
      {items.length === 0 ? (
        <EmptyState icon={ClipboardCheck} title={t('approvals.emptyTitle')} body={t('approvals.emptyBody')} />
      ) : (
        <ul className="approval-list" data-testid="approvals-list">
          {items.map((r) => {
            const mine = me?.id !== undefined && r.requested_by?.id === me.id;
            return (
              <li key={r.id} className="card approval-item">
                <div className="approval-head">
                  <Badge tone={TONES[r.status]}>{t(`approvals.status.${r.status}` as MessageKey)}</Badge>
                  <strong>{approvalText(t, r)}</strong>
                  <span className="spacer" />
                  {decidable(r) && mayDecide ? (
                    <>
                      {!mine ? (
                        <button type="button" className="btn btn-small btn-primary" onClick={() => setDecision({ request: r, approve: true, orgId: org.id })}>
                          {t('approvals.approve')}
                        </button>
                      ) : null}
                      <button type="button" className="btn btn-small btn-danger" onClick={() => setDecision({ request: r, approve: false, orgId: org.id })}>
                        {mine ? t('approvals.withdraw') : t('approvals.reject')}
                      </button>
                    </>
                  ) : null}
                </div>
                <div className="muted small">
                  {t('approvals.requestedBy', { email: r.requested_by?.email ?? t('history.noAuthor') })} · <RelativeTime value={r.created_at} />
                  {r.status === 'pending' ? <> · {t('approvals.expires', { when: formatTime(r.expires_at) })}</> : null}
                  {r.decided_by ? <> · {t('approvals.decidedBy', { email: r.decided_by.email ?? '' , when: formatTime(r.decided_at) })}</> : null}
                </div>
                {mine && decidable(r) ? <div className="small muted">{t('approvals.ownRequest')}</div> : null}
                {r.reason ? <div className="small">“{r.reason}”</div> : null}
                {r.decision_note ? <div className="small muted">{t('approvals.note')}: {r.decision_note}</div> : null}
              </li>
            );
          })}
        </ul>
      )}

      {instanceAdmin ? (
        <section className="card" data-testid="instance-deletions">
          <h3>{t('approvals.instanceTitle')}</h3>
          <p className="muted small">{t('approvals.instanceHelp')}</p>
          <ErrorBanner error={deletions.error} />
          {(deletions.data ?? []).length === 0 ? (
            <p className="muted small">{t('approvals.instanceEmpty')}</p>
          ) : (
            <ul className="approval-list">
              {(deletions.data ?? []).map((r) => (
                <li key={r.id} className="approval-item">
                  <div className="approval-head">
                    <Badge tone="warn">{t('approvals.status.pending')}</Badge>
                    <strong>{t('approvals.instanceItem', { org: orgLabel(r) })}</strong>
                    <span className="spacer" />
                    {r.requested_by?.id !== me.id ? (
                      <button type="button" className="btn btn-small btn-primary" onClick={() => setDecision({ request: r, approve: true, orgId: r.org_id ?? '' })}>
                        {t('approvals.approve')}
                      </button>
                    ) : null}
                    <button type="button" className="btn btn-small btn-danger" onClick={() => setDecision({ request: r, approve: false, orgId: r.org_id ?? '' })}>
                      {t('approvals.reject')}
                    </button>
                  </div>
                  <div className="muted small">
                    {t('approvals.requestedBy', { email: r.requested_by?.email ?? t('history.noAuthor') })} · <RelativeTime value={r.created_at} /> ·{' '}
                    {t('approvals.expires', { when: formatTime(r.expires_at) })}
                  </div>
                  {r.reason ? <div className="small">“{r.reason}”</div> : null}
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}

      <Dialog
        open={decision !== null}
        title={decision ? (decision.approve ? t('approvals.approve') : t('approvals.reject')) : ''}
        onClose={() => setDecision(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setDecision(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className={decision?.approve ? 'btn btn-primary' : 'btn btn-danger'} disabled={busy} onClick={() => void decide()}>
              {busy ? t('common.saving') : decision?.approve ? t('approvals.approve') : t('approvals.reject')}
            </button>
          </>
        }
      >
        <ErrorBanner error={decisionError} />
        <p>{decision ? (decision.orgId !== org.id ? t('approvals.instanceItem', { org: orgLabel(decision.request) }) : approvalText(t, decision.request)) : null}</p>
        {decision?.approve ? <p className="banner banner-warn">{t('approvals.approveWarn')}</p> : null}
        <Field label={t('approvals.note')} help={t('approvals.noteHelp')}>
          {(p) => <input {...p} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />}
        </Field>
      </Dialog>
    </div>
  );
}

export default ApprovalsPage;
