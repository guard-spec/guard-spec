// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Two-person approval (migration 027): the requests waiting for a second
// admin, and the decided ones. The requester cannot approve their own.

import { ClipboardCheck } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Badge, EmptyState, Forbidden, NotAvailable } from '../components/DataTable';
import { Dialog, ErrorBanner, Field, Loading, PageHeader, RelativeTime, formatTime, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey, Translate } from '../i18n';
import { href, onLink } from '../router';
import type { ApprovalRequest, ApprovalStatus } from '../types';

/** The request in words: what it asks for, naming the policy when known. */
export function approvalText(t: Translate, r: Pick<ApprovalRequest, 'kind' | 'target' | 'target_label'>): string {
  const name = r.target_label ?? r.target ?? '';
  return t(`approvals.kind.${r.kind}` as MessageKey, { name });
}

/** Whether a request may still be decided (pending and not past its time). */
export function decidable(r: Pick<ApprovalRequest, 'status' | 'expires_at'>, now = Date.now()): boolean {
  return r.status === 'pending' && Date.parse(r.expires_at) > now;
}

const TONES: Record<ApprovalStatus, 'warn' | 'ok' | 'danger' | 'off'> = { pending: 'warn', approved: 'ok', rejected: 'danger', expired: 'off' };

export function ApprovalsPage() {
  const { api, t, notify, me } = useApp();
  const { org, can } = useOrg();
  const [status, setStatus] = useState<ApprovalStatus | 'all'>('pending');
  const { data, error, loading, notFound, forbidden, reload } = useLoad(useCallback(() => api.listApprovals(org.id, status), [api, org.id, status]));
  const [decision, setDecision] = useState<{ request: ApprovalRequest; approve: boolean } | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const mayDecide = can('approvals.decide');

  const decide = async () => {
    if (!decision) return;
    setBusy(true);
    setDecisionError(null);
    try {
      if (decision.approve) await api.approveRequest(org.id, decision.request.id, note.trim() || undefined);
      else await api.rejectRequest(org.id, decision.request.id, note.trim() || undefined);
      notify(decision.approve ? t('approvals.approved') : t('approvals.rejected'));
      setDecision(null);
      setNote('');
      await reload();
    } catch (e) {
      setDecisionError(errorText(e));
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
              {(['pending', 'approved', 'rejected', 'expired', 'all'] as const).map((s) => (
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
                        <button type="button" className="btn btn-small btn-primary" onClick={() => setDecision({ request: r, approve: true })}>
                          {t('approvals.approve')}
                        </button>
                      ) : null}
                      <button type="button" className="btn btn-small btn-danger" onClick={() => setDecision({ request: r, approve: false })}>
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
        <p>{decision ? approvalText(t, decision.request) : null}</p>
        {decision?.approve ? <p className="banner banner-warn">{t('approvals.approveWarn')}</p> : null}
        <Field label={t('approvals.note')} help={t('approvals.noteHelp')}>
          {(p) => <input {...p} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />}
        </Field>
      </Dialog>
    </div>
  );
}

export default ApprovalsPage;
