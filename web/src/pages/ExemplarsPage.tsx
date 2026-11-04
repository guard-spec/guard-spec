// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';
import { ConfirmDialog, Dialog, ErrorBanner, Field, formatTime, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { Exemplar } from '../types';

interface Draft {
  id: string | null;
  label: 'block' | 'allow';
  text: string;
  source: string;
}

export function ExemplarsPage() {
  const { api, t, notify } = useApp();
  const { org } = useOrg();
  const { data, error, loading, reload } = useLoad(useCallback(() => api.listExemplars(org.id), [api, org.id]));
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Exemplar | null>(null);

  const save = async () => {
    if (!draft) return;
    setFormError(null);
    try {
      const body = { label: draft.label, text: draft.text, source: draft.source };
      if (draft.id) await api.updateExemplar(org.id, draft.id, body);
      else await api.createExemplar(org.id, body);
      setDraft(null);
      notify(t('common.saved'));
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    }
  };

  return (
    <div>
      <PageHeader
        title={t('ex.title')}
        help={t('ex.help')}
        actions={
          <button type="button" className="btn btn-primary" onClick={() => setDraft({ id: null, label: 'block', text: '', source: '' })}>
            + {t('ex.new')}
          </button>
        }
      />
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : null}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t('ex.label')}</th>
              <th scope="col">{t('ex.text')}</th>
              <th scope="col">{t('ex.source')}</th>
              <th scope="col">{t('common.created')}</th>
              <th scope="col">
                <span className="sr-only">{t('common.actions')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {data?.data.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  {t('common.empty')}
                </td>
              </tr>
            ) : null}
            {data?.data.map((x) => (
              <tr key={x.id}>
                <td>
                  <span className={`action action-${x.label}`}>{x.label}</span>
                </td>
                <td className="text-cell">{x.text}</td>
                <td>{x.source}</td>
                <td>{formatTime(x.created_at)}</td>
                <td className="row-actions">
                  <button type="button" className="btn btn-small" onClick={() => setDraft({ id: x.id, label: x.label, text: x.text, source: x.source })}>
                    {t('common.edit')}
                  </button>
                  <button type="button" className="btn btn-small btn-danger" onClick={() => setDeleting(x)}>
                    {t('common.delete')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Dialog
        open={draft !== null}
        title={draft?.id ? t('common.edit') : t('ex.new')}
        onClose={() => setDraft(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setDraft(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void save()}>
              {t('common.save')}
            </button>
          </>
        }
      >
        <ErrorBanner error={formError} />
        {draft ? (
          <>
            <Field label={t('ex.label')}>
              {(p) => (
                <select {...p} value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value as 'block' | 'allow' })}>
                  <option value="block">block</option>
                  <option value="allow">allow</option>
                </select>
              )}
            </Field>
            <Field label={t('ex.text')}>
              {(p) => <textarea {...p} rows={5} maxLength={4000} value={draft.text} onChange={(e) => setDraft({ ...draft, text: e.target.value })} />}
            </Field>
            <Field label={t('ex.source')}>
              {(p) => <input {...p} maxLength={200} value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })} />}
            </Field>
          </>
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        title={t('common.delete')}
        body={t('common.confirmDelete', { name: deleting ? `"${deleting.text.slice(0, 60)}"` : '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteExemplar(org.id, deleting.id);
            await reload();
          } catch (e) {
            notify(errorText(e), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}
