// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Library, Plus } from 'lucide-react';
import { useCallback, useState } from 'react';
import { DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, useDebounced, Day } from '../components/ui';
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
  const { org, can } = useOrg();
  const writable = can('exemplars.write');
  const [q, setQ] = useState('');
  const [label, setLabel] = useState('');
  const query = useDebounced(q);
  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listExemplarsPage(org.id, { ...p, q: query || undefined, label: label || undefined }),
    [api, org.id, query, label],
  );
  const needle = query.trim().toLowerCase();
  const paged = usePaged<Exemplar>(fetchPage, {
    clientFilter: needle || label ? (x) => (!label || x.label === label) && (!needle || `${x.text} ${x.source}`.toLowerCase().includes(needle)) : undefined,
  });
  const reload = paged.reload;
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

  const columns: Column<Exemplar>[] = [
    { key: 'label', header: t('ex.label'), cell: (x) => <span className={`action action-${x.label}`}>{x.label}</span> },
    { key: 'text', header: t('ex.text'), className: 'text-cell', cell: (x) => x.text },
    { key: 'source', header: t('ex.source'), cell: (x) => x.source },
    { key: 'created', header: t('common.created'), className: 'nowrap small', cell: (x) => <Day value={x.created_at} /> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (x) =>
        writable ? (
          <>
            <button type="button" className="btn btn-small" onClick={() => setDraft({ id: x.id, label: x.label, text: x.text, source: x.source })}>
              {t('common.edit')}
            </button>
            <button type="button" className="btn btn-small btn-danger" onClick={() => setDeleting(x)}>
              {t('common.delete')}
            </button>
          </>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('ex.title')}
        help={t('ex.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={() => setDraft({ id: null, label: 'block', text: '', source: '' })}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('ex.new')}</span>
            </button>
          ) : null
        }
      />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(x) => x.id}
        testId="exemplars-table"
        toolbar={
          <>
            <SearchBox value={q} onChange={setQ} label={t('ex.search')} />
            <div className="field field-inline">
              <label htmlFor="ex-label-filter">{t('ex.label')}</label>
              <select id="ex-label-filter" value={label} onChange={(e) => setLabel(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                <option value="block">block</option>
                <option value="allow">allow</option>
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={Library} title={needle || label ? t('table.noMatch') : t('ex.empty')} />}
      />
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
