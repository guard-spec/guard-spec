// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Key, Plus } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Badge, DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, formatTime, PageHeader, useDebounced, Day } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { ApiKey, CreatedApiKey, NewApiKey } from '../types';

function limit(v: string): number | null {
  return v.trim() === '' ? null : Math.max(0, Math.trunc(Number(v)));
}

export function KeysPage() {
  const { api, t, notify } = useApp();
  const { org, projects, can } = useOrg();
  const [q, setQ] = useState('');
  const [showRevoked, setShowRevoked] = useState(true);
  const query = useDebounced(q);
  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listApiKeysPage(org.id, { ...p, q: query || undefined, revoked: showRevoked ? undefined : false }),
    [api, org.id, query, showRevoked],
  );
  const needle = query.trim().toLowerCase();
  const paged = usePaged<ApiKey>(fetchPage, {
    clientFilter:
      needle || !showRevoked
        ? (k) => (showRevoked || !k.revoked) && (!needle || `${k.alias ?? ''} ${k.key_prefix}`.toLowerCase().includes(needle))
        : undefined,
  });
  const reload = paged.reload;
  const [form, setForm] = useState<{ alias: string; project: string; rpm: string; tpm: string; expires: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [secret, setSecret] = useState<CreatedApiKey | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);

  const create = async () => {
    if (!form) return;
    setFormError(null);
    try {
      const input: NewApiKey = { alias: form.alias, project_id: form.project || null, rpm_limit: limit(form.rpm), tpm_limit: limit(form.tpm) };
      if (form.expires) input.expires_at = new Date(form.expires).toISOString();
      const created = await api.createApiKey(org.id, input);
      setForm(null);
      setSecret(created);
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    }
  };

  const projectName = (id: string | null) => (id ? (projects.find((p) => p.id === id)?.name ?? id) : '—');
  const writable = can('api_keys.manage');

  const columns: Column<ApiKey>[] = [
    { key: 'alias', header: t('keys.alias'), cell: (k) => k.alias ?? '—' },
    { key: 'prefix', header: t('keys.prefix'), className: 'mono', cell: (k) => `${k.key_prefix}…` },
    { key: 'project', header: t('keys.project'), cell: (k) => projectName(k.project_id) },
    { key: 'rpm', header: t('keys.rpm'), cell: (k) => k.rpm_limit ?? '—' },
    { key: 'tpm', header: t('keys.tpm'), cell: (k) => k.tpm_limit ?? '—' },
    { key: 'created', header: t('common.created'), className: 'nowrap small', cell: (k) => formatTime(k.created_at) },
    { key: 'expires', header: t('keys.expires'), className: 'nowrap small', cell: (k) => (k.expires_at ? <Day value={k.expires_at} /> : t('keys.never')) },
    { key: 'status', header: t('keys.status'), cell: (k) => <Badge tone={k.revoked ? 'off' : 'ok'}>{k.revoked ? t('keys.revoked') : t('keys.active')}</Badge> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (k) =>
        !k.revoked && writable ? (
          <button type="button" className="btn btn-small btn-danger" aria-label={`${t('keys.revoke')} ${k.key_prefix}`} onClick={() => setRevoking(k)}>
            {t('keys.revoke')}
          </button>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('keys.title')}
        help={t('keys.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={() => setForm({ alias: '', project: '', rpm: '', tpm: '', expires: '' })}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('keys.new')}</span>
            </button>
          ) : null
        }
      />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(k) => k.key_prefix}
        rowClassName={(k) => (k.revoked ? 'row-muted' : '')}
        testId="keys-table"
        toolbar={
          <>
            <SearchBox value={q} onChange={setQ} label={t('keys.search')} />
            <label className="check">
              <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} />
              <span>{t('keys.showRevoked')}</span>
            </label>
          </>
        }
        empty={<EmptyState icon={Key} title={t('keys.emptyTitle')} body={t('keys.emptyBody')} />}
      />

      <Dialog
        open={form !== null}
        title={t('keys.new')}
        onClose={() => setForm(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setForm(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void create()}>
              {t('common.create')}
            </button>
          </>
        }
      >
        <ErrorBanner error={formError} />
        {form ? (
          <>
            <Field label={t('keys.alias')}>{(p) => <input {...p} value={form.alias} onChange={(e) => setForm({ ...form, alias: e.target.value })} />}</Field>
            <Field label={t('keys.project')}>
              {(p) => (
                <select {...p} value={form.project} onChange={(e) => setForm({ ...form, project: e.target.value })}>
                  <option value="">{t('common.none')}</option>
                  {projects.map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <div className="form-grid">
              <Field label={t('keys.rpm')} help={t('keys.limitHelp')}>
                {(p) => <input {...p} type="number" min={0} value={form.rpm} onChange={(e) => setForm({ ...form, rpm: e.target.value })} />}
              </Field>
              <Field label={t('keys.tpm')} help={t('keys.limitHelp')}>
                {(p) => <input {...p} type="number" min={0} value={form.tpm} onChange={(e) => setForm({ ...form, tpm: e.target.value })} />}
              </Field>
            </div>
            <Field label={t('keys.expires')}>
              {(p) => <input {...p} type="datetime-local" value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })} />}
            </Field>
          </>
        ) : null}
      </Dialog>

      <Dialog
        open={secret !== null}
        title={t('keys.secretTitle')}
        onClose={() => setSecret(null)}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => setSecret(null)}>
            {t('common.close')}
          </button>
        }
      >
        <p className="banner banner-warn">{t('keys.secretHelp')}</p>
        <div className="secret-row">
          <code className="secret" data-testid="new-key-secret">
            {secret?.key}
          </code>
          {secret ? <CopyButton text={secret.key} /> : null}
        </div>
      </Dialog>

      <ConfirmDialog
        open={revoking !== null}
        title={t('keys.revoke')}
        body={t('keys.confirmRevoke', { name: revoking?.alias ?? revoking?.key_prefix ?? '' })}
        confirmLabel={t('keys.revoke')}
        danger
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await api.revokeApiKey(org.id, revoking.key_prefix);
            await reload();
          } catch (e) {
            notify(errorText(e), 'error');
          }
          setRevoking(null);
        }}
      />
    </div>
  );
}
