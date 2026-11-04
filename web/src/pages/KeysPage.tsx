// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, formatTime, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { ApiKey, CreatedApiKey, NewApiKey } from '../types';

function limit(v: string): number | null {
  return v.trim() === '' ? null : Math.max(0, Math.trunc(Number(v)));
}

export function KeysPage() {
  const { api, t, notify } = useApp();
  const { org, projects } = useOrg();
  const { data, error, loading, reload } = useLoad(useCallback(() => api.listApiKeys(org.id), [api, org.id]));
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

  return (
    <div>
      <PageHeader
        title={t('keys.title')}
        actions={
          <button type="button" className="btn btn-primary" onClick={() => setForm({ alias: '', project: '', rpm: '', tpm: '', expires: '' })}>
            + {t('keys.new')}
          </button>
        }
      />
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : null}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t('keys.alias')}</th>
              <th scope="col">{t('keys.prefix')}</th>
              <th scope="col">{t('keys.project')}</th>
              <th scope="col">{t('keys.rpm')}</th>
              <th scope="col">{t('keys.tpm')}</th>
              <th scope="col">{t('common.created')}</th>
              <th scope="col">{t('keys.expires')}</th>
              <th scope="col">{t('keys.status')}</th>
              <th scope="col">
                <span className="sr-only">{t('common.actions')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {data?.length === 0 ? (
              <tr>
                <td colSpan={9} className="muted">
                  {t('common.empty')}
                </td>
              </tr>
            ) : null}
            {data?.map((k) => (
              <tr key={k.key_prefix} className={k.revoked ? 'row-muted' : ''}>
                <td>{k.alias ?? '—'}</td>
                <td className="mono">{k.key_prefix}…</td>
                <td>{projectName(k.project_id)}</td>
                <td>{k.rpm_limit ?? '—'}</td>
                <td>{k.tpm_limit ?? '—'}</td>
                <td>{formatTime(k.created_at)}</td>
                <td>{k.expires_at ? formatTime(k.expires_at) : t('keys.never')}</td>
                <td>
                  <span className={k.revoked ? 'badge badge-off' : 'badge badge-ok'}>{k.revoked ? t('keys.revoked') : t('keys.active')}</span>
                </td>
                <td className="row-actions">
                  {!k.revoked ? (
                    <button type="button" className="btn btn-small btn-danger" aria-label={`${t('keys.revoke')} ${k.key_prefix}`} onClick={() => setRevoking(k)}>
                      {t('keys.revoke')}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

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
