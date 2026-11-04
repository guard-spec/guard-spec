// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import { API_KEY_ENV_RE, UPSTREAM_NAME_RE, type Upstream, type UpstreamInput } from '../types';

const EMPTY: UpstreamInput = { name: '', base_url: '', model: '', api_key_env: '', timeout_ms: 300000, enabled: true };

export function validateUpstream(u: UpstreamInput): Partial<Record<keyof UpstreamInput, 'name' | 'url' | 'env'>> {
  const errs: Partial<Record<keyof UpstreamInput, 'name' | 'url' | 'env'>> = {};
  if (!UPSTREAM_NAME_RE.test(u.name)) errs.name = 'name';
  try {
    const url = new URL(u.base_url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') errs.base_url = 'url';
  } catch {
    errs.base_url = 'url';
  }
  if (u.api_key_env !== '' && !API_KEY_ENV_RE.test(u.api_key_env)) errs.api_key_env = 'env';
  return errs;
}

export function UpstreamsPage() {
  const { api, t, notify } = useApp();
  const { org, projects, upstreams, upstreamError, reload, setOrg } = useOrg();
  const [editing, setEditing] = useState<{ id: string | null; value: UpstreamInput } | null>(null);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A server refusal of the key variable (UPSTREAM_KEY_ORGS), shown at the field.
  const [keyEnvError, setKeyEnvError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Upstream | null>(null);

  const errs = editing ? validateUpstream(editing.value) : {};
  const msg = (k: keyof UpstreamInput) => {
    if (k === 'api_key_env' && keyEnvError) return keyEnvError;
    if (!touched) return undefined;
    const e = errs[k];
    return e === 'name' ? t('up.invalidName') : e === 'url' ? t('up.invalidUrl') : e === 'env' ? t('up.invalidEnv') : undefined;
  };

  const save = async () => {
    setTouched(true);
    if (!editing || Object.keys(errs).length > 0) return;
    try {
      if (editing.id) await api.updateUpstream(org.id, editing.id, editing.value);
      else await api.createUpstream(org.id, editing.value);
      setEditing(null);
      notify(t('common.saved'));
      await reload();
    } catch (e) {
      const m = errorText(e);
      if (m.includes('api_key_env')) setKeyEnvError(m);
      else setError(m);
    }
  };

  const setDefault = async (projectId: string | null, upstreamId: string | null) => {
    try {
      if (projectId) await api.setProjectDefaultUpstream(org.id, projectId, upstreamId);
      else {
        await api.setOrgDefaultUpstream(org.id, upstreamId);
        setOrg({ ...org, default_upstream_id: upstreamId });
      }
      notify(t('common.saved'));
      await reload();
    } catch (e) {
      notify(errorText(e), 'error');
    }
  };

  const set = (patch: Partial<UpstreamInput>) => {
    if ('api_key_env' in patch) setKeyEnvError(null);
    if (editing) setEditing({ ...editing, value: { ...editing.value, ...patch } });
  };
  const list = upstreams ?? [];

  return (
    <div>
      <PageHeader
        title={t('up.title')}
        help={t('up.help')}
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              setTouched(false);
              setError(null);
              setKeyEnvError(null);
              setEditing({ id: null, value: { ...EMPTY } });
            }}
          >
            + {t('up.new')}
          </button>
        }
      />
      {upstreamError ? <div className="banner banner-warn">{t('common.notAvailable', { error: upstreamError })}</div> : null}
      <p className="muted small">{t('up.resolution')}</p>
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t('up.name')}</th>
              <th scope="col">{t('up.baseUrl')}</th>
              <th scope="col">{t('up.model')}</th>
              <th scope="col">{t('up.keyEnv')}</th>
              <th scope="col">{t('up.timeout')}</th>
              <th scope="col">{t('up.enabled')}</th>
              <th scope="col">
                <span className="sr-only">{t('common.actions')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.length === 0 ? (
              <tr>
                <td colSpan={7} className="muted">
                  {t('common.empty')}
                </td>
              </tr>
            ) : null}
            {list.map((u) => (
              <tr key={u.id}>
                <td>
                  <strong className="mono">{u.name}</strong>
                  {org.default_upstream_id === u.id ? <span className="badge badge-accent">{t('flow.defaultBadge')}</span> : null}
                </td>
                <td className="mono small">{u.base_url}</td>
                <td className="mono small">{u.model || '—'}</td>
                <td className="mono small">{u.api_key_env ? `$${u.api_key_env}` : '—'}</td>
                <td>{u.timeout_ms}</td>
                <td>{u.enabled ? t('common.yes') : t('common.no')}</td>
                <td className="row-actions">
                  <button
                    type="button"
                    className="btn btn-small"
                    aria-label={t('up.edit', { name: u.name })}
                    onClick={() => {
                      setTouched(false);
                      setError(null);
                      setKeyEnvError(null);
                      setEditing({
                        id: u.id,
                        value: { name: u.name, base_url: u.base_url, model: u.model, api_key_env: u.api_key_env, timeout_ms: u.timeout_ms, enabled: u.enabled },
                      });
                    }}
                  >
                    {t('common.edit')}
                  </button>
                  <button type="button" className="btn btn-small btn-danger" aria-label={`${t('common.delete')} ${u.name}`} onClick={() => setDeleting(u)}>
                    {t('common.delete')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="card" aria-labelledby="defaults-title">
        <h2 id="defaults-title">{t('up.defaults')}</h2>
        <div className="form-grid">
          <DefaultSelect
            label={t('up.orgDefault')}
            value={org.default_upstream_id ?? null}
            emptyLabel={t('up.gatewayDefault')}
            upstreams={list}
            onChange={(id) => void setDefault(null, id)}
          />
          {projects.map((p) => (
            <DefaultSelect
              key={p.id}
              label={t('up.projectDefault', { name: p.name })}
              value={p.default_upstream_id ?? null}
              emptyLabel={t('up.inherit')}
              upstreams={list}
              onChange={(id) => void setDefault(p.id, id)}
            />
          ))}
        </div>
      </section>

      <Dialog
        open={editing !== null}
        title={editing?.id ? t('up.edit', { name: editing.value.name }) : t('up.new')}
        onClose={() => setEditing(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setEditing(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void save()}>
              {t('common.save')}
            </button>
          </>
        }
      >
        <ErrorBanner error={error} />
        {editing ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <Field label={t('up.name')} help={t('up.nameHelp')} error={msg('name')}>
              {(p) => <input {...p} className="mono" value={editing.value.name} onChange={(e) => set({ name: e.target.value })} required />}
            </Field>
            <Field label={t('up.baseUrl')} help={t('up.baseUrlHelp')} error={msg('base_url')}>
              {(p) => (
                <input
                  {...p}
                  className="mono"
                  type="url"
                  placeholder="https://api.openai.com/v1"
                  value={editing.value.base_url}
                  onChange={(e) => set({ base_url: e.target.value })}
                  required
                />
              )}
            </Field>
            <Field label={t('up.model')} help={t('up.modelHelp')}>
              {(p) => <input {...p} className="mono" value={editing.value.model} onChange={(e) => set({ model: e.target.value })} />}
            </Field>
            <Field label={t('up.keyEnv')} help={`${t('up.keyEnvHelp')} ${t('up.keyEnvOrgs')}`} error={msg('api_key_env')}>
              {(p) => (
                <input
                  {...p}
                  className="mono"
                  placeholder="UPSTREAM_KEY_MAIN"
                  autoComplete="off"
                  spellCheck={false}
                  value={editing.value.api_key_env}
                  onChange={(e) => set({ api_key_env: e.target.value.toUpperCase() })}
                />
              )}
            </Field>
            <div className="form-grid">
              <Field label={t('up.timeout')}>
                {(p) => (
                  <input
                    {...p}
                    type="number"
                    min={1000}
                    step={1000}
                    value={editing.value.timeout_ms}
                    onChange={(e) => set({ timeout_ms: Number(e.target.value) })}
                  />
                )}
              </Field>
              <label className="check">
                <input type="checkbox" checked={editing.value.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
                <span>{t('up.enabled')}</span>
              </label>
            </div>
            <button type="submit" hidden />
          </form>
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={deleting !== null}
        title={t('common.delete')}
        body={t('common.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteUpstream(org.id, deleting.id);
            notify(t('common.deleted'));
            await reload();
          } catch (e) {
            notify(t('up.inUse', { error: errorText(e) }), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}

function DefaultSelect({
  label,
  value,
  emptyLabel,
  upstreams,
  onChange,
}: {
  label: string;
  value: string | null;
  emptyLabel: string;
  upstreams: Upstream[];
  onChange: (id: string | null) => void;
}) {
  return (
    <Field label={label}>
      {(p) => (
        <select {...p} value={value ?? ''} onChange={(e) => onChange(e.target.value || null)}>
          <option value="">{emptyLabel}</option>
          {upstreams.map((u) => (
            <option key={u.id} value={u.id}>
              {u.name}
            </option>
          ))}
        </select>
      )}
    </Field>
  );
}
