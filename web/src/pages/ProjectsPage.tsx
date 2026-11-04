// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from 'react';
import { ErrorBanner, Field, formatTime, PageHeader } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';

export function ProjectsPage() {
  const { api, t, notify } = useApp();
  const { org, projects, upstreams, reload } = useOrg();
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [error, setError] = useState<string | null>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.createProject(org.id, name, slug);
      setName('');
      setSlug('');
      notify(t('common.saved'));
      await reload();
    } catch (err) {
      setError(errorText(err));
    }
  };

  const setDefault = async (projectId: string, upstreamId: string | null) => {
    try {
      await api.setProjectDefaultUpstream(org.id, projectId, upstreamId);
      notify(t('common.saved'));
      await reload();
    } catch (err) {
      notify(errorText(err), 'error');
    }
  };

  return (
    <div>
      <PageHeader title={t('proj.title')} help={t('proj.help')} />
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t('common.name')}</th>
              <th scope="col">{t('proj.slug')}</th>
              <th scope="col">{t('proj.default')}</th>
              <th scope="col">{t('common.created')}</th>
            </tr>
          </thead>
          <tbody>
            {projects.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted">
                  {t('common.empty')}
                </td>
              </tr>
            ) : null}
            {projects.map((p) => (
              <tr key={p.id}>
                <td>
                  <strong>{p.name}</strong>
                  <div className="mono small muted">{p.id}</div>
                </td>
                <td className="mono">{p.slug}</td>
                <td>
                  <label className="sr-only" htmlFor={`pd-${p.id}`}>
                    {t('up.projectDefault', { name: p.name })}
                  </label>
                  <select
                    id={`pd-${p.id}`}
                    value={p.default_upstream_id ?? ''}
                    disabled={upstreams === null}
                    onChange={(e) => void setDefault(p.id, e.target.value || null)}
                  >
                    <option value="">{t('up.inherit')}</option>
                    {(upstreams ?? []).map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td>{formatTime(p.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form className="card" onSubmit={create}>
        <h2>{t('proj.new')}</h2>
        <ErrorBanner error={error} />
        <div className="form-grid">
          <Field label={t('common.name')}>{(p) => <input {...p} value={name} onChange={(e) => setName(e.target.value)} required />}</Field>
          <Field label={t('proj.slug')}>
            {(p) => <input {...p} className="mono" value={slug} pattern="[a-z0-9][a-z0-9\-]{0,62}" onChange={(e) => setSlug(e.target.value)} required />}
          </Field>
        </div>
        <button type="submit" className="btn btn-primary">
          {t('common.create')}
        </button>
      </form>
    </div>
  );
}
