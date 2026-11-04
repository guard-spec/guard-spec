// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { FolderKanban } from 'lucide-react';
import { useCallback, useState, type FormEvent } from 'react';
import { DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ErrorBanner, Field, formatTime, PageHeader, useDebounced } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { Project } from '../types';

export function ProjectsPage() {
  const { api, t, notify } = useApp();
  const { org, upstreams, reload, can } = useOrg();
  const writable = can('projects.write');
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const query = useDebounced(q);
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => api.listProjectsPage(org.id, { ...p, q: query || undefined }), [api, org.id, query]);
  const needle = query.trim().toLowerCase();
  const paged = usePaged<Project>(fetchPage, {
    clientFilter: needle ? (p) => `${p.name} ${p.slug}`.toLowerCase().includes(needle) : undefined,
  });

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.createProject(org.id, name, slug);
      setName('');
      setSlug('');
      notify(t('common.saved'));
      await Promise.all([reload(), paged.reload()]);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const setDefault = async (projectId: string, upstreamId: string | null) => {
    try {
      await api.setProjectDefaultUpstream(org.id, projectId, upstreamId);
      notify(t('common.saved'));
      await Promise.all([reload(), paged.reload()]);
    } catch (err) {
      notify(errorText(err), 'error');
    }
  };

  const columns: Column<Project>[] = [
    {
      key: 'name',
      header: t('common.name'),
      cell: (p) => (
        <div className="cell-stack">
          <strong>{p.name}</strong>
          <span className="mono small muted">{p.id}</span>
        </div>
      ),
    },
    { key: 'slug', header: t('proj.slug'), className: 'mono', cell: (p) => p.slug },
    {
      key: 'default',
      header: t('proj.default'),
      cell: (p) => (
        <>
          <label className="sr-only" htmlFor={`pd-${p.id}`}>
            {t('up.projectDefault', { name: p.name })}
          </label>
          <select
            id={`pd-${p.id}`}
            value={p.default_upstream_id ?? ''}
            disabled={upstreams === null || !can('upstreams.write')}
            onChange={(e) => void setDefault(p.id, e.target.value || null)}
          >
            <option value="">{t('up.inherit')}</option>
            {(upstreams ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name ? `${u.display_name} (${u.name})` : u.name}
              </option>
            ))}
          </select>
        </>
      ),
    },
    { key: 'created', header: t('common.created'), className: 'nowrap small', cell: (p) => formatTime(p.created_at) },
  ];

  return (
    <div>
      <PageHeader title={t('proj.title')} help={t('proj.help')} />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(p) => p.id}
        testId="projects-table"
        toolbar={<SearchBox value={q} onChange={setQ} label={t('proj.search')} />}
        empty={<EmptyState icon={FolderKanban} title={needle ? t('table.noMatch') : t('proj.empty')} />}
      />
      {writable ? (
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
      ) : null}
    </div>
  );
}
