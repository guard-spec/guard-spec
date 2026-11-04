// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState, type FormEvent } from 'react';
import { ErrorBanner, Field, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp } from '../context';
import type { MessageKey } from '../i18n';
import { prefs, session } from '../session';
import type { Org } from '../types';

/** The organization seeded by migration 002. */
export const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// The organizations of the signed-in user (GET /v1/organizations). Opening
// one by id stays available: for a control plane without that list, and for
// pasting an id.
export function OrgPicker({ onChoose }: { onChoose: (org: Org) => void }) {
  const { api, t } = useApp();
  const mine = useLoad(useCallback(() => api.listMyOrgs(), [api]));
  const [id, setId] = useState(session.orgId() ?? DEFAULT_ORG_ID);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const recent = prefs.recentOrgs();

  const open = async (orgId: string) => {
    setError(null);
    try {
      const org = await api.getOrg(orgId.trim());
      prefs.addRecentOrg({ id: org.id, name: org.name });
      onChoose(org);
    } catch (e) {
      setError(t('org.notFound', { error: errorText(e) }));
    }
  };

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const org = await api.createOrg(name, slug);
      prefs.addRecentOrg({ id: org.id, name: org.name });
      onChoose(org);
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="narrow">
      <PageHeader title={t('org.title')} help={t('org.listHelp')} />
      <ErrorBanner error={error} />
      {mine.loading && !mine.data ? <Loading /> : null}
      {mine.data ? (
        <section className="card" aria-labelledby="my-orgs">
          <h2 id="my-orgs">{t('org.mine')}</h2>
          {mine.data.length === 0 ? <p className="muted">{t('org.none')}</p> : null}
          <ul className="org-list" data-testid="my-orgs">
            {mine.data.map((o) => (
              <li key={o.id}>
                <button type="button" className="org-item" onClick={() => void open(o.id)}>
                  <strong>{o.name}</strong>
                  <span className="muted mono small">{o.slug}</span>
                  <span className="badge">{t(`org.role.${o.role}` as MessageKey)}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {!mine.data && !mine.loading && recent.length > 0 ? (
        <section className="card">
          <h2>{t('org.recent')}</h2>
          <ul className="plain-list">
            {recent.map((o) => (
              <li key={o.id}>
                <button type="button" className="btn btn-link" onClick={() => void open(o.id)}>
                  {o.name} <span className="muted mono">{o.id}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void open(id);
        }}
      >
        <h2>{t('org.byId')}</h2>
        <p className="muted small">{t('org.help', { id: DEFAULT_ORG_ID })}</p>
        <div className="form-row">
          <Field label={t('org.id')}>{(p) => <input {...p} className="mono" value={id} onChange={(e) => setId(e.target.value)} required />}</Field>
          <button type="submit" className="btn">
            {t('org.open')}
          </button>
        </div>
      </form>
      <form className="card" onSubmit={create}>
        <h2>{t('org.createTitle')}</h2>
        <div className="form-grid">
          <Field label={t('common.name')}>{(p) => <input {...p} value={name} onChange={(e) => setName(e.target.value)} required />}</Field>
          <Field label={t('org.slug')}>{(p) => <input {...p} value={slug} onChange={(e) => setSlug(e.target.value)} required />}</Field>
        </div>
        <button type="submit" className="btn">
          {t('common.create')}
        </button>
      </form>
    </div>
  );
}
