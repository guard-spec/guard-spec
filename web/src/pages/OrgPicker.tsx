// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from 'react';
import { ErrorBanner, Field, PageHeader } from '../components/ui';
import { errorText, useApp } from '../context';
import { prefs, session } from '../session';
import type { Org } from '../types';

/** The organization seeded by migration 002. */
export const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

// The API has no "my organizations" list, so the user enters an org id; the
// default org and recently opened ones are offered.
export function OrgPicker({ onChoose }: { onChoose: (org: Org) => void }) {
  const { api, t } = useApp();
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
      <PageHeader title={t('org.title')} help={t('org.help', { id: DEFAULT_ORG_ID })} />
      <ErrorBanner error={error} />
      <form
        className="card form-row"
        onSubmit={(e) => {
          e.preventDefault();
          void open(id);
        }}
      >
        <Field label={t('org.id')}>{(p) => <input {...p} className="mono" value={id} onChange={(e) => setId(e.target.value)} required />}</Field>
        <button type="submit" className="btn btn-primary">
          {t('org.open')}
        </button>
      </form>
      {recent.length > 0 ? (
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
