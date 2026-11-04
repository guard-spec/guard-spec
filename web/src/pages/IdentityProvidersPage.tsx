// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SSO providers of the instance (identity contract §2): Google as a preset
// and any OpenID Connect provider. The client secret stays in the control
// plane's environment; the UI only names the variable (client_secret_env).

import { Fingerprint, Pencil, Plus, Trash2 } from 'lucide-react';
import { useCallback, useState } from 'react';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, InstanceAdminOnly, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, PageHeader, Toggle } from '../components/ui';
import { authErrorText } from '../auth/errors';
import { useApp } from '../context';
import { CLIENT_SECRET_ENV_RE, GOOGLE_ISSUER, type IdentityProvider, type IdentityProviderInput } from '../types';

const GOOGLE: IdentityProviderInput = {
  type: 'google',
  display_name: 'Google',
  issuer: GOOGLE_ISSUER,
  client_id: '',
  client_secret_env: 'OIDC_SECRET_GOOGLE',
  scopes: ['openid', 'email', 'profile'],
  allowed_domains: [],
  auto_provision: false,
  trust_email_for_linking: false,
  enabled: true,
};

const OIDC: IdentityProviderInput = {
  type: 'oidc',
  display_name: '',
  issuer: '',
  client_id: '',
  client_secret_env: 'OIDC_SECRET_',
  scopes: ['openid', 'email', 'profile'],
  allowed_domains: [],
  auto_provision: false,
  trust_email_for_linking: false,
  enabled: true,
};

/** As validIssuer of the control plane: https, or http on a loopback host (a local test IdP). */
export function validIssuer(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (!u.host || u.username || u.password || u.search || u.hash) return false;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const loopback = host === 'localhost' || host.startsWith('127.') || host === '::1';
  return u.protocol === 'https:' || (u.protocol === 'http:' && loopback);
}

export function validateIdp(v: IdentityProviderInput): Partial<Record<'display_name' | 'issuer' | 'client_id' | 'client_secret_env', true>> {
  const e: Partial<Record<'display_name' | 'issuer' | 'client_id' | 'client_secret_env', true>> = {};
  if (!v.display_name.trim()) e.display_name = true;
  if (!validIssuer(v.issuer)) e.issuer = true;
  if (!v.client_id.trim()) e.client_id = true;
  if (!CLIENT_SECRET_ENV_RE.test(v.client_secret_env)) e.client_secret_env = true;
  return e;
}

export default function IdentityProvidersPage() {
  const { api, t, notify, me } = useApp();
  const [draft, setDraft] = useState<{ id: string | null; value: IdentityProviderInput } | null>(null);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<IdentityProvider | null>(null);
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => api.listIdentityProvidersPage(p), [api]);
  const paged = usePaged<IdentityProvider>(fetchPage);

  if (me && !me.is_instance_admin) {
    return (
      <div>
        <PageHeader title={t('idp.title')} />
        <InstanceAdminOnly />
      </div>
    );
  }

  const errs = draft ? validateIdp(draft.value) : {};
  const set = (patch: Partial<IdentityProviderInput>) => draft && setDraft({ ...draft, value: { ...draft.value, ...patch } });
  const openNew = (preset: IdentityProviderInput) => {
    setTouched(false);
    setError(null);
    setDraft({ id: null, value: { ...preset, scopes: [...preset.scopes], allowed_domains: [] } });
  };
  const save = async () => {
    setTouched(true);
    if (!draft || Object.keys(errs).length > 0) return;
    setError(null);
    try {
      if (draft.id) await api.updateIdentityProvider(draft.id, draft.value);
      else await api.createIdentityProvider(draft.value);
      setDraft(null);
      notify(t('common.saved'));
      await paged.reload();
    } catch (e) {
      setError(authErrorText(e, t));
    }
  };

  const columns: Column<IdentityProvider>[] = [
    {
      key: 'name',
      header: t('common.name'),
      cell: (p) => (
        <div className="cell-stack">
          <strong>{p.display_name}</strong>
          <span className="mono small muted ellipsis col-issuer" title={p.issuer}>
            {p.issuer}
          </span>
        </div>
      ),
    },
    { key: 'type', header: t('idp.type'), cell: (p) => <Badge tone={p.type === 'google' ? 'accent' : 'neutral'}>{p.type === 'google' ? 'Google' : 'OIDC'}</Badge> },
    { key: 'client', header: t('idp.clientId'), className: 'col-env', cell: (p) => <span className="mono small ellipsis" title={p.client_id}>{p.client_id}</span> },
    { key: 'secret', header: t('idp.secretEnv'), className: 'col-env', cell: (p) => <span className="mono small ellipsis" title={`$${p.client_secret_env}`}>{`$${p.client_secret_env}`}</span> },
    {
      key: 'domains',
      header: t('idp.domains'),
      cell: (p) => (p.allowed_domains.length ? <span className="badges">{p.allowed_domains.map((d) => <Badge key={d}>{d}</Badge>)}</span> : <span className="muted">{t('idp.anyDomain')}</span>),
    },
    {
      key: 'status',
      header: t('prov.status'),
      cell: (p) => (
        <span className="badges">
          <Badge tone={p.enabled ? 'ok' : 'off'}>{p.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
          {p.auto_provision ? <Badge tone="warn">{t('idp.autoProvisionShort')}</Badge> : null}
          {p.trust_email_for_linking ? <Badge tone="warn">{t('idp.trustedShort')}</Badge> : null}
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (p) => (
        <span className="icon-actions">
          <button
            type="button"
            className="btn btn-small btn-square"
            aria-label={`${t('common.edit')}: ${p.display_name}`}
            title={t('common.edit')}
            onClick={() => {
              setTouched(false);
              setError(null);
              const { id, ...value } = p;
              setDraft({ id, value });
            }}
          >
            <Pencil size={14} aria-hidden="true" />
          </button>
          <button type="button" className="btn btn-small btn-square btn-danger" title={t('common.delete')} aria-label={`${t('common.delete')}: ${p.display_name}`} onClick={() => setDeleting(p)}>
            <Trash2 size={14} aria-hidden="true" />
          </button>
        </span>
      ),
    },
  ];

  const v = draft?.value;
  return (
    <div>
      <PageHeader
        title={t('idp.title')}
        help={t('idp.help')}
        actions={
          <>
            <button type="button" className="btn btn-icon-text" onClick={() => openNew(GOOGLE)}>
              <span className="provider-mark provider-google" aria-hidden="true">
                G
              </span>
              <span>{t('idp.addGoogle')}</span>
            </button>
            <button type="button" className="btn btn-primary btn-icon-text" onClick={() => openNew(OIDC)}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('idp.addOidc')}</span>
            </button>
          </>
        }
      />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(p) => p.id}
        testId="idp-table"
        feature={t('idp.title')}
        empty={<EmptyState icon={Fingerprint} title={t('idp.emptyTitle')} body={t('idp.emptyBody')} />}
      />
      <Dialog
        open={draft !== null}
        wide
        title={draft?.id ? t('idp.edit', { name: draft.value.display_name }) : v?.type === 'google' ? t('idp.addGoogle') : t('idp.addOidc')}
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
        <ErrorBanner error={error} />
        {draft && v ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <div className="banner banner-info">
              <div>
                <strong>{t('idp.redirectUri')}</strong>
                <div className="secret-row">
                  <code className="secret">{draft.id ? api.oidcCallbackUrl(draft.id) : api.oidcCallbackUrl(null)}</code>
                  {draft.id ? <CopyButton text={api.oidcCallbackUrl(draft.id)} /> : null}
                </div>
                {draft.id ? null : <small>{t('idp.redirectAfterSave')}</small>}
              </div>
            </div>
            <div className="form-grid">
              <Field label={t('prov.displayName')} error={touched && errs.display_name ? t('idp.required') : undefined}>
                {(p) => <input {...p} value={v.display_name} onChange={(e) => set({ display_name: e.target.value })} required />}
              </Field>
              <Field label={t('idp.type')}>
                {(p) => (
                  <select
                    {...p}
                    value={v.type}
                    onChange={(e) => set(e.target.value === 'google' ? { type: 'google', issuer: GOOGLE_ISSUER } : { type: 'oidc' })}
                  >
                    <option value="google">Google</option>
                    <option value="oidc">OpenID Connect</option>
                  </select>
                )}
              </Field>
            </div>
            <Field label={t('idp.issuer')} help={v.type === 'google' ? t('idp.issuerGoogle') : t('idp.issuerHelp')} error={touched && errs.issuer ? t('idp.issuerError') : undefined}>
              {(p) => (
                <input
                  {...p}
                  className="mono"
                  type="url"
                  readOnly={v.type === 'google'}
                  placeholder="https://login.example.com/realms/main"
                  value={v.issuer}
                  onChange={(e) => set({ issuer: e.target.value })}
                />
              )}
            </Field>
            <Field label={t('idp.clientId')} error={touched && errs.client_id ? t('idp.required') : undefined}>
              {(p) => <input {...p} className="mono" autoComplete="off" value={v.client_id} onChange={(e) => set({ client_id: e.target.value.trim() })} />}
            </Field>
            <Field label={t('idp.secretEnv')} help={t('idp.secretEnvHelp')} error={touched && errs.client_secret_env ? t('idp.secretEnvError') : undefined}>
              {(p) => (
                <input
                  {...p}
                  className="mono"
                  autoComplete="off"
                  spellCheck={false}
                  value={v.client_secret_env}
                  onChange={(e) => set({ client_secret_env: e.target.value.toUpperCase() })}
                />
              )}
            </Field>
            <ChipsInput label={t('idp.scopes')} values={v.scopes} onChange={(scopes) => set({ scopes })} suggestions={['openid', 'email', 'profile']} />
            <ChipsInput
              label={t('idp.domains')}
              help={v.type === 'google' ? t('idp.domainsHelpGoogle') : t('idp.domainsHelp')}
              values={v.allowed_domains}
              placeholder="example.com"
              normalize={(s) => s.trim().toLowerCase().replace(/^@/, '')}
              onChange={(allowed_domains) => set({ allowed_domains })}
            />
            <Toggle label={t('idp.autoProvision')} help={t('idp.autoProvisionHelp')} checked={v.auto_provision} onChange={(x) => set({ auto_provision: x })} />
            <Toggle
              label={t('idp.trustEmail')}
              help={t('idp.trustEmailHelp')}
              checked={v.trust_email_for_linking === true}
              onChange={(x) => set({ trust_email_for_linking: x })}
            />
            <Toggle label={t('common.enabled')} help={t('idp.enabledHelp')} checked={v.enabled} onChange={(x) => set({ enabled: x })} />
            <button type="submit" hidden />
          </form>
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        title={t('common.delete')}
        body={t('idp.confirmDelete', { name: deleting?.display_name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteIdentityProvider(deleting.id);
            notify(t('common.deleted'));
            await paged.reload();
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}
