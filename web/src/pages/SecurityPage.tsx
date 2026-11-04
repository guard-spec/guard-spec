// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The organization's sign-in policy (identity contract §3): required 2FA,
// allowed login methods, domain join rules and the session lifetime.

import { Plus, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { isNotFound } from '../api';
import { NotAvailable } from '../components/DataTable';
import { ErrorBanner, Field, Loading, PageHeader, Toggle, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { ROLES, type LoginProvider, type OrgSecurity, type Role } from '../types';

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function methodKey(p: LoginProvider): string {
  return p.type === 'google' ? 'google' : `oidc:${p.id}`;
}

export function validateSecurity(s: OrgSecurity): string[] {
  const errs: string[] = [];
  if (s.allowed_login_methods.length === 0) errs.push('methods');
  if (!Number.isInteger(s.session_lifetime_hours) || s.session_lifetime_hours < 1 || s.session_lifetime_hours > 12) errs.push('lifetime');
  if (s.domain_join.some((d) => !DOMAIN_RE.test(d.domain) || d.provider_id === '')) errs.push('domain');
  return errs;
}

export function SecurityPage() {
  const { api, t, notify } = useApp();
  const { org, can } = useOrg();
  const writable = can('security.write');
  const { data, error, loading, notFound } = useLoad(useCallback(() => api.getOrgSecurity(org.id), [api, org.id]));
  const [draft, setDraft] = useState<OrgSecurity | null>(null);
  const [providers, setProviders] = useState<LoginProvider[]>([]);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.listLoginProviders().then(setProviders, () => setProviders([]));
  }, [api]);

  if (loading && !data) return <Loading />;
  if (error && !data) {
    return (
      <div className="narrow">
        <PageHeader title={t('sec.title')} help={t('sec.help')} />
        {notFound ? <NotAvailable feature={t('sec.title')} /> : <ErrorBanner error={error} />}
      </div>
    );
  }
  const s: OrgSecurity = draft ?? data ?? { require_mfa: false, sso_satisfies_mfa: false, allowed_login_methods: ['password'], domain_join: [], session_lifetime_hours: 12 };
  const set = (patch: Partial<OrgSecurity>) => setDraft({ ...s, ...patch });
  const errs = touched ? validateSecurity(s) : [];
  const methods = [{ key: 'password', label: t('sec.methodPassword') }, ...providers.map((p) => ({ key: methodKey(p), label: p.display_name }))];
  // Methods saved before a provider was removed stay listed.
  for (const m of s.allowed_login_methods) if (!methods.some((x) => x.key === m)) methods.push({ key: m, label: m });

  const save = async () => {
    setTouched(true);
    if (validateSecurity(s).length > 0) return;
    setBusy(true);
    setSaveError(null);
    try {
      setDraft(await api.putOrgSecurity(org.id, s));
      notify(t('common.saved'));
    } catch (e) {
      setSaveError(isNotFound(e) ? t('na.title') : errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="narrow">
      <PageHeader title={t('sec.title')} help={t('sec.help')} />
      {!writable ? <div className="banner banner-info">{t('sec.readOnly')}</div> : null}
      <ErrorBanner error={saveError} />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <fieldset className="card" disabled={!writable}>
          <legend>{t('sec.mfaTitle')}</legend>
          <Toggle label={t('sec.requireMfa')} help={t('sec.requireMfaHelp')} checked={s.require_mfa} onChange={(v) => set({ require_mfa: v })} />
          <Toggle
            label={t('sec.ssoSatisfies')}
            help={t('sec.ssoSatisfiesHelp')}
            checked={s.sso_satisfies_mfa}
            disabled={!s.require_mfa}
            onChange={(v) => set({ sso_satisfies_mfa: v })}
          />
        </fieldset>

        <fieldset className="card" disabled={!writable}>
          <legend>{t('sec.methods')}</legend>
          <p className="muted small">{t('sec.methodsHelp')}</p>
          {methods.map((m) => (
            <label key={m.key} className="check">
              <input
                type="checkbox"
                checked={s.allowed_login_methods.includes(m.key)}
                onChange={(e) =>
                  set({ allowed_login_methods: e.target.checked ? [...s.allowed_login_methods, m.key] : s.allowed_login_methods.filter((x) => x !== m.key) })
                }
              />
              <span>{m.label}</span>
              <span className="mono small muted">{m.key}</span>
            </label>
          ))}
          {errs.includes('methods') ? <small className="field-error">{t('sec.methodsError')}</small> : null}
        </fieldset>

        <fieldset className="card" disabled={!writable}>
          <legend>{t('sec.domainJoin')}</legend>
          <p className="muted small">{t('sec.domainJoinHelp')}</p>
          {s.domain_join.length === 0 ? <p className="muted">{t('sec.noDomains')}</p> : null}
          {s.domain_join.map((d, i) => (
            <div key={i} className="kv-row kv-row-3">
              <input
                className="mono"
                aria-label={t('sec.domain', { n: i + 1 })}
                placeholder="example.com"
                value={d.domain}
                onChange={(e) => set({ domain_join: s.domain_join.map((x, j) => (j === i ? { ...x, domain: e.target.value.trim().toLowerCase() } : x)) })}
              />
              <select
                aria-label={t('sec.provider', { n: i + 1 })}
                value={d.provider_id}
                onChange={(e) => set({ domain_join: s.domain_join.map((x, j) => (j === i ? { ...x, provider_id: e.target.value } : x)) })}
              >
                <option value="" disabled>{t('sec.chooseProvider')}</option>
                {providers.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.display_name}
                  </option>
                ))}
              </select>
              <select
                aria-label={t('sec.joinRole', { n: i + 1 })}
                value={d.role}
                onChange={(e) => set({ domain_join: s.domain_join.map((x, j) => (j === i ? { ...x, role: e.target.value as Role } : x)) })}
              >
                {ROLES.filter((r) => r !== 'owner').map((r) => (
                  <option key={r} value={r}>
                    {t(`org.role.${r}` as MessageKey)}
                  </option>
                ))}
              </select>
              <button type="button" className="btn-icon" aria-label={t('sec.removeDomain', { n: i + 1 })} onClick={() => set({ domain_join: s.domain_join.filter((_, j) => j !== i) })}>
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </div>
          ))}
          {errs.includes('domain') ? <small className="field-error">{t('sec.domainError')}</small> : null}
          <button
            type="button"
            className="btn btn-small btn-icon-text"
            onClick={() => set({ domain_join: [...s.domain_join, { domain: '', provider_id: providers[0]?.id ?? '', role: 'viewer' }] })}
          >
            <Plus size={14} aria-hidden="true" />
            <span>{t('sec.addDomain')}</span>
          </button>
        </fieldset>

        <fieldset className="card" disabled={!writable}>
          <legend>{t('sec.sessions')}</legend>
          <Field label={t('sec.lifetime')} help={t('sec.lifetimeHelp')} error={errs.includes('lifetime') ? t('sec.lifetimeError') : undefined}>
            {(p) => (
              <input {...p} type="number" min={1} max={12} value={s.session_lifetime_hours} onChange={(e) => set({ session_lifetime_hours: Number(e.target.value) })} />
            )}
          </Field>
        </fieldset>
        {writable ? (
          <div className="form-actions">
            <button type="button" className="btn" disabled={!draft || busy} onClick={() => setDraft(null)}>
              {t('flow.discard')}
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? t('common.saving') : t('common.save')}
            </button>
          </div>
        ) : null}
      </form>
    </div>
  );
}
