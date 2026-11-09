// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SCIM 2.0 provisioning of the organization (migration 025): the base URL
// and bearer tokens a directory (Okta, Entra ID, …) uses, and the mappings
// of IdP groups to org roles, for SCIM groups and for the groups a SAML
// assertion lists. Admins read; owners create and revoke tokens and change
// the mappings. What a deactivation revokes is on the Security page.

import { Plus, Trash2, UserCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { isNotFound } from '../api';
import { authErrorText } from '../auth/errors';
import { Badge, EmptyState, Forbidden, NotAvailable } from '../components/DataTable';
import { ConfirmDialog, CopyButton, Day, Dialog, ErrorBanner, Field, Loading, PageHeader, RelativeTime, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink } from '../router';
import { GROUP_ROLE_VALUES, type CreatedScimToken, type GroupRole, type GroupRoleValue, type LoginProvider, type ScimToken } from '../types';

/** The control plane's limits (cmd/control-plane/scim.go). */
export const MAX_GROUP_ROLES = 100;
export const MAX_GROUP_KEY = 256;
export const MAX_TOKEN_NAME = 100;

/** The SCIM base URL as the directory needs it: absolute (the control plane sends a path when PUBLIC_BASE_URL is not set). */
export function scimBaseUrl(base: string, origin: string): string {
  if (!base) return `${origin}/v1/scim/v2`;
  return base.startsWith('/') ? `${origin}${base}` : base;
}

export type TokenStatus = 'active' | 'expired' | 'revoked';

export function tokenStatus(tok: Pick<ScimToken, 'revoked_at' | 'expires_at'>, now = Date.now()): TokenStatus {
  if (tok.revoked_at) return 'revoked';
  if (tok.expires_at && Date.parse(tok.expires_at) <= now) return 'expired';
  return 'active';
}

export type TokenFormError = 'name' | 'expires';

/** The new token form: a name of 1 to 100 characters, an expiry in the future (optional). */
export function validateTokenForm(f: { name: string; expires: string }, now = Date.now()): TokenFormError[] {
  const errs: TokenFormError[] = [];
  const name = f.name.trim();
  if (!name || Array.from(name).length > MAX_TOKEN_NAME) errs.push('name');
  if (f.expires) {
    const at = Date.parse(f.expires);
    if (Number.isNaN(at) || at <= now) errs.push('expires');
  }
  return errs;
}

export type GroupRoleProblem = 'empty' | 'tooLong' | 'duplicate';

/** As putGroupRoles: a group of 1 to 256 characters, listed once per source (case-insensitive). */
export function validateGroupRoles(rows: readonly GroupRole[]): { tooMany: boolean; rows: Record<number, GroupRoleProblem> } {
  const out: Record<number, GroupRoleProblem> = {};
  const seen = new Set<string>();
  rows.forEach((r, i) => {
    const key = r.group_key.trim();
    if (!key) out[i] = 'empty';
    else if (key.length > MAX_GROUP_KEY) out[i] = 'tooLong';
    else {
      const k = `${r.provider_id ?? ''}/${key.toLowerCase()}`;
      if (seen.has(k)) out[i] = 'duplicate';
      seen.add(k);
    }
  });
  return { tooMany: rows.length > MAX_GROUP_ROLES, rows: out };
}

/** The PUT body's items: trimmed group names. */
export function groupRolesBody(rows: readonly GroupRole[]): GroupRole[] {
  return rows.map((r) => ({ provider_id: r.provider_id === '' ? null : r.provider_id, group_key: r.group_key.trim(), role: r.role }));
}

const SCIM_SOURCE = '';

export default function ProvisioningPage() {
  const { api, t } = useApp();
  const { org, can } = useOrg();
  const tokens = useLoad(useCallback(() => api.listScimTokens(org.id), [api, org.id]));

  if (tokens.loading && !tokens.data) return <Loading />;
  if (tokens.error && !tokens.data) {
    return (
      <div className="narrow">
        <PageHeader title={t('scim.title')} help={t('scim.help')} />
        {tokens.notFound ? <NotAvailable feature={t('scim.title')} /> : tokens.forbidden ? <Forbidden /> : <ErrorBanner error={tokens.error} />}
      </div>
    );
  }
  const writable = can('security.write');
  return (
    <div className="narrow">
      <PageHeader title={t('scim.title')} help={t('scim.help')} />
      {!writable ? <div className="banner banner-info">{t('scim.readOnly')}</div> : null}
      {tokens.data ? <ScimTokens list={tokens.data} writable={writable} reload={tokens.reload} /> : null}
      <GroupRoles writable={writable} />
      <section className="card" aria-labelledby="scim-deprov">
        <h2 id="scim-deprov">{t('scim.deprovTitle')}</h2>
        <p className="muted small">
          {t('scim.deprovHelp')}{' '}
          <a href={href('security')} onClick={onLink('security')}>
            {t('scim.deprovLink')}
          </a>
        </p>
      </section>
    </div>
  );
}

function ScimTokens({ list, writable, reload }: { list: { items: ScimToken[]; base_url: string; users: number; groups: number }; writable: boolean; reload: () => Promise<void> }) {
  const { api, t, notify } = useApp();
  const { org } = useOrg();
  const [form, setForm] = useState<{ name: string; expires: string } | null>(null);
  const [touched, setTouched] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedScimToken | null>(null);
  const [revoking, setRevoking] = useState<ScimToken | null>(null);
  const base = scimBaseUrl(list.base_url, typeof window === 'undefined' ? '' : window.location.origin);
  const errs = form && touched ? validateTokenForm(form) : [];

  const create = async () => {
    if (!form) return;
    setTouched(true);
    if (validateTokenForm(form).length > 0) return;
    setBusy(true);
    setFormError(null);
    try {
      const input: { name: string; expires_at?: string } = { name: form.name.trim() };
      if (form.expires) input.expires_at = new Date(form.expires).toISOString();
      const r = await api.createScimToken(org.id, input);
      setForm(null);
      setCreated(r);
      await reload();
    } catch (e) {
      setFormError(authErrorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  const statusTone = { active: 'ok', expired: 'warn', revoked: 'off' } as const;
  return (
    <section className="card" aria-labelledby="scim-conn">
      <div className="section-head">
        <h2 id="scim-conn">{t('scim.connection')}</h2>
        {writable ? (
          <button
            type="button"
            className="btn btn-primary btn-small btn-icon-text"
            onClick={() => {
              setTouched(false);
              setFormError(null);
              setForm({ name: '', expires: '' });
            }}
          >
            <Plus size={14} aria-hidden="true" />
            <span>{t('scim.newToken')}</span>
          </button>
        ) : null}
      </div>
      <p className="muted small">{t('scim.connectionHelp')}</p>
      <Field label={t('scim.baseUrl')}>
        {(p) => (
          <div className="secret-row">
            <input {...p} className="mono" readOnly value={base} data-testid="scim-base-url" />
            <CopyButton text={base} label={t('scim.baseUrl')} />
          </div>
        )}
      </Field>
      <div className="scim-stats muted small" data-testid="scim-stats">
        <span>{t('scim.usersCount', { n: list.users })}</span>
        <span>{t('scim.groupsCount', { n: list.groups })}</span>
      </div>

      <h3>{t('scim.tokens')}</h3>
      {list.items.length === 0 ? (
        <EmptyState icon={UserCheck} title={t('scim.noTokens')} body={t('scim.noTokensBody')} />
      ) : (
        <div className="table-wrap">
          <table data-testid="scim-tokens-table">
            <caption className="sr-only">{t('scim.tokens')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('common.name')}</th>
                <th scope="col">{t('keys.prefix')}</th>
                <th scope="col" className="col-wide-only">
                  {t('common.created')}
                </th>
                <th scope="col">{t('scim.lastUsed')}</th>
                <th scope="col">{t('keys.expires')}</th>
                <th scope="col">{t('keys.status')}</th>
                <th scope="col" className="row-actions">
                  <span className="sr-only">{t('common.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((k) => {
                const st = tokenStatus(k);
                return (
                  <tr key={k.id} className={st === 'active' ? undefined : 'row-muted'}>
                    <td>
                      <span className="ellipsis" title={k.name}>
                        {k.name}
                      </span>
                    </td>
                    <td className="mono">{`${k.prefix}…`}</td>
                    <td className="nowrap small col-wide-only">
                      <Day value={k.created_at} />
                    </td>
                    <td className="nowrap small">{k.last_used_at ? <RelativeTime value={k.last_used_at} /> : <span className="muted">{t('scim.neverUsed')}</span>}</td>
                    <td className="nowrap small">{k.expires_at ? <Day value={k.expires_at} /> : t('keys.never')}</td>
                    <td>
                      <Badge tone={statusTone[st]}>{t(`scim.status.${st}` as MessageKey)}</Badge>
                    </td>
                    <td className="row-actions">
                      {writable && st !== 'revoked' ? (
                        <button type="button" className="btn btn-small btn-danger" aria-label={`${t('keys.revoke')}: ${k.name}`} onClick={() => setRevoking(k)}>
                          {t('keys.revoke')}
                        </button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <Dialog
        open={form !== null}
        title={t('scim.newToken')}
        onClose={() => setForm(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setForm(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void create()}>
              {t('common.create')}
            </button>
          </>
        }
      >
        <ErrorBanner error={formError} />
        {form ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void create();
            }}
          >
            <Field label={t('scim.tokenName')} help={t('scim.tokenNameHelp')} error={errs.includes('name') ? t('scim.tokenNameError') : undefined}>
              {(p) => <input {...p} maxLength={MAX_TOKEN_NAME + 20} autoComplete="off" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />}
            </Field>
            <Field label={t('keys.expires')} help={t('scim.expiresHelp')} error={errs.includes('expires') ? t('scim.expiresError') : undefined}>
              {(p) => <input {...p} type="datetime-local" value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })} />}
            </Field>
            <button type="submit" hidden />
          </form>
        ) : null}
      </Dialog>

      <Dialog
        open={created !== null}
        title={t('scim.tokenCreatedTitle')}
        onClose={() => setCreated(null)}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => setCreated(null)}>
            {t('common.close')}
          </button>
        }
      >
        <p className="banner banner-warn" role="note">
          {t('scim.tokenCreatedWarn')}
        </p>
        <div className="secret-row">
          <code className="secret" data-testid="new-scim-token">
            {created?.token}
          </code>
          {created ? <CopyButton text={created.token} label={t('scim.tokenLabel')} /> : null}
        </div>
        <p className="muted small">{t('scim.tokenCreatedHelp', { url: base })}</p>
      </Dialog>

      <ConfirmDialog
        open={revoking !== null}
        title={t('keys.revoke')}
        body={t('scim.confirmRevoke', { name: revoking?.name ?? '' })}
        confirmLabel={t('keys.revoke')}
        danger
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await api.revokeScimToken(org.id, revoking.id);
            notify(t('scim.revoked', { name: revoking.name }));
            await reload();
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setRevoking(null);
        }}
      />
    </section>
  );
}

function GroupRoles({ writable }: { writable: boolean }) {
  const { api, t, notify } = useApp();
  const { org } = useOrg();
  const loaded = useLoad(useCallback(() => api.getGroupRoles(org.id), [api, org.id]));
  const [draft, setDraft] = useState<GroupRole[] | null>(null);
  const [providers, setProviders] = useState<LoginProvider[]>([]);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    api.listLoginProviders().then(
      (ps) => setProviders(ps.filter((p) => p.type === 'saml')),
      () => setProviders([]),
    );
  }, [api]);

  const rows = draft ?? loaded.data ?? [];
  const check = validateGroupRoles(rows);
  const problems = touched ? check.rows : {};
  const setRow = (i: number, patch: Partial<GroupRole>) => setDraft(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  // Mappings of a provider that is disabled or gone stay listed by id.
  const sources = [...providers.map((p) => ({ id: p.id, label: p.display_name }))];
  for (const r of rows) if (r.provider_id && !sources.some((s) => s.id === r.provider_id)) sources.push({ id: r.provider_id, label: t('scim.unknownProvider', { id: r.provider_id.slice(0, 8) }) });

  const save = async () => {
    setTouched(true);
    const c = validateGroupRoles(rows);
    if (c.tooMany || Object.keys(c.rows).length > 0) return;
    setBusy(true);
    setSaveError(null);
    try {
      await api.putGroupRoles(org.id, groupRolesBody(rows));
      setDraft(null);
      setTouched(false);
      await loaded.reload();
      notify(t('common.saved'));
    } catch (e) {
      setSaveError(isNotFound(e) ? t('na.title') : authErrorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  const problemText: Record<GroupRoleProblem, MessageKey> = { empty: 'scim.groupEmpty', tooLong: 'scim.groupTooLong', duplicate: 'scim.groupDuplicate' };
  return (
    <section className="card" aria-labelledby="scim-groups">
      <h2 id="scim-groups">{t('scim.groupRoles')}</h2>
      <p className="muted small">{t('scim.groupRolesHelp')}</p>
      {loaded.loading && !loaded.data ? <Loading /> : null}
      {loaded.error && !loaded.data ? loaded.notFound ? <NotAvailable feature={t('scim.groupRoles')} compact /> : <ErrorBanner error={loaded.error} /> : null}
      <ErrorBanner error={saveError} />
      {loaded.data ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <fieldset className="plain-fieldset" disabled={!writable} data-testid="group-roles">
            <legend className="sr-only">{t('scim.groupRoles')}</legend>
            {rows.length === 0 ? <p className="muted">{t('scim.noGroupRoles')}</p> : null}
            {rows.map((r, i) => {
              const n = i + 1;
              const problem = problems[i];
              const errId = `group-role-${i}-err`;
              return (
                <div key={i}>
                  <div className="kv-row kv-row-3">
                    <select aria-label={t('scim.source', { n })} value={r.provider_id ?? SCIM_SOURCE} onChange={(e) => setRow(i, { provider_id: e.target.value === SCIM_SOURCE ? null : e.target.value })}>
                      <option value={SCIM_SOURCE}>{t('scim.sourceScim')}</option>
                      {sources.map((s) => (
                        <option key={s.id} value={s.id}>
                          {t('scim.sourceSaml', { name: s.label })}
                        </option>
                      ))}
                    </select>
                    <input
                      aria-label={t('scim.group', { n })}
                      aria-invalid={problem ? true : undefined}
                      aria-describedby={problem ? errId : undefined}
                      placeholder={t('scim.groupPlaceholder')}
                      value={r.group_key}
                      onChange={(e) => setRow(i, { group_key: e.target.value })}
                    />
                    <select aria-label={t('scim.role', { n })} value={r.role} onChange={(e) => setRow(i, { role: e.target.value as GroupRoleValue })}>
                      {GROUP_ROLE_VALUES.map((role) => (
                        <option key={role} value={role}>
                          {t(`org.role.${role}` as MessageKey)}
                        </option>
                      ))}
                    </select>
                    <button type="button" className="btn-icon" aria-label={t('scim.removeMapping', { n })} onClick={() => setDraft(rows.filter((_, j) => j !== i))}>
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  </div>
                  {problem ? (
                    <small id={errId} className="field-error">
                      {t(problemText[problem])}
                    </small>
                  ) : null}
                </div>
              );
            })}
            {touched && check.tooMany ? <small className="field-error">{t('scim.tooManyMappings', { n: MAX_GROUP_ROLES })}</small> : null}
            <button
              type="button"
              className="btn btn-small btn-icon-text"
              onClick={() => setDraft([...rows, { provider_id: null, group_key: '', role: 'member' }])}
            >
              <Plus size={14} aria-hidden="true" />
              <span>{t('scim.addMapping')}</span>
            </button>
          </fieldset>
          {writable ? (
            <div className="form-actions">
              <button
                type="button"
                className="btn"
                disabled={!draft || busy}
                onClick={() => {
                  setDraft(null);
                  setTouched(false);
                }}
              >
                {t('flow.discard')}
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy || !draft}>
                {busy ? t('common.saving') : t('scim.saveMappings')}
              </button>
            </div>
          ) : null}
        </form>
      ) : null}
    </section>
  );
}
