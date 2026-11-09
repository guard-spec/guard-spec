// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SSO providers of the instance (identity contract §2): Google as a preset,
// any OpenID Connect provider and SAML 2.0. The client secret stays in the
// control plane's environment; the UI only names the variable
// (client_secret_env). A SAML provider is its IdP metadata: the control plane
// takes the entity id, SSO URL and signing certificates from it, and answers
// with the values the IdP needs (saml_sp).

import { Building2, Fingerprint, Pencil, Plus, Trash2, Upload } from 'lucide-react';
import { useCallback, useRef, useState } from 'react';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, InstanceAdminOnly, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, PageHeader, Toggle } from '../components/ui';
import { authErrorText } from '../auth/errors';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import {
  CLIENT_SECRET_ENV_RE,
  GOOGLE_ISSUER,
  SAML_METADATA_MAX,
  type IdentityProvider,
  type IdentityProviderInput,
  type IdentityProviderType,
  type SamlSpInfo,
} from '../types';

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

const SAML: IdentityProviderInput = {
  type: 'saml',
  display_name: '',
  issuer: '',
  client_id: '',
  client_secret_env: '',
  scopes: [],
  allowed_domains: [],
  auto_provision: false,
  trust_email_for_linking: false,
  enabled: true,
  saml_metadata: '',
  saml_allow_idp_initiated: false,
  saml_email_attribute: '',
  saml_name_attribute: '',
  saml_groups_attribute: '',
};

const PRESETS: Record<IdentityProviderType, IdentityProviderInput> = { google: GOOGLE, oidc: OIDC, saml: SAML };
const TYPE_LABEL: Record<IdentityProviderType, string> = { google: 'Google', oidc: 'OIDC', saml: 'SAML' };

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

/** As validAttrName of the control plane: empty, or up to 256 characters without whitespace, quotes or angle brackets. */
export function validAttrName(s: string | undefined): boolean {
  const v = (s ?? '').trim();
  return v === '' || (v.length <= 256 && !/[\s"<>]/.test(v));
}

/** Bytes of a string as UTF-8 (the control plane counts bytes). */
function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

export type SamlMetadataProblem = 'required' | 'tooLarge' | 'notMetadata';

/** Whether saml_metadata looks like IdP metadata (an EntityDescriptor with an IDPSSODescriptor); the control plane checks the rest. */
export function samlMetadataError(raw: string | undefined): SamlMetadataProblem | null {
  const v = (raw ?? '').trim();
  if (!v) return 'required';
  if (byteLength(v) > SAML_METADATA_MAX) return 'tooLarge';
  if (!/<([\w-]+:)?EntityDescriptor[\s/>]/.test(v) || !/<([\w-]+:)?IDPSSODescriptor[\s/>]/.test(v)) return 'notMetadata';
  return null;
}

/** The entityID of IdP metadata, shown before saving (the control plane reads it). */
export function samlEntityId(raw: string | undefined): string | null {
  const m = /<([\w-]+:)?EntityDescriptor\b[^>]*?\bentityID\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(raw ?? '');
  const id = (m?.[2] ?? m?.[3] ?? '').trim();
  return id || null;
}

type IdpField = 'display_name' | 'issuer' | 'client_id' | 'client_secret_env' | 'saml_metadata' | 'saml_attributes';

export function validateIdp(v: IdentityProviderInput): Partial<Record<IdpField, true>> {
  const e: Partial<Record<IdpField, true>> = {};
  if (!v.display_name.trim()) e.display_name = true;
  if (v.type === 'saml') {
    if (samlMetadataError(v.saml_metadata)) e.saml_metadata = true;
    if (![v.saml_email_attribute, v.saml_name_attribute, v.saml_groups_attribute].every(validAttrName)) e.saml_attributes = true;
    return e;
  }
  if (!validIssuer(v.issuer)) e.issuer = true;
  if (!v.client_id.trim()) e.client_id = true;
  if (!CLIENT_SECRET_ENV_RE.test(v.client_secret_env)) e.client_secret_env = true;
  return e;
}

/** The POST/PUT body: a SAML provider carries no client settings (the issuer comes from its metadata), an OIDC one no SAML fields. */
export function idpBody(v: IdentityProviderInput & { id?: string; saml_sp?: SamlSpInfo }): IdentityProviderInput {
  const common = {
    type: v.type,
    display_name: v.display_name.trim(),
    allowed_domains: v.allowed_domains,
    auto_provision: v.auto_provision,
    trust_email_for_linking: v.trust_email_for_linking === true,
    enabled: v.enabled,
  };
  if (v.type === 'saml') {
    return {
      ...common,
      issuer: '',
      client_id: '',
      client_secret_env: '',
      scopes: [],
      saml_metadata: (v.saml_metadata ?? '').trim(),
      saml_allow_idp_initiated: v.saml_allow_idp_initiated === true,
      saml_email_attribute: (v.saml_email_attribute ?? '').trim(),
      saml_name_attribute: (v.saml_name_attribute ?? '').trim(),
      saml_groups_attribute: (v.saml_groups_attribute ?? '').trim(),
    };
  }
  return { ...common, issuer: v.issuer, client_id: v.client_id, client_secret_env: v.client_secret_env, scopes: v.scopes };
}

/** The values to enter at the SAML identity provider, each with a copy button. */
function SamlSpValues({ sp }: { sp: SamlSpInfo }) {
  const { t } = useApp();
  const rows: [MessageKey, string][] = [
    ['idp.samlEntityId', sp.entity_id],
    ['idp.samlAcsUrl', sp.acs_url],
    ['idp.samlMetadataUrl', sp.metadata_url],
  ];
  return (
    <dl className="sp-values" data-testid="saml-sp">
      {rows.map(([label, value]) => (
        <div key={label} className="sp-value">
          <dt>{t(label)}</dt>
          <dd className="secret-row">
            <code className="secret">{value}</code>
            <CopyButton text={value} label={t(label)} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

export default function IdentityProvidersPage() {
  const { api, t, notify, me } = useApp();
  const [draft, setDraft] = useState<{ id: string | null; value: IdentityProviderInput & { saml_sp?: SamlSpInfo } } | null>(null);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<IdentityProvider | null>(null);
  // A SAML provider just created: the values its IdP needs.
  const [savedSaml, setSavedSaml] = useState<IdentityProvider | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
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
    setFileError(null);
    setDraft({ id: null, value: { ...preset, scopes: [...preset.scopes], allowed_domains: [] } });
  };
  const changeType = (type: IdentityProviderType) => {
    if (!draft) return;
    const v = draft.value;
    const preset = PRESETS[type];
    setDraft({
      ...draft,
      value: {
        ...preset,
        scopes: [...preset.scopes],
        display_name: v.display_name || preset.display_name,
        allowed_domains: v.allowed_domains,
        auto_provision: v.auto_provision,
        trust_email_for_linking: v.trust_email_for_linking,
        enabled: v.enabled,
      },
    });
  };
  const readMetadataFile = async (file: File | undefined) => {
    setFileError(null);
    if (!file) return;
    if (file.size > SAML_METADATA_MAX) {
      setFileError(t('idp.samlMetadataError.tooLarge'));
      return;
    }
    set({ saml_metadata: await file.text() });
  };
  const save = async () => {
    setTouched(true);
    if (!draft || Object.keys(errs).length > 0) return;
    setError(null);
    try {
      const body = idpBody(draft.value);
      if (draft.id) {
        await api.updateIdentityProvider(draft.id, body);
      } else {
        const created = await api.createIdentityProvider(body);
        if (created.type === 'saml') setSavedSaml(created);
      }
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
    { key: 'type', header: t('idp.type'), cell: (p) => <Badge tone={p.type === 'google' ? 'accent' : 'neutral'}>{TYPE_LABEL[p.type]}</Badge> },
    {
      key: 'client',
      header: t('idp.clientId'),
      className: 'col-env col-wide-only',
      cell: (p) =>
        p.type === 'saml' ? (
          <span className="muted">—</span>
        ) : (
          <span className="mono small ellipsis" title={p.client_id}>
            {p.client_id}
          </span>
        ),
    },
    {
      key: 'secret',
      header: t('idp.secretEnv'),
      className: 'col-env',
      cell: (p) =>
        p.type === 'saml' ? (
          <span className="muted">—</span>
        ) : (
          <span className="mono small ellipsis" title={`$${p.client_secret_env}`}>{`$${p.client_secret_env}`}</span>
        ),
    },
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
          {p.type === 'saml' && p.saml_allow_idp_initiated ? <Badge tone="warn">{t('idp.samlIdpInitiatedShort')}</Badge> : null}
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
              setFileError(null);
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
  const sp = v?.saml_sp;
  const entityId = v?.type === 'saml' ? samlEntityId(v.saml_metadata) : null;
  const metadataProblem = v?.type === 'saml' ? samlMetadataError(v.saml_metadata) : null;
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
            <button type="button" className="btn btn-icon-text" onClick={() => openNew(SAML)}>
              <Building2 size={16} aria-hidden="true" />
              <span>{t('idp.addSaml')}</span>
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
        title={draft?.id ? t('idp.edit', { name: draft.value.display_name }) : v?.type === 'google' ? t('idp.addGoogle') : v?.type === 'saml' ? t('idp.addSaml') : t('idp.addOidc')}
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
            {v.type === 'saml' ? (
              <div className="banner banner-info">
                <div>
                  <strong>{t('idp.samlSpTitle')}</strong>
                  {sp ? <SamlSpValues sp={sp} /> : <small>{draft.id ? t('idp.samlNoPublicUrl') : t('idp.samlSpAfterSave')}</small>}
                </div>
              </div>
            ) : (
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
            )}
            <div className="form-grid">
              <Field label={t('prov.displayName')} error={touched && errs.display_name ? t('idp.required') : undefined}>
                {(p) => <input {...p} value={v.display_name} onChange={(e) => set({ display_name: e.target.value })} required />}
              </Field>
              <Field label={t('idp.type')} help={draft.id ? t('idp.typeFixed') : undefined}>
                {(p) => (
                  // The control plane keeps a provider's type: SAML and OIDC settings differ.
                  <select {...p} value={v.type} disabled={draft.id !== null} onChange={(e) => changeType(e.target.value as IdentityProviderType)}>
                    <option value="google">Google</option>
                    <option value="oidc">OpenID Connect</option>
                    <option value="saml">SAML 2.0</option>
                  </select>
                )}
              </Field>
            </div>
            {v.type === 'saml' ? (
              <>
                <Field
                  label={t('idp.samlMetadata')}
                  help={t('idp.samlMetadataHelp')}
                  error={touched && metadataProblem ? t(`idp.samlMetadataError.${metadataProblem}` as MessageKey) : undefined}
                >
                  {(p) => (
                    <textarea
                      {...p}
                      className="mono saml-metadata"
                      rows={8}
                      spellCheck={false}
                      placeholder={'<md:EntityDescriptor entityID="https://idp.example.com/saml">…</md:EntityDescriptor>'}
                      value={v.saml_metadata ?? ''}
                      onChange={(e) => set({ saml_metadata: e.target.value })}
                    />
                  )}
                </Field>
                <div className="inline-actions">
                  <input
                    ref={fileRef}
                    type="file"
                    accept=".xml,application/xml,text/xml,application/samlmetadata+xml"
                    hidden
                    aria-label={t('idp.samlUpload')}
                    data-testid="saml-metadata-file"
                    onChange={(e) => {
                      void readMetadataFile(e.target.files?.[0]);
                      e.target.value = '';
                    }}
                  />
                  <button type="button" className="btn btn-small btn-icon-text" onClick={() => fileRef.current?.click()}>
                    <Upload size={14} aria-hidden="true" />
                    <span>{t('idp.samlUpload')}</span>
                  </button>
                  {entityId ? (
                    <small className="muted" data-testid="saml-entity-preview">
                      {t('idp.samlEntityPreview')} <code className="mono">{entityId}</code>
                    </small>
                  ) : null}
                </div>
                {fileError ? (
                  <small className="field-error" role="alert">
                    {fileError}
                  </small>
                ) : null}
                <fieldset>
                  <legend>{t('idp.samlAttributes')}</legend>
                  <p className="muted small">{t('idp.samlAttributesHelp')}</p>
                  <div className="form-grid form-grid-3">
                    <Field label={t('idp.samlEmailAttr')}>
                      {(p) => (
                        <input {...p} className="mono" autoComplete="off" spellCheck={false} placeholder="email" value={v.saml_email_attribute ?? ''} onChange={(e) => set({ saml_email_attribute: e.target.value })} />
                      )}
                    </Field>
                    <Field label={t('idp.samlNameAttr')}>
                      {(p) => (
                        <input {...p} className="mono" autoComplete="off" spellCheck={false} placeholder="displayName" value={v.saml_name_attribute ?? ''} onChange={(e) => set({ saml_name_attribute: e.target.value })} />
                      )}
                    </Field>
                    <Field label={t('idp.samlGroupsAttr')} help={t('idp.samlGroupsAttrHelp')}>
                      {(p) => (
                        <input {...p} className="mono" autoComplete="off" spellCheck={false} placeholder="groups" value={v.saml_groups_attribute ?? ''} onChange={(e) => set({ saml_groups_attribute: e.target.value })} />
                      )}
                    </Field>
                  </div>
                  {touched && errs.saml_attributes ? <small className="field-error">{t('idp.samlAttrError')}</small> : null}
                </fieldset>
                <Toggle
                  label={t('idp.samlIdpInitiated')}
                  help={t('idp.samlIdpInitiatedHelp')}
                  checked={v.saml_allow_idp_initiated === true}
                  onChange={(x) => set({ saml_allow_idp_initiated: x })}
                />
                {v.saml_allow_idp_initiated ? (
                  <div className="banner banner-warn" role="note" data-testid="idp-initiated-warning">
                    {t('idp.samlIdpInitiatedWarn')}
                  </div>
                ) : null}
              </>
            ) : (
              <>
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
              </>
            )}
            <ChipsInput
              label={t('idp.domains')}
              help={v.type === 'google' ? t('idp.domainsHelpGoogle') : v.type === 'saml' ? t('idp.domainsHelpSaml') : t('idp.domainsHelp')}
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
      <Dialog
        open={savedSaml !== null}
        wide
        title={t('idp.samlSavedTitle', { name: savedSaml?.display_name ?? '' })}
        onClose={() => setSavedSaml(null)}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => setSavedSaml(null)}>
            {t('common.close')}
          </button>
        }
      >
        <p>{t('idp.samlSavedHelp')}</p>
        {savedSaml?.saml_sp ? <SamlSpValues sp={savedSaml.saml_sp} /> : <div className="banner banner-warn">{t('idp.samlNoPublicUrl')}</div>}
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
