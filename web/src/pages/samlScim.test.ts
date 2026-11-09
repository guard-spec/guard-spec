// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SAML providers, SAML sign-in errors, SCIM tokens and IdP group roles.

import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../api';
import { authErrorText, callbackErrorText, CODES } from '../auth/errors';
import { methodKey, methodLabel } from '../auth/methods';
import { translator } from '../i18n';
import { en } from '../i18n/en';
import { NAV } from '../nav';
import { PATHS, resolve } from '../router';
import { SAML_METADATA_MAX, type IdentityProviderInput } from '../types';
import { idpBody, samlEntityId, samlMetadataError, validAttrName, validateIdp } from './IdentityProvidersPage';
import { groupRolesBody, scimBaseUrl, tokenStatus, validateGroupRoles, validateTokenForm } from './ProvisioningPage';
import { groupRoleSource, ORG_FAMILIES } from './ActivityPage';
import { securityBody } from './SecurityPage';

const METADATA = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.acme.example/saml">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

const saml: IdentityProviderInput = {
  type: 'saml',
  display_name: 'Acme SSO',
  issuer: '',
  client_id: '',
  client_secret_env: '',
  scopes: [],
  allowed_domains: ['acme.example'],
  auto_provision: true,
  trust_email_for_linking: false,
  enabled: true,
  saml_metadata: METADATA,
  saml_allow_idp_initiated: false,
  saml_email_attribute: '',
  saml_name_attribute: '',
  saml_groups_attribute: 'groups',
};

describe('SAML providers', () => {
  it('needs metadata, not a client id or a secret variable', () => {
    expect(validateIdp(saml)).toEqual({});
    expect(validateIdp({ ...saml, display_name: ' ', saml_metadata: '' })).toEqual({ display_name: true, saml_metadata: true });
    expect(validateIdp({ ...saml, saml_groups_attribute: 'member of' })).toEqual({ saml_attributes: true });
  });

  it('recognizes IdP metadata, with or without a namespace prefix, up to 256 KiB', () => {
    expect(samlMetadataError(METADATA)).toBeNull();
    expect(samlMetadataError('<EntityDescriptor entityID="x"><IDPSSODescriptor/></EntityDescriptor>')).toBeNull();
    expect(samlMetadataError('  ')).toBe('required');
    expect(samlMetadataError('<html><body>login</body></html>')).toBe('notMetadata');
    // An SP's metadata is not an IdP's.
    expect(samlMetadataError('<md:EntityDescriptor entityID="x"><md:SPSSODescriptor/></md:EntityDescriptor>')).toBe('notMetadata');
    expect(samlMetadataError(METADATA + ' '.repeat(SAML_METADATA_MAX))).toBeNull(); // trimmed, as the control plane does
    expect(samlMetadataError(METADATA + '<!--' + 'x'.repeat(SAML_METADATA_MAX) + '-->')).toBe('tooLarge');
    // Bytes, not characters: 3 bytes each.
    expect(samlMetadataError(METADATA + '<!--' + 'ệ'.repeat(SAML_METADATA_MAX / 3) + '-->')).toBe('tooLarge');
  });

  it('previews the IdP entity id', () => {
    expect(samlEntityId(METADATA)).toBe('https://idp.acme.example/saml');
    expect(samlEntityId("<EntityDescriptor ID='a' entityID='urn:idp'>")).toBe('urn:idp');
    expect(samlEntityId('<EntityDescriptor>')).toBeNull();
  });

  it('accepts attribute names as the control plane does', () => {
    expect(validAttrName('')).toBe(true);
    expect(validAttrName('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')).toBe(true);
    expect(validAttrName('urn:oid:0.9.2342.19200300.100.1.3')).toBe(true);
    expect(validAttrName('a b')).toBe(false);
    expect(validAttrName('"x"')).toBe(false);
    expect(validAttrName('<x>')).toBe(false);
    expect(validAttrName('x'.repeat(257))).toBe(false);
  });

  it('sends a SAML body without client settings, and an OIDC body without SAML fields', () => {
    const body = idpBody({ ...saml, id: 'p1', saml_sp: { entity_id: 'e', acs_url: 'a', metadata_url: 'm' }, saml_groups_attribute: ' groups ', saml_metadata: `\n${METADATA}\n` });
    expect(body).not.toHaveProperty('id');
    expect(body).not.toHaveProperty('saml_sp');
    expect(body).toMatchObject({ type: 'saml', client_id: '', client_secret_env: '', scopes: [], saml_groups_attribute: 'groups', saml_metadata: METADATA, saml_allow_idp_initiated: false });
    const oidc = idpBody({ ...saml, type: 'oidc', issuer: 'https://login.acme.example', client_id: 'gs', client_secret_env: 'OIDC_SECRET_ACME', scopes: ['openid'] });
    expect(oidc).toMatchObject({ type: 'oidc', issuer: 'https://login.acme.example', client_id: 'gs', client_secret_env: 'OIDC_SECRET_ACME' });
    expect(Object.keys(oidc).filter((k) => k.startsWith('saml_'))).toEqual([]);
  });

  it('names saml:<id> login methods and starts SAML sign-in at /auth/saml', () => {
    const t = translator('en');
    const acme = { id: 'p1', type: 'saml' as const, display_name: 'Acme SSO' };
    const providers = [acme];
    expect(methodKey(acme)).toBe('saml:p1');
    expect(methodLabel('saml:p1', providers, t)).toBe('Acme SSO');
    expect(methodLabel('saml:gone', providers, t)).toBe('SSO');
    const api = new ApiClient({ getToken: () => null, fetch: vi.fn() });
    expect(api.loginStartUrl(acme, '/ui/')).toBe('/v1/auth/saml/p1/start?redirect=%2Fui%2F');
    expect(api.loginStartUrl({ id: 'google', type: 'google' }, '/ui/')).toBe('/v1/auth/oidc/google/start?redirect=%2Fui%2F');
    expect(api.loginStartUrl({ id: 'k', type: 'oidc' })).toBe('/v1/auth/oidc/k/start?redirect=%2Fui%2F');
  });

  it('explains the ACS refusals, and an expired assertion is not an expired 2FA step', () => {
    const t = translator('vi');
    for (const code of ['invalid_response', 'replayed', 'idp_initiated_disabled']) {
      expect(CODES[code], code).toBeDefined();
      expect(callbackErrorText(code, t)).toBe(t(CODES[code] ?? 'authErr.sso_unavailable'));
    }
    expect(callbackErrorText('expired', translator('en'))).toBe(en['authErr.assertion_expired']);
    expect(authErrorText('expired', translator('en'))).toBe(en['authErr.mfa_token_invalid']);
    expect(callbackErrorText('account_exists', translator('en'))).toBe(en['authErr.account_exists']);
    expect(callbackErrorText('something_new', translator('en'))).toBe('something_new');
  });
});

describe('org security: SCIM deactivation', () => {
  const s = { require_mfa: false, sso_satisfies_mfa: false, allowed_login_methods: null, domain_join: [], session_lifetime_hours: 12 };
  it('always sends scim_revoke_keys (the control plane turns an omitted value back on)', () => {
    expect(securityBody(s, false).scim_revoke_keys).toBe(true);
    expect(securityBody({ ...s, scim_revoke_keys: false }, false).scim_revoke_keys).toBe(false);
  });
});

describe('SCIM provisioning', () => {
  it('shows an absolute base URL', () => {
    expect(scimBaseUrl('https://gs.acme.example/v1/scim/v2', 'http://localhost:4173')).toBe('https://gs.acme.example/v1/scim/v2');
    expect(scimBaseUrl('/v1/scim/v2', 'http://localhost:4173')).toBe('http://localhost:4173/v1/scim/v2');
    expect(scimBaseUrl('', 'https://gs.example')).toBe('https://gs.example/v1/scim/v2');
  });

  it('tells active, expired and revoked tokens apart', () => {
    const now = Date.parse('2026-11-09T00:00:00Z');
    expect(tokenStatus({ revoked_at: null, expires_at: null }, now)).toBe('active');
    expect(tokenStatus({ revoked_at: null, expires_at: '2026-12-01T00:00:00Z' }, now)).toBe('active');
    expect(tokenStatus({ revoked_at: null, expires_at: '2026-11-01T00:00:00Z' }, now)).toBe('expired');
    expect(tokenStatus({ revoked_at: '2026-11-02T00:00:00Z', expires_at: '2026-11-01T00:00:00Z' }, now)).toBe('revoked');
  });

  it('checks the new token form', () => {
    const now = Date.parse('2026-11-09T00:00:00Z');
    expect(validateTokenForm({ name: 'Okta', expires: '' }, now)).toEqual([]);
    expect(validateTokenForm({ name: 'Okta', expires: '2027-01-01T00:00' }, now)).toEqual([]);
    expect(validateTokenForm({ name: '  ', expires: '2026-01-01T00:00' }, now)).toEqual(['name', 'expires']);
    expect(validateTokenForm({ name: 'x'.repeat(101), expires: 'nope' }, now)).toEqual(['name', 'expires']);
    // Characters, not UTF-16 units, as the control plane counts runes.
    expect(validateTokenForm({ name: 'ệ'.repeat(100), expires: '' }, now)).toEqual([]);
  });

  it('checks group mappings as PUT /group-roles does', () => {
    const r = validateGroupRoles([
      { provider_id: null, group_key: 'Engineering', role: 'member' },
      { provider_id: null, group_key: ' engineering ', role: 'admin' },
      { provider_id: 'p1', group_key: 'Engineering', role: 'admin' },
      { provider_id: null, group_key: '   ', role: 'viewer' },
      { provider_id: null, group_key: 'x'.repeat(257), role: 'viewer' },
    ]);
    expect(r).toEqual({ tooMany: false, rows: { 1: 'duplicate', 3: 'empty', 4: 'tooLong' } });
    const many = Array.from({ length: 101 }, (_, i) => ({ provider_id: null, group_key: `g${i}`, role: 'viewer' as const }));
    expect(validateGroupRoles(many).tooMany).toBe(true);
    expect(groupRolesBody([{ id: 'x', provider_id: '', group_key: ' Ops ', role: 'admin' }])).toEqual([{ provider_id: null, group_key: 'Ops', role: 'admin' }]);
  });

  it('reads the token list and sends group roles as {items}', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const answers = [
      { items: [{ id: 't1', name: 'Okta', prefix: 'gss_abcdefgh', created_at: '2026-11-01T00:00:00Z', last_used_at: null, expires_at: null, revoked_at: null }], base_url: '/v1/scim/v2', users: 3, groups: 1 },
      { items: [{ id: 'g1', provider_id: null, group_key: 'Ops', role: 'admin' }] },
    ];
    const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url, init: init ?? {} });
      return Promise.resolve(new Response(JSON.stringify(answers.shift()), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    });
    const api = new ApiClient({ getToken: () => 'tok', fetch: fetchFn });
    const list = await api.listScimTokens('o1');
    expect(list).toMatchObject({ base_url: '/v1/scim/v2', users: 3, groups: 1 });
    expect(list.items[0]?.prefix).toBe('gss_abcdefgh');
    expect(calls[0]?.url).toBe('/v1/organizations/o1/scim/tokens');
    const saved = await api.putGroupRoles('o1', [{ id: 'g1', provider_id: null, group_key: 'Ops', role: 'admin' }]);
    expect(saved).toHaveLength(1);
    expect(calls[1]?.init.method).toBe('PUT');
    expect(calls[1]?.url).toBe('/v1/organizations/o1/group-roles');
    expect(JSON.parse(typeof calls[1]?.init.body === 'string' ? calls[1].init.body : 'null')).toEqual({ items: [{ provider_id: null, group_key: 'Ops', role: 'admin' }] });
  });

  it('tells SAML and SCIM group roles apart in the activity log', () => {
    expect(groupRoleSource({ action: 'member.role_from_group', details: { from: 'member', to: 'admin', source: 'saml' } })).toBe('saml');
    expect(groupRoleSource({ action: 'member.role_from_group', details: { source: 'scim' } })).toBe('scim');
    expect(groupRoleSource({ action: 'member.role_changed', details: { source: 'saml' } })).toBeNull();
    expect(ORG_FAMILIES).toContain('scim');
  });

  it('has a page under Access, gated like the security policy', () => {
    expect(resolve(`/ui/${PATHS.provisioning}`, '', '', '/ui')).toEqual({ route: 'provisioning', redirect: null });
    const item = NAV.find((g) => g.id === 'access')?.items.find((i) => i.route === 'provisioning');
    expect(item?.capability).toBe('security.read');
  });
});
