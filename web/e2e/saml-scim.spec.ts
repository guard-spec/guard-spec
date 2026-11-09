// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SAML SSO and SCIM provisioning (RF-39437a0f) against the mocked API: the
// SAML provider form, SAML sign-in buttons and ACS errors, SAML login
// methods and the SCIM deactivation switch of the security policy, SCIM
// tokens and the IdP group to role editor.
//   SHOTS_DIR=/some/dir also saves screenshots of the new views.

import type { Page } from '@playwright/test';
import { expect, go, login, test } from './fixtures';
import { installMockApi, SAML_METADATA, samlProvider, seedState } from './mockApi';

async function shot(page: Page, name: string) {
  if (!process.env.SHOTS_DIR) return;
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${process.env.SHOTS_DIR.replace(/\/$/, '')}/${name}.png`, animations: 'disabled' });
}

test.describe('SAML provider form', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

  test('adds a SAML provider from its metadata file and shows the values for the IdP', async ({ page, mock }) => {
    await login(page, 'Identity providers');
    await page.getByRole('button', { name: 'Add SAML provider' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Add SAML provider' })).toBeVisible();
    // No client settings, and nothing that could hold a secret.
    await expect(dialog.getByLabel('Client ID')).toHaveCount(0);
    await expect(dialog.locator('input[type=password]')).toHaveCount(0);
    await expect(dialog.getByText('shown after saving')).toBeVisible();

    await dialog.getByLabel('Display name', { exact: true }).fill('Acme SSO');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByText('Paste the identity provider’s metadata XML.')).toBeVisible();
    await dialog.getByLabel('IdP metadata XML').fill('<html><body>login</body></html>');
    await expect(dialog.getByText('This is not SAML IdP metadata')).toBeVisible();
    await expect(dialog.getByLabel('IdP metadata XML')).toHaveAttribute('aria-invalid', 'true');

    await dialog.getByTestId('saml-metadata-file').setInputFiles({ name: 'idp-metadata.xml', mimeType: 'application/xml', buffer: Buffer.from(SAML_METADATA) });
    await expect(dialog.getByLabel('IdP metadata XML')).toHaveValue(/IDPSSODescriptor/);
    await expect(dialog.getByText('This is not SAML IdP metadata')).toHaveCount(0);
    await expect(dialog.getByTestId('saml-entity-preview')).toContainText('https://idp.acme.example/saml/metadata');

    await dialog.getByLabel('Email attribute').fill('e mail');
    await dialog.getByLabel('Groups attribute').fill('memberOf');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByText('Attribute names cannot contain spaces')).toBeVisible();
    await dialog.getByLabel('Email attribute').fill('mail');

    // IdP-initiated sign-in is off by default, and turning it on warns.
    const idpInitiated = dialog.getByLabel('Accept IdP-initiated sign-in');
    await expect(idpInitiated).not.toBeChecked();
    await expect(dialog.getByTestId('idp-initiated-warning')).toHaveCount(0);
    await idpInitiated.check();
    await expect(dialog.getByTestId('idp-initiated-warning')).toContainText('login CSRF');
    await shot(page, 'saml-form');
    await idpInitiated.uncheck();
    await expect(dialog.getByTestId('idp-initiated-warning')).toHaveCount(0);
    await dialog.getByLabel('Allowed domains').fill('acme.example');
    await dialog.getByLabel('Allowed domains').press('Enter');
    await dialog.getByRole('button', { name: 'Save' }).click();

    const saved = page.getByRole('dialog');
    await expect(saved.getByRole('heading', { name: 'Acme SSO is saved' })).toBeVisible();
    const created = mock.identity.idps.at(-1);
    const sp = saved.getByTestId('saml-sp');
    await expect(sp).toContainText(`/v1/auth/saml/${created?.id ?? ''}/metadata`);
    await expect(sp).toContainText(`/v1/auth/saml/${created?.id ?? ''}/acs`);
    await saved.getByRole('button', { name: 'Copy: ACS URL (HTTP-POST)' }).click();
    await expect(saved.getByRole('button', { name: 'Copied: ACS URL (HTTP-POST)' })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(created?.saml_sp?.acs_url);
    await shot(page, 'saml-saved');

    const post = mock.calls.find((c) => c.method === 'POST' && c.path === '/admin/identity-providers');
    expect(post?.body).toMatchObject({
      type: 'saml',
      display_name: 'Acme SSO',
      client_id: '',
      client_secret_env: '',
      scopes: [],
      allowed_domains: ['acme.example'],
      saml_allow_idp_initiated: false,
      saml_email_attribute: 'mail',
      saml_groups_attribute: 'memberOf',
      saml_name_attribute: '',
    });
    expect((post?.body as { saml_metadata?: string }).saml_metadata).toBe(SAML_METADATA.trim());

    await saved.getByRole('button', { name: 'Close' }).last().click();
    const row = page.getByTestId('idp-table').getByRole('row').filter({ hasText: 'Acme SSO' });
    await expect(row).toContainText('SAML');
    await expect(row).toContainText('https://idp.acme.example/saml/metadata');

    // Editing keeps the type and shows the values again.
    await page.getByRole('button', { name: 'Edit: Acme SSO' }).click();
    await expect(page.getByRole('dialog').getByLabel('Type')).toBeDisabled();
    await expect(page.getByRole('dialog').getByTestId('saml-sp')).toContainText('/acs');
    await page.getByRole('dialog').getByLabel('Accept IdP-initiated sign-in').check();
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(row).toContainText('IdP-initiated');
    const put = mock.calls.filter((c) => c.method === 'PUT' && c.path.startsWith('/admin/identity-providers/')).at(-1);
    expect(put?.body).toMatchObject({ type: 'saml', saml_allow_idp_initiated: true });
    expect(put?.body).not.toHaveProperty('saml_sp');
  });
});

test('signs in with a SAML provider and explains the ACS refusals', async ({ page, mock }) => {
  mock.identity.idps.push(samlProvider('saml-acme', 'Acme SSO'));
  await page.goto('/ui/');
  const sso = page.getByTestId('sso-buttons');
  await expect(sso.getByRole('link', { name: 'Continue with Acme SSO' })).toHaveAttribute('href', '/v1/auth/saml/saml-acme/start?redirect=%2Fui%2F');
  await expect(sso.getByRole('link', { name: 'Continue with Google' })).toHaveAttribute('href', '/v1/auth/oidc/google/start?redirect=%2Fui%2F');
  const cases: [string, string][] = [
    ['replayed', 'already used'],
    ['expired', 'out of its validity period'],
    ['idp_initiated_disabled', 'Start from the Guard Spec sign-in page'],
    ['invalid_response', 'SAML response was refused'],
  ];
  for (const [code, text] of cases) {
    // Each ACS redirect is a new page load.
    await page.goto('about:blank');
    await page.goto(`/ui/#/auth/callback?error=${code}`);
    await expect(page.getByRole('alert')).toContainText(text);
  }
});

test('links a SAML identity from My account and names SAML sign-ins of members', async ({ page, mock }) => {
  mock.identity.idps.push(samlProvider('saml-acme', 'Acme SSO'));
  const member = mock.identity.members[1];
  if (member) member.login_methods = ['saml:saml-acme'];
  await login(page, 'Members');
  const row = page.getByTestId('members-table').getByRole('row').filter({ hasText: member?.email ?? '' });
  await expect(row).toContainText('Acme SSO');
  await expect(row).not.toContainText('saml:');

  await page.goto('/ui/account');
  const acme = page.getByRole('listitem').filter({ hasText: 'Acme SSO' });
  await expect(acme).toContainText('Not linked');
  await acme.getByRole('button', { name: 'Link' }).click();
  await expect(page.getByText('Acme SSO is linked.')).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/account$/);
  await expect(acme).toContainText('Linked as ada@idp.acme.example');
  expect(mock.calls.some((c) => c.method === 'POST' && c.path === '/auth/identities/saml-acme/link/start')).toBe(true);
  expect(mock.calls.find((c) => c.path === '/auth/identities/link/complete')?.body).toEqual({ code: 'mock-link-saml-acme' });
});

test('lists SAML login methods and saves the SCIM deactivation switch', async ({ page, mock }) => {
  mock.identity.idps.push(samlProvider('saml-acme', 'Acme SSO'));
  await login(page, 'Security');
  await page.getByRole('radio', { name: 'Only the methods below' }).check();
  const methods = page.getByTestId('login-methods');
  await expect(methods).toContainText('saml:saml-acme');
  await expect(methods.getByRole('checkbox', { name: /Acme SSO/ })).toBeChecked();
  const revoke = page.getByLabel('Revoke their API keys on deactivation');
  await expect(revoke).toBeChecked();
  await revoke.uncheck();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved.')).toBeVisible();
  const put = mock.calls.filter((c) => c.method === 'PUT' && c.path.endsWith('/security')).at(-1);
  expect(put?.body).toMatchObject({ scim_revoke_keys: false });
  expect((put?.body as { allowed_login_methods?: string[] }).allowed_login_methods).toContain('saml:saml-acme');
  expect(mock.identity.security.scim_revoke_keys).toBe(false);
  await page.getByRole('link', { name: 'SCIM provisioning page.' }).click();
  await expect(page.getByRole('heading', { name: 'SCIM provisioning', level: 1 })).toBeVisible();
});

test.describe('SCIM tokens', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

  test('shows the base URL, creates a token once and revokes one', async ({ page, mock }) => {
    await login(page, 'SCIM provisioning');
    await expect(page.getByTestId('scim-base-url')).toHaveValue('http://localhost:4173/v1/scim/v2');
    await expect(page.getByTestId('scim-stats')).toContainText('Provisioned users: 12');
    const table = page.getByTestId('scim-tokens-table');
    await expect(table.getByRole('row')).toHaveCount(3);
    const old = table.getByRole('row').filter({ hasText: 'Old connector' });
    await expect(old).toContainText('Revoked');
    await expect(old.getByRole('button')).toHaveCount(0);
    await expect(table.getByRole('row').filter({ hasText: 'Okta production' })).toContainText('gss_q8Zt3kLm…');
    await shot(page, 'scim-page');

    await page.getByRole('button', { name: 'New token' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog.getByText('Enter a name of 1 to 100 characters.')).toBeVisible();
    expect(mock.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/scim/tokens'))).toHaveLength(0);
    await dialog.getByLabel('Name').fill('Entra ID');
    await dialog.getByRole('button', { name: 'Create' }).click();

    const shown = page.getByRole('dialog');
    await expect(shown.getByRole('heading', { name: 'Your new SCIM token' })).toBeVisible();
    await expect(shown.getByRole('note')).toContainText('shown only once');
    const secret = shown.getByTestId('new-scim-token');
    await expect(secret).toHaveText(/^gss_[0-9a-f]{32}$/);
    const token = (await secret.textContent()) ?? '';
    await shown.getByRole('button', { name: 'Copy: SCIM token' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(token);
    await shot(page, 'scim-token-created');
    expect(mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/scim/tokens'))?.body).toEqual({ name: 'Entra ID' });
    await shown.getByRole('button', { name: 'Close' }).last().click();
    await expect(table.getByRole('row').filter({ hasText: 'Entra ID' })).toContainText('Never used');
    // The token itself is not on the page any more.
    await expect(page.getByText(token)).toHaveCount(0);

    await table.getByRole('button', { name: 'Revoke: Okta production' }).click();
    const confirm = page.getByRole('dialog');
    await expect(confirm).toContainText('can no longer provision');
    await confirm.getByRole('button', { name: 'Revoke' }).click();
    await expect(table.getByRole('row').filter({ hasText: 'Okta production' })).toContainText('Revoked');
    expect(mock.calls.some((c) => c.method === 'DELETE' && c.path.endsWith('/scim/tokens/scim-1'))).toBe(true);
    expect(mock.identity.scimTokens.find((x) => x.id === 'scim-1')?.revoked_at).not.toBeNull();
  });
});

test('maps SCIM and SAML groups to roles', async ({ page, mock }) => {
  mock.identity.idps.push(samlProvider('saml-acme', 'Acme SSO'));
  await login(page, 'SCIM provisioning');
  const editor = page.getByTestId('group-roles');
  await expect(editor.getByLabel('Group of mapping 1')).toHaveValue('Guard Spec Admins');
  await expect(editor.getByLabel('Source of mapping 1')).toHaveValue('');
  await expect(editor.getByLabel('Role of mapping 1')).toHaveValue('admin');
  // The roles a mapping can give: never owner.
  await expect(editor.getByLabel('Role of mapping 1').locator('option')).toHaveText(['Viewer', 'Member', 'Admin']);
  const save = page.getByRole('button', { name: 'Save group roles' });
  await expect(save).toBeDisabled();

  await editor.getByRole('button', { name: 'Add mapping' }).click();
  await save.click();
  await expect(editor.getByText('Enter a group name.')).toBeVisible();
  await expect(editor.getByLabel('Group of mapping 2')).toHaveAttribute('aria-invalid', 'true');
  await editor.getByLabel('Group of mapping 2').fill('guard spec admins');
  await save.click();
  await expect(editor.getByText('This group is already mapped for this source.')).toBeVisible();
  // The same name from a SAML provider is another group.
  await editor.getByLabel('Source of mapping 2').selectOption({ label: 'SAML: Acme SSO' });
  await editor.getByLabel('Role of mapping 2').selectOption('viewer');
  await editor.getByRole('button', { name: 'Add mapping' }).click();
  await editor.getByLabel('Group of mapping 3').fill('  Engineering ');
  await shot(page, 'group-roles');
  await save.click();
  await expect(page.getByText('Saved.')).toBeVisible();
  const put = mock.calls.filter((c) => c.method === 'PUT' && c.path.endsWith('/group-roles')).at(-1);
  expect(put?.body).toEqual({
    items: [
      { provider_id: null, group_key: 'Guard Spec Admins', role: 'admin' },
      { provider_id: 'saml-acme', group_key: 'guard spec admins', role: 'viewer' },
      { provider_id: null, group_key: 'Engineering', role: 'member' },
    ],
  });
  await expect(save).toBeDisabled();

  await editor.getByRole('button', { name: 'Remove mapping 1' }).click();
  await save.click();
  await expect.poll(() => mock.identity.groupRoles.map((g) => g.group_key)).toEqual(['guard spec admins', 'Engineering']);
});

test('an admin reads SCIM provisioning but only an owner changes it', async ({ page }) => {
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await installMockApi(page, seedState(), { role: 'admin' });
  await login(page, 'SCIM provisioning');
  await expect(page.getByText('Only an owner can create tokens and change group roles.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'New token' })).toHaveCount(0);
  await expect(page.getByTestId('scim-tokens-table').getByRole('button')).toHaveCount(0);
  await expect(page.getByTestId('group-roles').getByLabel('Group of mapping 1')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save group roles' })).toHaveCount(0);
});

test('hides SCIM provisioning from a viewer', async ({ page }) => {
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await installMockApi(page, seedState(), { role: 'viewer' });
  await login(page, null);
  await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'SCIM provisioning' })).toHaveCount(0);
  await page.goto('/ui/provisioning');
  await expect(page.getByText('You don’t have permission')).toBeVisible();
});

test.describe('control plane without SCIM', () => {
  test.use({ mockOptions: { noIdentity: true } });

  test('says the page is not available', async ({ page }) => {
    await login(page, null);
    await go(page, 'SCIM provisioning');
    await expect(page.getByText('Not available on this control plane')).toBeVisible();
  });
});
