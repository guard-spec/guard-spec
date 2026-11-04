// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Admin UI v2 (N16) against the identity contract (N15): sign-in with 2FA and
// SSO, members, model providers, security, account, pagination, and a
// control plane without the new endpoints.

import { chooseOrg, expect, go, login, openProfile, test } from './fixtures';
import { EMAIL, PASSWORD, RECOVERY_CODE, SSO_CODE, TOTP_CODE } from './mockApi';

async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/ui/');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test.describe('sign-in with two-factor authentication', () => {
  test.use({ mockOptions: { mfa: 'totp' } });

  test('asks for a code, refuses a wrong one, accepts a recovery code', async ({ page, mock }) => {
    await signIn(page);
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
    await page.getByLabel('Authentication code').fill('000000');
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByRole('alert')).toContainText('That code is not valid');
    await page.getByRole('button', { name: 'Use a recovery code' }).click();
    await page.getByLabel('Recovery code').fill(RECOVERY_CODE.toUpperCase());
    await page.getByRole('button', { name: 'Verify' }).click();
    await chooseOrg(page);
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
    const verify = mock.calls.filter((c) => c.path === '/auth/mfa/verify');
    expect(verify.at(-1)?.body).toMatchObject({ code: RECOVERY_CODE });
    // The mfa_token never lands in storage.
    expect(await page.evaluate(() => JSON.stringify([Object.entries(sessionStorage), Object.entries(localStorage)]))).not.toContain('mfa');
  });

  test('applies 2FA after an SSO callback, and removes the code from the address bar', async ({ page, mock }) => {
    await page.goto(`/ui/#/auth/callback?code=${SSO_CODE}`);
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
    await expect(page).not.toHaveURL(/code=/);
    expect(mock.calls.find((c) => c.path === '/auth/oidc/exchange')?.body).toEqual({ code: SSO_CODE });
    await page.getByLabel('Authentication code').fill(TOTP_CODE);
    await page.getByRole('button', { name: 'Verify' }).click();
    await chooseOrg(page);
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });
});

test.describe('forced 2FA enrollment', () => {
  test.use({ mockOptions: { mfa: 'enroll' } });

  test('draws the QR code locally, confirms, shows the recovery codes once', async ({ page }) => {
    await signIn(page);
    await expect(page.getByRole('heading', { name: 'Set up two-factor authentication' })).toBeVisible();
    await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
    await expect(page.getByTestId('totp-secret')).toContainText('JBSW Y3DP');
    await page.getByLabel('Authentication code').fill(TOTP_CODE);
    await page.getByRole('button', { name: 'Turn on two-factor authentication' }).click();
    await expect(page.getByTestId('recovery-codes').getByRole('listitem')).toHaveCount(10);
    await page.getByRole('button', { name: 'I saved them, continue' }).click();
    await chooseOrg(page);
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });
});

test('shows SSO buttons and reports a refused SSO sign-in', async ({ page }) => {
  await page.goto('/ui/');
  const sso = page.getByTestId('sso-buttons');
  await expect(sso.getByRole('link', { name: 'Continue with Google' })).toHaveAttribute('href', '/v1/auth/oidc/google/start?redirect=%2Fui%2F');
  await expect(sso.getByRole('link', { name: 'Continue with Okta' })).toBeVisible();
  await page.goto('/ui/#/auth/callback?error=account_exists');
  await expect(page.getByRole('alert')).toContainText('An account with this email already exists');
});

test.describe('members and invites', () => {
  test.use({ mockOptions: { rich: true } });

  test('pages through members, changes a role, resets 2FA and invites', async ({ page, mock }) => {
    await login(page, 'Members');
    const table = page.getByTestId('members-table');
    await expect(table.getByRole('row')).toHaveCount(26);
    await expect(page.getByText('1–25 of 38')).toBeVisible();
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('26–38 of 38')).toBeVisible();
    expect(mock.calls.some((c) => c.path.endsWith('/members') && c.method === 'GET')).toBe(true);
    await page.getByRole('button', { name: 'Previous' }).click();
    await page.getByLabel('Rows per page').selectOption('50');
    await expect(table.getByRole('row')).toHaveCount(39);

    await page.getByLabel('Search by name or email').fill('bình');
    await expect(table.getByRole('row')).toHaveCount(4);
    const target = mock.identity.members.find((m) => m.display_name === 'Bình Tran');
    await page.getByLabel(`Role of ${target?.email ?? ''}`).selectOption('admin');
    await page.getByRole('dialog').getByRole('button', { name: 'Change role' }).click();
    await expect(page.getByText(/is now Admin/)).toBeVisible();
    expect(target?.role).toBe('admin');

    await page.getByLabel('Search by name or email').fill('');
    const reset = page.getByRole('button', { name: `Reset 2FA: ${mock.identity.members[1]?.email ?? ''}` });
    await reset.click();
    await page.getByRole('dialog').getByRole('button', { name: 'Reset 2FA' }).click();
    await expect.poll(() => mock.identity.members[1]?.mfa_enabled).toBe(false);

    await page.getByRole('button', { name: 'Invite member' }).click();
    await page.getByRole('dialog').getByLabel('Email').fill('someone@acme.example');
    await page.getByRole('dialog').getByRole('button', { name: 'Send invite' }).click();
    await expect(page.getByTestId('invite-token')).toHaveText(/^inv_/);
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();
    await expect(page.getByTestId('invites-table')).toContainText('someone@acme.example');
  });
});

test('hides write actions from a viewer', async ({ page }) => {
  test.info().annotations.push({ type: 'note', description: 'role from GET /organizations' });
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  const { installMockApi, seedState } = await import('./mockApi');
  await installMockApi(page, seedState(), { role: 'viewer' });
  await login(page, 'Model providers');
  await expect(page.getByRole('button', { name: 'Add provider' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Edit provider main' })).toHaveCount(0);
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Members' })).toHaveCount(0);
  await expect(nav.getByRole('link', { name: 'Security' })).toHaveCount(0);
  await go(page, 'Roles and permissions');
  await expect(page.getByText('Your role')).toBeVisible();
});

test('adds a provider from the catalog, with allowed models and a connection test', async ({ page, mock }) => {
  await login(page, 'Model providers');
  await page.getByRole('button', { name: 'Test connection of main' }).click();
  await expect(page.getByTestId('test-result').first()).toContainText('Connected');
  await expect(page.getByTestId('test-result').first()).toContainText('212 ms');
  await expect(page.getByTestId('test-result').first()).toContainText('4 models found');

  await page.getByRole('button', { name: 'Add provider' }).click();
  await page.getByTestId('provider-catalog').getByRole('button', { name: /^Google Gemini/ }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('reached through its OpenAI-compatible endpoint')).toBeVisible();
  await expect(dialog.getByLabel('Base URL')).toHaveValue('https://generativelanguage.googleapis.com/v1beta/openai');
  await expect(dialog.getByLabel('API key environment variable')).toHaveValue('UPSTREAM_KEY_GEMINI');
  await dialog.getByRole('button', { name: '+ gemini-2.5-flash' }).click();
  await dialog.getByLabel('Allowed models').fill('gemini-2.5-pro');
  await dialog.getByLabel('Allowed models').press('Enter');
  await dialog.getByRole('button', { name: 'Add header' }).click();
  await dialog.getByLabel('Header 1 name').fill('Authorization');
  await dialog.getByLabel('Header 1 value').fill('Bearer abc');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByText('headers cannot carry secrets')).toBeVisible();
  await dialog.getByLabel('Header 1 name').fill('X-Team');
  await dialog.getByLabel('Header 1 value').fill('search');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/upstreams'));
  expect(post?.body).toMatchObject({
    name: 'google-gemini',
    provider: 'gemini',
    models: ['gemini-2.5-flash', 'gemini-2.5-pro'],
    default_model: 'gemini-2.5-flash',
    model: 'gemini-2.5-flash',
    headers: { 'X-Team': 'search' },
  });
  await expect(page.getByTestId('providers-table').getByText('google-gemini', { exact: true })).toBeVisible();
});

test('saves the security policy and manages identity providers without secrets', async ({ page, mock }) => {
  await login(page, 'Security');
  await expect(page.getByLabel('Require two-factor authentication')).toBeChecked();
  await page.getByLabel('SSO counts as two-factor').check();
  await page.getByRole('checkbox', { name: /Okta/ }).check();
  await page.getByLabel('Session lifetime (hours)').fill('8');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved.')).toBeVisible();
  expect(mock.identity.security).toMatchObject({ sso_satisfies_mfa: true, session_lifetime_hours: 8, allowed_login_methods: ['password', 'google', 'oidc:okta'] });

  await go(page, 'Identity providers');
  await page.getByRole('button', { name: 'Add OIDC provider' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('input[type=password]')).toHaveCount(0);
  await dialog.getByLabel('Display name').fill('Keycloak');
  await dialog.getByLabel('Issuer URL').fill('https://sso.acme.example/realms/main');
  await dialog.getByLabel('Client ID').fill('guard-spec');
  await dialog.getByLabel('Client secret variable').fill('not-a-var');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByText('Must look like OIDC_SECRET_NAME')).toBeVisible();
  await dialog.getByLabel('Client secret variable').fill('oidc_secret_keycloak');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  expect(mock.identity.idps.at(-1)).toMatchObject({ type: 'oidc', client_secret_env: 'OIDC_SECRET_KEYCLOAK' });
});

test('my account: password, 2FA required by the org, recovery codes, sessions', async ({ page, mock }) => {
  await login(page, null);
  await openProfile(page);
  await page.getByRole('link', { name: 'My account' }).click();
  await expect(page.getByRole('heading', { name: 'My account', level: 1 })).toBeVisible();
  await page.getByLabel('Current password').fill(PASSWORD);
  await page.getByLabel('New password', { exact: true }).fill('short');
  await page.getByLabel('Confirm new password').fill('short');
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page.getByText('Use at least 12 characters.')).toBeVisible();

  await page.getByRole('button', { name: 'Turn off 2FA' }).click();
  await page.getByRole('dialog').getByLabel('Code or recovery code').fill(TOTP_CODE);
  await page.getByRole('dialog').getByRole('button', { name: 'Turn off 2FA' }).click();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText('requires two-factor authentication');
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('button', { name: 'New recovery codes' }).click();
  await page.getByRole('dialog').getByLabel('Code or recovery code').fill(TOTP_CODE);
  await page.getByRole('dialog').getByRole('button', { name: 'New recovery codes' }).click();
  await expect(page.getByTestId('recovery-codes').getByRole('listitem')).toHaveCount(10);

  const sessions = page.getByTestId('sessions-table');
  await expect(sessions).toContainText('This session');
  await sessions.getByRole('button', { name: 'Sign out' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Sign out' }).click();
  await expect.poll(() => mock.identity.sessions.length).toBe(1);
  await expect(page.getByText('Linked as ada@acme.example')).toBeVisible();
});

test.describe('control plane without the identity API (main before N15)', () => {
  test.use({ mockOptions: { noIdentity: true } });

  test('degrades gracefully and still pages older lists', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page.getByTestId('sso-buttons')).toHaveCount(0);
    await login(page, 'Members');
    await expect(page.getByText('Not available on this control plane')).toBeVisible();
    await go(page, 'Activity log');
    await expect(page.getByText('Not available on this control plane')).toBeVisible();
    await go(page, 'Security');
    await expect(page.getByText('Not available on this control plane')).toBeVisible();
    await go(page, 'Roles and permissions');
    await expect(page.getByText('showing the built-in one')).toBeVisible();
    // {data} lists page in the browser.
    await go(page, 'API keys');
    await expect(page.getByText('1–3 of 3')).toBeVisible();
    await go(page, 'Model providers');
    await expect(page.getByText('built-in presets', { exact: false })).toHaveCount(0);
    await page.getByRole('button', { name: 'Test connection of main' }).click();
    await expect(page.getByText('Not available on this control plane')).toBeVisible();
    // No /auth/me: the instance admin group stays hidden.
    await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Users' })).toHaveCount(0);
  });
});

test('redirects the old addresses', async ({ page }) => {
  await login(page, null);
  await page.goto('/ui/upstreams');
  await expect(page.getByRole('heading', { name: 'Model providers', level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/providers$/);
  await page.goto('/ui/audit');
  await expect(page.getByRole('heading', { name: 'Request log', level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/requests$/);
  await page.goto('/ui/#/flow');
  await expect(page.getByRole('heading', { name: 'Policy flow', level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/flow$/);
  // Back from linking a provider (N15: #/auth/callback?linked=<id>).
  await page.goto('/ui/#/auth/callback?linked=google');
  await expect(page.getByText('Identity linked.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'My account', level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/account$/);
});

test.describe('mobile', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('opens the sidebar as a drawer and closes it with Escape', async ({ page }) => {
    await login(page, null);
    const nav = page.getByRole('navigation', { name: 'Main' });
    await expect(nav).toBeHidden();
    await page.getByRole('button', { name: 'Open menu' }).click();
    await expect(nav).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(nav).toBeHidden();
    await expect(page.getByRole('button', { name: 'Open menu' })).toBeFocused();
    await page.getByRole('button', { name: 'Open menu' }).click();
    await nav.getByRole('link', { name: 'Request log' }).click();
    await expect(page.getByRole('heading', { name: 'Request log', level: 1 })).toBeVisible();
    await expect(nav).toBeHidden();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
});
