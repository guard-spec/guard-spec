// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Custom backends (RF-d6ba510e): an organization's own JSON API as a
// provider of kind "custom", with its paths, methods and scanned fields.

import AxeBuilder from '@axe-core/playwright';
import { expect, login, test } from './fixtures';

test('adds a custom backend, refusing an unsupported JSONPath', async ({ page, mock }) => {
  await login(page, 'Model providers');
  await page.getByRole('button', { name: 'Add provider' }).click();
  await page.getByTestId('provider-catalog').getByRole('button', { name: /^Custom backend/ }).click();
  const dialog = page.getByRole('dialog');
  const fields = dialog.getByTestId('backend-fields');
  await expect(fields).toBeVisible();
  // No models and no retries for a business API.
  await expect(dialog.getByLabel('Allowed models')).toHaveCount(0);
  await expect(dialog.getByLabel('Retries')).toHaveCount(0);

  await dialog.getByLabel('Name', { exact: true }).fill('search');
  await dialog.getByLabel('Base URL').fill('https://search.internal.example/api');
  await expect(fields).toContainText('/v1/backend/search/{path}');
  await fields.getByLabel('Allowed path prefixes').fill('/search\nadmin');
  await fields.getByRole('checkbox', { name: 'GET' }).check();
  await fields.getByLabel('Request fields to scan (JSONPath)').fill('$.query\n$..filters');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(fields.getByText('admin: a prefix starts with /')).toBeVisible();
  await expect(fields.getByText('$..filters: recursive descent (..) is not supported')).toBeVisible();
  expect(mock.calls.some((c) => c.method === 'POST' && c.path.endsWith('/upstreams'))).toBe(false);
  // The form, with its errors shown, has no serious accessibility violation.
  const axe = await new AxeBuilder({ page }).include('dialog[open]').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(axe.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);

  await fields.getByLabel('Allowed path prefixes').fill('/search');
  await fields.getByLabel('Request fields to scan (JSONPath)').fill('$.query\n$.filters[*]\n');
  await fields.getByLabel('Response fields to guard (JSONPath)').fill('$.results[*].snippet');
  await fields.getByLabel('Key header').fill('X-Api-Key');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();

  const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/upstreams'));
  expect(post?.body).toMatchObject({
    name: 'search',
    provider: 'custom',
    base_url: 'https://search.internal.example/api',
    models: [],
    default_model: '',
    retries: 0,
    max_tokens_cap: null,
    backend: {
      path_prefixes: ['/search'],
      methods: ['GET', 'POST'],
      key_header: 'X-Api-Key',
      scan: { request: ['$.query', '$.filters[*]'], response: ['$.results[*].snippet'], all_strings: false, raw_text: false },
    },
  });

  // Listed with its gateway route, without a model connection test, and
  // never offered as a default upstream.
  const table = page.getByTestId('providers-table');
  await expect(table.getByText('/v1/backend/search/…')).toBeVisible();
  await expect(table.getByText('1 path prefixes')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Test connection of search' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Test connection of main' })).toBeVisible();
  await expect(page.getByLabel('Organization default').locator('option', { hasText: 'search' })).toHaveCount(0);
});

test('requires a scanned field unless every string is scanned', async ({ page, mock }) => {
  await login(page, 'Model providers');
  await page.getByRole('button', { name: 'Add provider' }).click();
  await page.getByTestId('provider-catalog').getByRole('button', { name: /^Custom backend/ }).click();
  const dialog = page.getByRole('dialog');
  const fields = dialog.getByTestId('backend-fields');
  await dialog.getByLabel('Name', { exact: true }).fill('notes');
  await dialog.getByLabel('Base URL').fill('https://notes.example');
  await fields.getByLabel('Request fields to scan (JSONPath)').fill('');
  await fields.getByRole('checkbox', { name: 'POST' }).uncheck();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(fields.getByText('List at least one request field to scan')).toBeVisible();
  await expect(fields.getByText('Choose at least one method.')).toBeVisible();

  await fields.getByRole('checkbox', { name: 'PUT' }).check();
  await fields.getByRole('checkbox', { name: 'Scan every string of a side that lists no field' }).check();
  await fields.getByRole('checkbox', { name: 'Accept text bodies (not JSON) and scan them whole' }).check();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/upstreams'));
  expect(post?.body).toMatchObject({
    provider: 'custom',
    backend: { path_prefixes: ['/'], methods: ['PUT'], scan: { request: [], all_strings: true, raw_text: true } },
  });
});
