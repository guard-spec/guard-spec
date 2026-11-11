// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../api';
import { en } from '../i18n/en';
import { vi as viMessages } from '../i18n/vi';
import { reportFilename } from './dashboard';

describe('CSV report', () => {
  it('names the file after the org, window and day', () => {
    expect(reportFilename('Acme Corp', '7d', new Date('2026-11-11T10:00:00Z'))).toBe('guard-spec-acme-corp-7d-2026-11-11.csv');
  });

  it('asks the control plane for text, with the window and project', async () => {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const fetchImpl = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: input instanceof URL ? input.toString() : typeof input === 'string' ? input : input.url, headers: (init?.headers ?? {}) as Record<string, string> });
      return Promise.resolve(new Response('period_start,period_end,section,key,requests,blocked\n', { status: 200, headers: { 'Content-Type': 'text/csv' } }));
    });
    const api = new ApiClient({ getToken: () => 'tok', fetch: fetchImpl });
    const csv = await api.getRequestsReportCsv('org-1', { window: '7d', project_id: 'p1' });
    expect(csv.startsWith('period_start,')).toBe(true);
    expect(calls[0]?.url).toBe('/v1/organizations/org-1/reports/requests.csv?window=7d&project_id=p1');
    expect(calls[0]?.headers.Accept).toContain('text/');
  });

  it('has the download messages in both languages', () => {
    for (const key of ['dash.csv', 'dash.csvBusy', 'dash.csvHelp'] as const) expect(viMessages, key).toHaveProperty(key, expect.any(String));
    expect(en['dash.csv']).toBe('Download CSV');
  });
});
