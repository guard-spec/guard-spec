// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Admin actions of the organization (identity contract §5).

import { History } from 'lucide-react';
import { useCallback, useId, useState } from 'react';
import { Badge, DataTable, EmptyState, SearchBox, type Column, type Tone } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { formatTime, PageHeader, useDebounced } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { ActivityEntry } from '../types';

/** Action families of the filter (the action is "family.verb"). */
const FAMILIES = ['auth', 'member', 'invite', 'api_key', 'policy', 'upstream', 'security', 'mfa', 'identity_provider'];

export function actionTone(action: string): Tone {
  if (/fail|denied|refused|revoked|removed|deleted|reset/.test(action)) return 'danger';
  if (/created|added|enabled|success|login$/.test(action)) return 'ok';
  if (/changed|updated|role/.test(action)) return 'warn';
  return 'neutral';
}

function detailsText(d: ActivityEntry['details']): string {
  if (!d) return '';
  return Object.entries(d)
    .map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' · ');
}

export function ActivityLog({ fetcher, title, help }: { fetcher: (q: Record<string, string | number | undefined>) => Promise<unknown>; title: string; help: string }) {
  const { t } = useApp();
  const [actor, setActor] = useState('');
  const [family, setFamily] = useState('');
  const actorQ = useDebounced(actor);
  const familyId = useId();
  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => fetcher({ ...p, actor: actorQ || undefined, action: family || undefined }),
    [fetcher, actorQ, family],
  );
  const needle = actorQ.trim().toLowerCase();
  const paged = usePaged<ActivityEntry>(fetchPage, {
    clientFilter:
      needle || family ? (e) => (!needle || (e.actor?.email ?? '').toLowerCase().includes(needle)) && (!family || e.action.startsWith(family)) : undefined,
  });

  const columns: Column<ActivityEntry>[] = [
    { key: 'at', header: t('act.at'), className: 'nowrap', cell: (e) => formatTime(e.at) },
    { key: 'actor', header: t('act.actor'), cell: (e) => e.actor?.email ?? <span className="muted">{t('act.system')}</span> },
    {
      key: 'action',
      header: t('act.action'),
      cell: (e) => (
        <Badge tone={actionTone(e.action)}>
          <span className="mono">{e.action}</span>
        </Badge>
      ),
    },
    { key: 'target', header: t('act.target'), className: 'small', cell: (e) => e.target ?? '—' },
    { key: 'ip', header: t('act.ip'), className: 'mono small', cell: (e) => e.ip ?? '—' },
    { key: 'details', header: t('act.details'), className: 'small muted text-cell', cell: (e) => detailsText(e.details) || '—' },
  ];

  return (
    <div>
      <PageHeader title={title} help={help} />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(e) => e.id}
        testId="activity-table"
        feature={title}
        toolbar={
          <>
            <SearchBox value={actor} onChange={setActor} label={t('act.searchActor')} />
            <div className="field field-inline">
              <label htmlFor={familyId}>{t('act.filter')}</label>
              <select id={familyId} value={family} onChange={(e) => setFamily(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {FAMILIES.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={History} title={t('act.emptyTitle')} body={t('act.emptyBody')} />}
      />
    </div>
  );
}

export function ActivityPage() {
  const { api, t } = useApp();
  const { org } = useOrg();
  const fetcher = useCallback((q: Record<string, string | number | undefined>) => api.listActivity(org.id, q), [api, org.id]);
  return <ActivityLog fetcher={fetcher} title={t('act.title')} help={t('act.help')} />;
}
