// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Activity, Gauge, ShieldAlert, Timer } from 'lucide-react';
import { useCallback, useMemo, useState, type ReactNode } from 'react';
import { listOf } from '../api';
import { EmptyState } from '../components/DataTable';
import { ErrorBanner, Loading, PageHeader, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import { normalizePage } from '../paging';
import { href, onLink } from '../router';
import type { AuditRow } from '../types';
import { computeStats } from './dashboard';

/** Rows the dashboard samples: at most this many pages of 200. */
const SAMPLE_PAGES = 5;

function Tile({ icon, label, value, sub }: { icon: ReactNode; label: string; value: string; sub?: string }) {
  return (
    <div className="card tile">
      <div className="tile-head muted">
        {icon}
        <span>{label}</span>
      </div>
      <div className="tile-value">{value}</div>
      {sub ? <div className="muted small">{sub}</div> : null}
    </div>
  );
}

export function DashboardPage() {
  const { api, t, lang } = useApp();
  const { org } = useOrg();
  const [hover, setHover] = useState<number | null>(null);
  const sample = useLoad(
    useCallback(async () => {
      const rows: AuditRow[] = [];
      let cursor: string | null = null;
      for (let i = 0; i < SAMPLE_PAGES; i++) {
        const raw = await api.listRequestsPage(org.id, cursor ? { limit: 200, cursor } : { limit: 200 });
        const page = normalizePage<AuditRow>(raw);
        rows.push(...(page.items.length ? page.items : listOf<AuditRow>(raw)));
        if (!page.nextCursor) break;
        cursor = page.nextCursor;
      }
      return rows;
    }, [api, org.id]),
  );
  const stats = useMemo(() => computeStats(sample.data ?? []), [sample.data]);
  const nf = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US');
  const pct = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US', { style: 'percent', maximumFractionDigits: 1 });
  const max = Math.max(1, ...stats.volume.map((b) => b.count));
  const time = (ms: number) => new Date(ms).toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  return (
    <div>
      <PageHeader title={t('dash.title')} help={t('dash.help')} />
      <ErrorBanner error={sample.error} />
      {sample.loading && !sample.data ? <Loading /> : null}
      {sample.data?.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={Activity}
            title={t('dash.emptyTitle')}
            body={t('dash.emptyBody')}
            action={
              <a className="btn" href={href('keys')} onClick={onLink('keys')}>
                {t('dash.createKey')}
              </a>
            }
          />
        </div>
      ) : null}
      {sample.data && sample.data.length > 0 ? (
        <>
          <p className="muted small" data-testid="dash-sample">
            {t('dash.sample', { count: nf.format(stats.count) })}
          </p>
          <div className="tiles">
            <Tile icon={<Activity size={16} aria-hidden="true" />} label={t('dash.requests')} value={nf.format(stats.count)} />
            <Tile
              icon={<ShieldAlert size={16} aria-hidden="true" />}
              label={t('dash.blockRate')}
              value={pct.format(stats.blockRate)}
              sub={t('dash.blocked', { count: nf.format(stats.blocked) })}
            />
            <Tile icon={<Timer size={16} aria-hidden="true" />} label={t('dash.p50')} value={stats.p50 !== null ? `${nf.format(stats.p50)} ms` : '—'} />
            <Tile icon={<Gauge size={16} aria-hidden="true" />} label={t('dash.p99')} value={stats.p99 !== null ? `${nf.format(stats.p99)} ms` : '—'} />
          </div>
          <div className="dash-grid">
            <section className="card" aria-labelledby="vol-title">
              <h2 id="vol-title">{t('dash.volume')}</h2>
              {stats.volume.length > 0 ? (
                <>
                  <div className="bars" role="img" aria-label={t('dash.volumeAria', { count: stats.count })}>
                    {stats.volume.map((b, i) => (
                      <div
                        key={b.start}
                        className="bar-slot"
                        onPointerEnter={() => setHover(i)}
                        onPointerLeave={() => setHover(null)}
                        title={`${time(b.start)}: ${b.count}`}
                      >
                        <svg className="bar-svg" viewBox="0 0 10 100" preserveAspectRatio="none" aria-hidden="true">
                          <rect x="1" width="8" y={100 - (b.count / max) * 100} height={(b.count / max) * 100} rx="1.5" className={hover === i ? 'bar bar-hover' : 'bar'} />
                        </svg>
                      </div>
                    ))}
                  </div>
                  <div className="bars-axis muted small">
                    <span>{stats.from !== null ? time(stats.from) : ''}</span>
                    <span>{hover !== null && stats.volume[hover] ? `${time(stats.volume[hover].start)} · ${stats.volume[hover].count}` : ''}</span>
                    <span>{stats.to !== null ? time(stats.to) : ''}</span>
                  </div>
                </>
              ) : null}
            </section>
            <section className="card" aria-labelledby="act-title">
              <h2 id="act-title">{t('dash.byAction')}</h2>
              <ul className="meter-list">
                {stats.byAction.map((a) => (
                  <li key={a.action}>
                    <span className={`action action-${a.action}`}>{a.action}</span>
                    <span className="meter" aria-hidden="true">
                      <svg viewBox="0 0 100 6" preserveAspectRatio="none">
                        <rect width={(a.count / stats.count) * 100} height="6" rx="3" className={`meter-fill meter-${a.action}`} />
                      </svg>
                    </span>
                    <span className="meter-value">
                      {nf.format(a.count)} <span className="muted">({pct.format(a.count / stats.count)})</span>
                    </span>
                  </li>
                ))}
              </ul>
              <h2 className="mt">{t('dash.topLabels')}</h2>
              {stats.topLabels.length === 0 ? (
                <p className="muted">{t('dash.noLabels')}</p>
              ) : (
                <ol className="rank-list">
                  {stats.topLabels.map((l) => (
                    <li key={l.label}>
                      <span className="mono">{l.label}</span>
                      <span className="muted">{nf.format(l.count)}</span>
                    </li>
                  ))}
                </ol>
              )}
              <a className="btn btn-link" href={href('requests')} onClick={onLink('requests')}>
                {t('dash.openLog')}
              </a>
            </section>
          </div>
        </>
      ) : null}
    </div>
  );
}
