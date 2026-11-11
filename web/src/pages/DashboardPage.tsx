// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Activity, Download, Gauge, ShieldAlert, Timer } from 'lucide-react';
import { useCallback, useId, useState, type ReactNode } from 'react';
import { EmptyState, Forbidden, NotAvailable } from '../components/DataTable';
import { downloadText, ErrorBanner, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink } from '../router';
import type { DashboardWindow } from '../types';
import { DASH_WINDOWS, reportFilename, share, volumeBars } from './dashboard';
import { formatShort } from '../dates';

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
  const { api, t, lang, notify } = useApp();
  const { org, projects } = useOrg();
  const [hover, setHover] = useState<number | null>(null);
  const [range, setRange] = useState<DashboardWindow>(DASH_WINDOWS[0] ?? '24h');
  const [project, setProject] = useState('');
  const projectId = useId();
  const stats = useLoad(
    useCallback(() => api.getDashboard(org.id, { window: range, project_id: project || undefined }), [api, org.id, range, project]),
  );
  const s = stats.data;
  const nf = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US');
  const pct = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US', { style: 'percent', maximumFractionDigits: 1 });
  const ms = (v: number | null) => (v !== null ? `${nf.format(Math.round(v))} ms` : '—');
  const { bars, max } = volumeBars(s ?? { series: [] });
  const time = (at: number) => formatShort(at);
  const windowName = t(`dash.window.${range}` as MessageKey);
  const [downloading, setDownloading] = useState(false);
  // The same window and project as the dashboard, per period, as a file.
  const downloadCsv = async () => {
    setDownloading(true);
    try {
      const csv = await api.getRequestsReportCsv(org.id, { window: range, project_id: project || undefined });
      downloadText(reportFilename(org.slug, range, new Date()), csv);
    } catch (e) {
      notify(errorText(e), 'error');
    } finally {
      setDownloading(false);
    }
  };

  const actions = (
    <>
      {projects.length > 0 ? (
        <div className="field field-inline">
          <label htmlFor={projectId}>{t('dash.project')}</label>
          <select id={projectId} value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">{t('dash.allProjects')}</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      <div className="segmented segmented-text" role="group" aria-label={t('dash.windowLabel')}>
        {DASH_WINDOWS.map((w) => (
          <button key={w} type="button" aria-pressed={range === w} title={t(`dash.window.${w}` as MessageKey)} onClick={() => setRange(w)}>
            {w}
          </button>
        ))}
      </div>
      <button type="button" className="btn btn-icon-text" disabled={downloading} title={t('dash.csvHelp')} onClick={() => void downloadCsv()}>
        <Download size={14} aria-hidden="true" />
        <span>{downloading ? t('dash.csvBusy') : t('dash.csv')}</span>
      </button>
    </>
  );

  return (
    <div>
      <PageHeader title={t('dash.title')} help={t('dash.help')} actions={actions} />
      {stats.notFound ? <NotAvailable feature={t('dash.title')} /> : stats.forbidden ? <Forbidden /> : <ErrorBanner error={stats.error} />}
      {stats.loading && !s ? <Loading /> : null}
      {s?.total === 0 ? (
        <div className="card">
          <EmptyState
            icon={Activity}
            title={t('dash.emptyTitle')}
            body={t('dash.emptyBody', { window: windowName })}
            action={
              <a className="btn" href={href('keys')} onClick={onLink('keys')}>
                {t('dash.createKey')}
              </a>
            }
          />
        </div>
      ) : null}
      {s && s.total > 0 ? (
        <>
          <p className="muted small" data-testid="dash-range">
            {t('dash.range', { window: windowName, bucket: t(s.bucket === 'day' ? 'dash.bucket.day' : 'dash.bucket.hour') })}
          </p>
          <div className="tiles">
            <Tile icon={<Activity size={16} aria-hidden="true" />} label={t('dash.requests')} value={nf.format(s.total)} />
            <Tile
              icon={<ShieldAlert size={16} aria-hidden="true" />}
              label={t('dash.blockRate')}
              value={pct.format(s.block_rate)}
              sub={t('dash.blocked', { count: nf.format(s.blocked) })}
            />
            <Tile icon={<Timer size={16} aria-hidden="true" />} label={t('dash.p50')} value={ms(s.latency_ms.p50)} />
            <Tile
              icon={<Gauge size={16} aria-hidden="true" />}
              label={t('dash.p99')}
              value={ms(s.latency_ms.p99)}
              sub={t('dash.p95', { value: ms(s.latency_ms.p95) })}
            />
          </div>
          <div className="dash-grid">
            <section className="card" aria-labelledby="vol-title">
              <h2 id="vol-title">{t('dash.volume')}</h2>
              {bars.length > 0 ? (
                <>
                  <div className="bars" role="img" aria-label={t('dash.volumeAria', { count: s.total })}>
                    {bars.map((b, i) => (
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
                    <span>{time(Date.parse(s.from))}</span>
                    <span>{hover !== null && bars[hover] ? `${time(bars[hover].start)} · ${bars[hover].count}` : ''}</span>
                    <span>{time(Date.parse(s.to))}</span>
                  </div>
                </>
              ) : null}
            </section>
            <section className="card" aria-labelledby="act-title">
              <h2 id="act-title">{t('dash.byAction')}</h2>
              <ul className="meter-list">
                {s.by_action.map((a) => (
                  <li key={a.action}>
                    <span className={`action action-${a.action}`}>{a.action}</span>
                    <span className="meter" aria-hidden="true">
                      <svg viewBox="0 0 100 6" preserveAspectRatio="none">
                        <rect width={share(a.count, s.total) * 100} height="6" rx="3" className={`meter-fill meter-${a.action}`} />
                      </svg>
                    </span>
                    <span className="meter-value">
                      {nf.format(a.count)} <span className="muted">({pct.format(share(a.count, s.total))})</span>
                    </span>
                  </li>
                ))}
              </ul>
              <h2 className="mt">{t('dash.topLabels')}</h2>
              {s.top_labels.length === 0 ? (
                <p className="muted">{t('dash.noLabels')}</p>
              ) : (
                <ol className="rank-list" data-testid="dash-labels">
                  {s.top_labels.map((l) => (
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
          <div className="dash-grid dash-grid-even">
            <section className="card" aria-labelledby="rules-title">
              <h2 id="rules-title">{t('dash.topRules')}</h2>
              {s.top_rules.length === 0 ? (
                <p className="muted">{t('dash.noRules')}</p>
              ) : (
                <ol className="rank-list" data-testid="dash-rules">
                  {s.top_rules.map((r) => (
                    <li key={r.rule_id}>
                      <span>
                        {r.rule ?? <span className="mono">{r.rule_id.slice(0, 8)}</span>}
                        <span className="muted"> · {r.policy ?? t('dash.deletedRule')}</span>
                      </span>
                      <span className="muted">{nf.format(r.count)}</span>
                    </li>
                  ))}
                </ol>
              )}
            </section>
            <section className="card" aria-labelledby="projects-title">
              <h2 id="projects-title">{t('dash.topProjects')}</h2>
              <ol className="rank-list" data-testid="dash-projects">
                {s.top_projects.map((p) => (
                  <li key={p.project_id ?? ''}>
                    <span className={p.project_id ? undefined : 'muted'}>{p.name ?? t('dash.noProject')}</span>
                    <span className="muted">
                      {nf.format(p.count)} · {t('dash.blocked', { count: nf.format(p.blocked) })}
                    </span>
                  </li>
                ))}
              </ol>
            </section>
          </div>
        </>
      ) : null}
    </div>
  );
}
