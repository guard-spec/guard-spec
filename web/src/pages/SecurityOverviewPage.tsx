// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The security overview (RF-a1dbafea U4): the attack trend (refused requests
// per period), the most attacked API keys and projects, the top detections,
// the health of the detection models and the running versions. The numbers
// come from the dashboard aggregates and GET /gateway/models.

import { Cpu, Download, Info, ShieldAlert, TrendingUp } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Badge, Forbidden, NotAvailable } from '../components/DataTable';
import { downloadText, ErrorBanner, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import { formatShort } from '../dates';
import type { MessageKey } from '../i18n';
import { href, onLink } from '../router';
import type { DashboardWindow, GatewayModels } from '../types';
import { DASH_WINDOWS, reportFilename } from './dashboard';
import { attackBars, modelHealth } from './securityOverview';
import { layerNames } from './start';

function ModelHealthCard({ gw }: { gw: GatewayModels | undefined }) {
  const { t } = useApp();
  const health = modelHealth(gw);
  return (
    <section className="card" aria-labelledby="health-title" data-testid="model-health">
      <h2 id="health-title">
        <Cpu size={16} aria-hidden="true" /> {t('secov.health')}
      </h2>
      <p>
        <Badge tone={health === 'ok' ? 'ok' : health === 'degraded' ? 'warn' : 'danger'}>{t(`secov.health.${health}` as MessageKey)}</Badge>
      </p>
      {gw?.reachable ? (
        <dl className="kv">
          <dt>{t('secov.layers')}</dt>
          <dd>{gw.layers?.length ? layerNames(gw.layers) : '—'}</dd>
          <dt>{t('secov.classifier')}</dt>
          <dd className="mono small">
            {gw.l2_model ?? t('secov.noClassifier')}
            {gw.l2_model ? ` · ${gw.l2_verified ? t('secov.verified') : t('secov.unverified')}` : ''}
          </dd>
          {gw.update_available && gw.recommended ? (
            <>
              <dt>{t('secov.update')}</dt>
              <dd className="mono small">{gw.recommended}</dd>
            </>
          ) : null}
          {gw.reload.error ? (
            <>
              <dt>{t('secov.reloadError')}</dt>
              <dd className="field-error">{gw.reload.error}</dd>
            </>
          ) : null}
        </dl>
      ) : (
        <p className="muted small">{gw?.configured ? t('start.models.unreachable', { error: gw.error ?? '' }) : t('start.models.unconfigured')}</p>
      )}
      <a className="btn btn-link" href={href('models')} onClick={onLink('models')}>
        {t('secov.openModels')}
      </a>
    </section>
  );
}

export default function SecurityOverviewPage() {
  const { api, t, lang, notify } = useApp();
  const { org } = useOrg();
  const [range, setRange] = useState<DashboardWindow>(DASH_WINDOWS[0] ?? '24h');
  const stats = useLoad(useCallback(() => api.getDashboard(org.id, { window: range }), [api, org.id, range]));
  const models = useLoad(useCallback(() => api.getGatewayModels(), [api]));
  const [downloading, setDownloading] = useState(false);
  const s = stats.data;
  const gw = models.data;
  const nf = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US');
  const pct = new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US', { style: 'percent', maximumFractionDigits: 1 });
  const { bars, max } = attackBars(s ?? { series: [] });
  const windowName = t(`dash.window.${range}` as MessageKey);

  const downloadCsv = async () => {
    setDownloading(true);
    try {
      downloadText(reportFilename(org.slug, range, new Date()), await api.getRequestsReportCsv(org.id, { window: range }));
    } catch (e) {
      notify(errorText(e), 'error');
    } finally {
      setDownloading(false);
    }
  };

  const actions = (
    <>
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

  const keys = s?.top_blocked_keys ?? [];
  const projects = s?.top_blocked_projects ?? [];
  return (
    <div>
      <PageHeader title={t('secov.title')} help={t('secov.help')} actions={actions} />
      {stats.notFound ? <NotAvailable feature={t('secov.title')} /> : stats.forbidden ? <Forbidden /> : <ErrorBanner error={stats.error} />}
      {stats.loading && !s ? <Loading /> : null}
      {s ? (
        <>
          <div className="tiles">
            <div className="card tile">
              <div className="tile-head muted">
                <ShieldAlert size={16} aria-hidden="true" />
                <span>{t('secov.blocked')}</span>
              </div>
              <div className="tile-value" data-testid="sec-blocked">
                {nf.format(s.blocked)}
              </div>
              <div className="muted small">{t('secov.blockRate', { rate: pct.format(s.block_rate), window: windowName })}</div>
            </div>
            <div className="card tile">
              <div className="tile-head muted">
                <TrendingUp size={16} aria-hidden="true" />
                <span>{t('secov.topDetection')}</span>
              </div>
              <div className="tile-value tile-value-text">{s.top_labels[0]?.label ?? '—'}</div>
              <div className="muted small">{s.top_labels[0] ? t('secov.times', { n: nf.format(s.top_labels[0].count) }) : t('dash.noLabels')}</div>
            </div>
            <div className="card tile" data-testid="sec-versions">
              <div className="tile-head muted">
                <Info size={16} aria-hidden="true" />
                <span>{t('secov.versions')}</span>
              </div>
              <dl className="kv kv-tight">
                <dt>{t('secov.gatewayVersion')}</dt>
                <dd className="mono">{gw?.gateway_version ?? '—'}</dd>
                <dt>{t('secov.cpVersion')}</dt>
                <dd className="mono">{gw?.control_plane_version ?? '—'}</dd>
              </dl>
            </div>
          </div>
          <section className="card" aria-labelledby="trend-title">
            <h2 id="trend-title">{t('secov.trend')}</h2>
            {s.blocked === 0 ? (
              <p className="muted">{t('secov.noAttacks', { window: windowName })}</p>
            ) : (
              <>
                <div className="bars" role="img" aria-label={t('secov.trendAria', { count: s.blocked, window: windowName })} data-testid="attack-trend">
                  {bars.map((b) => (
                    <div key={b.start} className="bar-slot" title={`${formatShort(b.start)}: ${b.blocked}`}>
                      <svg className="bar-svg" viewBox="0 0 10 100" preserveAspectRatio="none" aria-hidden="true">
                        <rect x="1" width="8" y={100 - (b.blocked / max) * 100} height={(b.blocked / max) * 100} rx="1.5" className="bar bar-attack" />
                      </svg>
                    </div>
                  ))}
                </div>
                <div className="bars-axis muted small">
                  <span>{formatShort(Date.parse(s.from))}</span>
                  <span>{formatShort(Date.parse(s.to))}</span>
                </div>
              </>
            )}
          </section>
          <div className="dash-grid dash-grid-even">
            <section className="card" aria-labelledby="keys-title">
              <h2 id="keys-title">{t('secov.topKeys')}</h2>
              {keys.length === 0 ? (
                <p className="muted">{t('secov.noneAttacked')}</p>
              ) : (
                <ol className="rank-list" data-testid="sec-keys">
                  {keys.map((k) => (
                    <li key={k.key_prefix}>
                      <span>
                        <span className="mono">{k.key_prefix === 'none' ? t('secov.noKey') : k.key_prefix}</span>
                        {k.alias ? <span className="muted"> · {k.alias}</span> : null}
                      </span>
                      <span className="muted">{t('secov.blockedOf', { blocked: nf.format(k.blocked), count: nf.format(k.count) })}</span>
                    </li>
                  ))}
                </ol>
              )}
            </section>
            <section className="card" aria-labelledby="sprojects-title">
              <h2 id="sprojects-title">{t('secov.topProjects')}</h2>
              {projects.length === 0 ? (
                <p className="muted">{t('secov.noneAttacked')}</p>
              ) : (
                <ol className="rank-list" data-testid="sec-projects">
                  {projects.map((p) => (
                    <li key={p.project_id ?? ''}>
                      <span className={p.project_id ? undefined : 'muted'}>{p.name ?? t('dash.noProject')}</span>
                      <span className="muted">{t('secov.blockedOf', { blocked: nf.format(p.blocked), count: nf.format(p.count) })}</span>
                    </li>
                  ))}
                </ol>
              )}
            </section>
          </div>
          <div className="dash-grid dash-grid-even">
            <section className="card" aria-labelledby="det-title">
              <h2 id="det-title">{t('dash.topLabels')}</h2>
              {s.top_labels.length === 0 ? (
                <p className="muted">{t('dash.noLabels')}</p>
              ) : (
                <ol className="rank-list">
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
            <ModelHealthCard gw={gw} />
          </div>
        </>
      ) : null}
    </div>
  );
}
