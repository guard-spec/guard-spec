// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The gateway's classifier models (GET /gateway/models, instance-wide) and the
// shadow comparison of this organization's traffic (GET /organizations/:orgId/shadow).

import { CheckCircle2, GitCompare, ShieldOff, ShieldPlus, TimerOff } from 'lucide-react';
import { useCallback, useId, useState, type ReactNode } from 'react';
import { Badge, DataTable, EmptyState, Forbidden, NotAvailable, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ErrorBanner, formatTime, Loading, PageHeader, RelativeTime, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { SHADOW_DIRECTIONS, type GatewayModels, type ShadowDirection, type ShadowDisagreement, type ShadowSummary, type ShadowWindow } from '../types';
import { DASH_WINDOWS } from './dashboard';
import { binLabel, histogramMax, notComparedTotal } from './models';

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

/** Number formats of the UI language. */
function useFormats() {
  const { lang } = useApp();
  const locale = lang === 'vi' ? 'vi-VN' : 'en-US';
  const nf = new Intl.NumberFormat(locale);
  const pct = new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 1 });
  const sf = new Intl.NumberFormat(locale, { minimumFractionDigits: 2, maximumFractionDigits: 3 });
  const df = new Intl.NumberFormat(locale, { minimumFractionDigits: 2, maximumFractionDigits: 3, signDisplay: 'exceptZero' });
  return {
    nf,
    pct,
    score: (v: number | null) => (v === null ? '—' : sf.format(v)),
    delta: (v: number | null) => (v === null ? '—' : df.format(v)),
  };
}

export function ModelsPage() {
  const { t } = useApp();
  const { can } = useOrg();
  const [range, setRange] = useState<ShadowWindow>(DASH_WINDOWS[0] ?? '24h');

  const actions = (
    <div className="segmented segmented-text" role="group" aria-label={t('dash.windowLabel')}>
      {DASH_WINDOWS.map((w) => (
        <button key={w} type="button" aria-pressed={range === w} title={t(`dash.window.${w}` as MessageKey)} onClick={() => setRange(w)}>
          {w}
        </button>
      ))}
    </div>
  );

  return (
    <div>
      <PageHeader title={t('models.title')} help={t('models.help')} actions={can('shadow.read') ? actions : undefined} />
      <RunningModel />
      <h2 className="mt" id="shadow-title">
        {t('models.shadow')}
      </h2>
      {can('shadow.read') ? <ShadowComparison range={range} /> : <Forbidden compact />}
    </div>
  );
}

function RunningModel() {
  const { api, t } = useApp();
  const gw = useLoad(useCallback(() => api.getGatewayModels(), [api]));
  const g = gw.data;
  return (
    <section className="card" aria-labelledby="running-title" data-testid="gateway-models">
      <div className="section-head">
        <h2 id="running-title">{t('models.running')}</h2>
        {g?.checked_at ? (
          <span className="muted small">
            {t('models.checked')} <RelativeTime value={g.checked_at} />
          </span>
        ) : null}
      </div>
      {gw.notFound ? <NotAvailable compact feature={t('models.title')} /> : gw.forbidden ? <Forbidden compact /> : <ErrorBanner error={gw.error} />}
      {gw.loading && !g ? <Loading /> : null}
      {g ? <GatewayDetails g={g} /> : null}
    </section>
  );
}

function GatewayDetails({ g }: { g: GatewayModels }) {
  const { t } = useApp();
  if (!g.configured) {
    return (
      <div className="banner banner-info" data-testid="gateway-not-configured">
        <span>{t('models.notConfigured')}</span>
      </div>
    );
  }
  if (!g.reachable) {
    return (
      <div className="banner banner-error" role="alert">
        <span>{g.error ? t('models.unreachable', { error: g.error }) : t('models.unreachableNoError')}</span>
      </div>
    );
  }
  const running = g.l2_model ?? t('models.noL2');
  return (
    <>
      {g.update_available && g.recommended ? (
        <div className="banner banner-warn" role="status" data-testid="models-update">
          <span>{t('models.update', { recommended: g.recommended, running })}</span>
        </div>
      ) : null}
      {g.reload.error ? (
        <div className="banner banner-error" role="alert">
          <span>{t('models.reloadError', { error: g.reload.error })}</span>
        </div>
      ) : null}
      <dl className="kv kv-wide">
        <dt>{t('models.l2')}</dt>
        <dd>
          <span className="name-line">
            <span className={g.l2_model ? 'mono' : 'muted'}>{running}</span>
            {g.l2_model ? (
              g.l2_verified ? (
                <Badge tone="ok" title={t('models.verifiedHelp')}>
                  {t('models.verified')}
                </Badge>
              ) : (
                <Badge tone="warn" title={t('models.unverifiedHelp')}>
                  {t('models.unverified')}
                </Badge>
              )
            ) : null}
          </span>
        </dd>
        <dt>{t('models.recommended')}</dt>
        <dd>
          <span className="name-line">
            <span className="mono">{g.recommended ?? '—'}</span>
            {g.recommended && !g.update_available ? <Badge tone="ok">{t('models.upToDate')}</Badge> : null}
          </span>
        </dd>
        <dt>{t('models.installed')}</dt>
        <dd>
          {g.installed.length === 0 ? (
            <span className="muted">{t('models.noneInstalled')}</span>
          ) : (
            <ul className="chip-list" data-testid="installed-models">
              {g.installed.map((m) => (
                <li key={m}>
                  <code>{m}</code>
                </li>
              ))}
            </ul>
          )}
        </dd>
        <dt>{t('models.shadowModel')}</dt>
        <dd>
          {g.shadow.enabled && g.shadow.model ? <span className="mono">{g.shadow.model}</span> : <span className="muted">{t('models.shadowOff')}</span>}
          {g.shadow.error ? <div className="field-error small">{t('models.shadowError', { error: g.shadow.error })}</div> : null}
        </dd>
        <dt>{t('models.lastReload')}</dt>
        <dd>
          {g.reload.at ? (
            <>
              {formatTime(g.reload.at)} <span className="muted small">· {t('models.reloadGeneration', { n: g.reload.generation })}</span>
            </>
          ) : (
            <span className="muted">{t('models.reloadNever')}</span>
          )}
        </dd>
      </dl>
    </>
  );
}

function ShadowComparison({ range }: { range: ShadowWindow }) {
  const { api, t } = useApp();
  const { org, can } = useOrg();
  const summary = useLoad(useCallback(() => api.getShadowSummary(org.id, { window: range }), [api, org.id, range]));
  const s = summary.data;
  const windowName = t(`dash.window.${range}` as MessageKey);
  return (
    <>
      {summary.notFound ? (
        <div className="card">
          <NotAvailable feature={t('models.shadow')} />
        </div>
      ) : summary.forbidden ? (
        <div className="card">
          <Forbidden />
        </div>
      ) : (
        <ErrorBanner error={summary.error} />
      )}
      {summary.loading && !s ? <Loading /> : null}
      {s?.total === 0 ? (
        <div className="card">
          <EmptyState icon={GitCompare} title={t('models.shadowEmptyTitle')} body={t('models.shadowEmptyBody')} />
        </div>
      ) : null}
      {s && s.total > 0 ? (
        <>
          <ShadowStats s={s} windowName={windowName} />
          <h2 className="mt" id="disagreements-title">
            {t('models.disagreements')}
          </h2>
          {can('shadow.disagreements.read') ? (
            <Disagreements range={range} />
          ) : (
            <p className="muted" data-testid="disagreements-admins-only">
              {t('models.adminsOnly')}
            </p>
          )}
        </>
      ) : null}
    </>
  );
}

function ShadowStats({ s, windowName }: { s: ShadowSummary; windowName: string }) {
  const { t } = useApp();
  const { nf, pct, score, delta } = useFormats();
  const max = histogramMax(s.scores.histogram);
  const nc = s.not_compared;
  return (
    <>
      <p className="muted small" data-testid="shadow-range">
        {t('models.shadowRange', { window: windowName, threshold: score(s.threshold) })}
      </p>
      <div className="tiles" data-testid="shadow-tiles">
        <Tile icon={<GitCompare size={16} aria-hidden="true" />} label={t('models.compared')} value={nf.format(s.compared)} sub={t('models.comparedOf', { total: nf.format(s.total) })} />
        <Tile
          icon={<CheckCircle2 size={16} aria-hidden="true" />}
          label={t('models.agreement')}
          value={s.agreement_rate === null ? '—' : pct.format(s.agreement_rate)}
          sub={t('models.agreeCount', { count: nf.format(s.agree) })}
        />
        <Tile icon={<ShieldPlus size={16} aria-hidden="true" />} label={t('models.wouldBlock')} value={nf.format(s.shadow_would_block)} sub={t('models.wouldBlockSub')} />
        <Tile icon={<ShieldOff size={16} aria-hidden="true" />} label={t('models.wouldAllow')} value={nf.format(s.shadow_would_allow)} sub={t('models.wouldAllowSub')} />
        <Tile
          icon={<TimerOff size={16} aria-hidden="true" />}
          label={t('models.notCompared')}
          value={nf.format(notComparedTotal(s))}
          sub={t('models.notComparedSub', { timeout: nf.format(nc.timeout), skipped: nf.format(nc.skipped), error: nf.format(nc.error) })}
        />
      </div>
      <div className="dash-grid dash-grid-even">
        <section className="card" aria-labelledby="scores-title">
          <h2 id="scores-title">
            {t('models.scores')}
          </h2>
          <table className="compact-table" data-testid="shadow-scores">
            <caption className="sr-only">{t('models.scoresCaption')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('models.stat')}</th>
                <th scope="col" className="num">
                  {t('models.active')}
                </th>
                <th scope="col" className="num">
                  {t('models.shadowCol')}
                </th>
              </tr>
            </thead>
            <tbody>
              {(['mean', 'p50', 'p95'] as const).map((k) => (
                <tr key={k}>
                  <th scope="row">{t(`models.${k}`)}</th>
                  <td className="num">{score(s.scores.active[k])}</td>
                  <td className="num">{score(s.scores.shadow[k])}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <dl className="kv mt" data-testid="shadow-delta">
            <dt>{t('models.deltaMean')}</dt>
            <dd>{delta(s.scores.delta.mean)}</dd>
            <dt>{t('models.deltaMeanAbs')}</dt>
            <dd>{score(s.scores.delta.mean_abs)}</dd>
            <dt>{t('models.deltaP95Abs')}</dt>
            <dd>{score(s.scores.delta.p95_abs)}</dd>
          </dl>
          <h2 className="mt">{t('models.pairs')}</h2>
          <table className="compact-table" data-testid="shadow-pairs">
            <thead>
              <tr>
                <th scope="col">{t('models.pairActive')}</th>
                <th scope="col">{t('models.pairShadow')}</th>
                <th scope="col" className="num">
                  {t('models.pairCount')}
                </th>
              </tr>
            </thead>
            <tbody>
              {s.pairs.map((p) => (
                <tr key={`${p.active_model} ${p.shadow_model}`}>
                  <td className="mono small">{p.active_model}</td>
                  <td className="mono small">{p.shadow_model}</td>
                  <td className="num">{nf.format(p.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <section className="card" aria-labelledby="hist-title">
          <h2 id="hist-title">{t('models.histogram')}</h2>
          <p className="hist-legend muted small" aria-hidden="true">
            <span className="legend-swatch legend-active" /> {t('models.active')}
            <span className="legend-swatch legend-shadow" /> {t('models.shadowCol')}
          </p>
          <table className="compact-table hist-table" data-testid="shadow-histogram">
            <caption className="sr-only">{t('models.histogramCaption')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('models.bin')}</th>
                <th scope="col">{t('models.active')}</th>
                <th scope="col">{t('models.shadowCol')}</th>
              </tr>
            </thead>
            <tbody>
              {s.scores.histogram.map((b) => (
                <tr key={b.from}>
                  <th scope="row" className="mono small nowrap">
                    {binLabel(b)}
                  </th>
                  <td>
                    <HistBar value={b.active} max={max} kind="active" label={nf.format(b.active)} />
                  </td>
                  <td>
                    <HistBar value={b.shadow} max={max} kind="shadow" label={nf.format(b.shadow)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </>
  );
}

function HistBar({ value, max, kind, label }: { value: number; max: number; kind: 'active' | 'shadow'; label: string }) {
  return (
    <span className="hist-cell">
      <span className="meter" aria-hidden="true">
        <svg viewBox="0 0 100 6" preserveAspectRatio="none">
          <rect width={(value / max) * 100} height="6" rx="3" className={`meter-fill meter-${kind}`} />
        </svg>
      </span>
      <span className="meter-value">{label}</span>
    </span>
  );
}

function Decision({ score, decision, model }: { score: number; decision: 'allow' | 'block'; model: string }) {
  const { score: fmt } = useFormats();
  return (
    <span className="name-line" title={model}>
      <span className="mono small">{fmt(score)}</span>
      <span className={`action action-${decision}`}>{decision}</span>
    </span>
  );
}

function Disagreements({ range }: { range: ShadowWindow }) {
  const { api, t } = useApp();
  const { org } = useOrg();
  const [direction, setDirection] = useState<ShadowDirection | ''>('');
  const directionId = useId();
  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listShadowDisagreements(org.id, { window: range, direction: direction || undefined, ...p }),
    [api, org.id, range, direction],
  );
  const paged = usePaged<ShadowDisagreement>(fetchPage);

  const columns: Column<ShadowDisagreement>[] = [
    { key: 'time', header: t('models.time'), className: 'nowrap', cell: (r) => formatTime(r.created_at) },
    {
      key: 'direction',
      header: t('models.direction'),
      className: 'nowrap',
      cell: (r) => <Badge tone={r.direction === 'would_block' ? 'danger' : 'ok'}>{t(`models.dir.${r.direction}`)}</Badge>,
    },
    { key: 'active', header: t('models.active'), className: 'nowrap', cell: (r) => <Decision score={r.active_score} decision={r.active_decision} model={r.active_model} /> },
    { key: 'shadow', header: t('models.shadowCol'), className: 'nowrap', cell: (r) => <Decision score={r.shadow_score} decision={r.shadow_decision} model={r.shadow_model} /> },
    { key: 'action', header: t('models.gatewayAction'), className: 'nowrap', cell: (r) => <span className={`action action-${r.action}`}>{r.action}</span> },
    {
      key: 'model',
      header: t('models.llm'),
      className: 'col-model col-wide-only',
      cell: (r) => (
        <span className="mono small ellipsis" title={r.model ?? undefined}>
          {r.model ?? '—'}
        </span>
      ),
    },
    {
      key: 'request',
      header: t('models.request'),
      className: 'col-wide-only',
      cell: (r) => (
        <code className="small" title={r.request_id}>
          {r.request_id.slice(0, 8)}
        </code>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      paged={paged}
      rowKey={(r) => r.request_id}
      testId="disagreements-table"
      caption={t('models.disagreements')}
      feature={t('models.disagreements')}
      toolbar={
        <div className="field field-inline">
          <label htmlFor={directionId}>{t('models.direction')}</label>
          <select id={directionId} value={direction} onChange={(e) => setDirection(e.target.value as ShadowDirection | '')}>
            <option value="">{t('models.directionAll')}</option>
            {SHADOW_DIRECTIONS.map((d) => (
              <option key={d} value={d}>
                {t(`models.dir.${d}`)}
              </option>
            ))}
          </select>
        </div>
      }
      empty={<EmptyState icon={GitCompare} title={t('models.noDisagreementsTitle')} body={direction ? undefined : t('models.noDisagreementsBody')} />}
    />
  );
}
