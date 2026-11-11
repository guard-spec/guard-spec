// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Getting started: the setup steps of an organization with their real state
// (GET .../getting-started), each with a link to the page that fixes it.
// New organizations land here until the required steps are done, unless the
// user puts the page away.

import { CircleCheck, CircleDashed, RefreshCw, TriangleAlert } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Forbidden, NotAvailable } from '../components/DataTable';
import { ErrorBanner, Loading, PageHeader, RelativeTime, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, navigate, onLink } from '../router';
import type { GettingStarted } from '../types';
import { isStartDismissed, layerNames, progress, setStartDismissed, startSteps, type Step } from './start';

function StateIcon({ state }: { state: Step['state'] }) {
  if (state === 'done') return <CircleCheck size={20} aria-hidden="true" className="step-icon step-icon-done" />;
  if (state === 'warn') return <TriangleAlert size={20} aria-hidden="true" className="step-icon step-icon-warn" />;
  return <CircleDashed size={20} aria-hidden="true" className="step-icon step-icon-todo" />;
}

/** The line under a step's title: what the checklist found. */
function StepDetail({ step, s }: { step: Step; s: GettingStarted }) {
  const { t } = useApp();
  switch (step.id) {
    case 'provider': {
      if (!s.upstream.configured) return <>{t('start.provider.todo')}</>;
      const what = s.upstream.upstreams > 0 ? t('start.provider.count', { n: s.upstream.upstreams }) : t('start.provider.env');
      if (s.upstream.reachable === true)
        return (
          <>
            {what} · {t('start.provider.answered')} <RelativeTime value={s.upstream.last_answer_at} />
          </>
        );
      if (s.upstream.reachable === false)
        return (
          <>
            {what} · {t('start.provider.failed')} <RelativeTime value={s.upstream.last_error_at} />
          </>
        );
      return (
        <>
          {what} · {t('start.provider.noTraffic')}
        </>
      );
    }
    case 'key':
      return <>{s.api_keys > 0 ? t('start.key.count', { n: s.api_keys }) : t('start.key.todo')}</>;
    case 'policy':
      return <>{s.policies > 0 ? t('start.policy.count', { n: s.policies }) : t('start.policy.todo')}</>;
    case 'models':
      if (!s.models.configured) return <>{t('start.models.unconfigured')}</>;
      if (!s.models.reachable) return <>{t('start.models.unreachable', { error: s.models.error ?? '' })}</>;
      if (s.models.layers.length === 0) return <>{t('start.models.noLayers')}</>;
      return (
        <>
          {t('start.models.layers', { layers: layerNames(s.models.layers) })}
          {s.models.version ? ` · ${t('start.models.version', { version: s.models.version })}` : ''}
        </>
      );
    case 'alerts':
      return <>{s.alert_channels > 0 ? t('start.alerts.count', { n: s.alert_channels }) : t('start.alerts.todo')}</>;
    case 'input':
      return <>{s.input_settings ? t('start.input.done') : t('start.input.todo')}</>;
  }
}

export default function GettingStartedPage() {
  const { api, t } = useApp();
  const { org } = useOrg();
  const status = useLoad(useCallback(() => api.getGettingStarted(org.id), [api, org.id]));
  const [dismissed, setDismissed] = useState(() => isStartDismissed(org.id));
  const s = status.data;
  const steps = s ? startSteps(s) : [];
  const p = progress(steps);

  const dismiss = () => {
    setStartDismissed(org.id, true);
    setDismissed(true);
    navigate('dashboard');
  };
  const restore = () => {
    setStartDismissed(org.id, false);
    setDismissed(false);
  };

  const actions = (
    <>
      <button type="button" className="btn btn-icon-text" onClick={() => void status.reload()}>
        <RefreshCw size={14} aria-hidden="true" />
        <span>{t('start.recheck')}</span>
      </button>
      {dismissed ? (
        <button type="button" className="btn" onClick={restore}>
          {t('start.restore')}
        </button>
      ) : (
        <button type="button" className="btn" onClick={dismiss}>
          {t('start.dismiss')}
        </button>
      )}
    </>
  );

  const section = (required: boolean, st: GettingStarted) => (
    <section className="card" aria-labelledby={required ? 'start-required' : 'start-recommended'}>
      <h2 id={required ? 'start-required' : 'start-recommended'}>{t(required ? 'start.required' : 'start.recommended')}</h2>
      <ol className="steps" data-testid={required ? 'start-required-steps' : 'start-recommended-steps'}>
        {steps
          .filter((x) => x.required === required)
          .map((x) => (
            <li key={x.id} className={`step step-${x.state}`} data-testid={`step-${x.id}`} data-state={x.state}>
              <StateIcon state={x.state} />
              <div className="step-body">
                <strong>{t(`start.${x.id}.title` as MessageKey)}</strong>
                <span className="sr-only"> ({t(`start.state.${x.state}` as MessageKey)})</span>
                <p className="muted small">{t(`start.${x.id}.desc` as MessageKey)}</p>
                <p className="small step-detail">
                  <StepDetail step={x} s={st} />
                </p>
              </div>
              <a
                className={x.state === 'done' ? 'btn btn-small' : 'btn btn-small btn-primary'}
                href={href(x.route)}
                onClick={onLink(x.route)}
                aria-label={`${t(x.state === 'done' ? 'start.review' : 'start.fix')}: ${t(`start.${x.id}.title` as MessageKey)}`}
              >
                {t(x.state === 'done' ? 'start.review' : 'start.fix')}
              </a>
            </li>
          ))}
      </ol>
    </section>
  );

  return (
    <div className="narrow-wide">
      <PageHeader title={t('start.title')} help={t('start.help')} actions={actions} />
      {status.notFound ? <NotAvailable feature={t('start.title')} /> : status.forbidden ? <Forbidden /> : <ErrorBanner error={status.error} />}
      {status.loading && !s ? <Loading /> : null}
      {s ? (
        <>
          <div className={p.requiredLeft === 0 ? 'banner banner-ok' : 'banner banner-info'} role="status" data-testid="start-progress">
            <span>
              {p.requiredLeft === 0 ? t('start.ready') : t('start.left', { n: p.requiredLeft })}{' '}
              {t('start.progress', { done: p.done, total: p.total })}
            </span>
          </div>
          <progress className="start-meter" max={p.total} value={p.done} aria-label={t('start.progress', { done: p.done, total: p.total })} />
          {section(true, s)}
          {section(false, s)}
        </>
      ) : null}
    </div>
  );
}
