// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Why a request was refused, and the one-click fixes of a false positive,
// inside the request details (RF-a1dbafea U2):
//
//   - the detector's layer scores and fired rules (detector:* tags), the
//     policy rule and the log-only rules that would have decided;
//   - an allow exemplar of the text, added without leaving the page;
//   - a false-positive report (the existing GitHub report dialog);
//   - an impact preview from GET .../requests/{id}/impact: counts from
//     stored scores and hashes, with what they cannot tell.
//
// The text is never fetched here: the exemplar starts from the stored
// content only when the user already read it (permission, reason, logged),
// else the user types it.

import { Flag, ThumbsUp } from 'lucide-react';
import { useCallback, useId, useState } from 'react';
import { Badge } from '../components/DataTable';
import { ErrorBanner, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import { extractPrompt } from '../report';
import { href, onLink } from '../router';
import type { AuditRow, RequestImpact } from '../types';
import { detectorOf, wouldDecideOf } from './auditTags';
import { exemplarSource, LAYERS, scoreText } from './falsePositive';

/** The detector's layers and the rules that fired. */
export function WhyRefused({ row, ruleLabel }: { row: AuditRow; ruleLabel: (id: string) => string }) {
  const { t } = useApp();
  const det = detectorOf(row);
  const would = wouldDecideOf(row);
  return (
    <div className="stack-sm" data-testid="why-refused">
      {det ? (
        <ul className="layer-scores" aria-label={t('fp.layers')}>
          {LAYERS.map((l) => {
            const v = det.layers[l];
            return (
              <li key={l} data-testid={`layer-${l}`}>
                <span className="layer-name">{t(`fp.layer.${l}`)}</span>
                {v === undefined ? (
                  <span className="muted small">{t('fp.notRun')}</span>
                ) : (
                  <>
                    <span className="meter" aria-hidden="true">
                      <svg viewBox="0 0 100 6" preserveAspectRatio="none">
                        <rect width={Math.max(0, Math.min(1, v)) * 100} height="6" rx="3" className={v >= 0.5 ? 'meter-fill meter-block' : 'meter-fill meter-allow'} />
                      </svg>
                    </span>
                    <span className="mono small">{scoreText(v)}</span>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="muted small" data-testid="no-layers">
          {t('fp.noLayers')}
        </p>
      )}
      <div className="name-line wrap" data-testid="fired-rules">
        <span className="small muted">{t('fp.fired')}</span>
        {row.rule_id ? <Badge tone="accent">{t('fp.policyRule', { name: ruleLabel(row.rule_id) })}</Badge> : null}
        {would.map((w) => (
          <Badge key={`${w.action}-${w.ruleId}`} tone="warn">
            {t('fp.wouldRule', { action: w.action, name: ruleLabel(w.ruleId) })}
          </Badge>
        ))}
        {det?.rules.map((r) => (
          <code key={r} className="small">
            {r}
          </code>
        ))}
        {!row.rule_id && would.length === 0 && (det?.rules.length ?? 0) === 0 ? <span className="small">{t('fp.noneFired')}</span> : null}
      </div>
    </div>
  );
}

function ImpactText({ impact }: { impact: RequestImpact }) {
  const { t } = useApp();
  const score = scoreText(impact.request.injection_score);
  return (
    <ul className="impact" data-testid="impact">
      {impact.same_input ? (
        <li>{t('fp.impact.sameInput', { total: impact.same_input.total, blocked: impact.same_input.blocked })}</li>
      ) : (
        <li className="muted">{t('fp.impact.noHash')}</li>
      )}
      {impact.same_rule ? <li>{t('fp.impact.sameRule', { total: impact.same_rule.total, blocked: impact.same_rule.blocked })}</li> : null}
      {impact.threshold ? (
        impact.threshold.above_default ? (
          <li>{t('fp.impact.aboveDefault', { score, threshold: scoreText(impact.threshold.gateway_default) })}</li>
        ) : (
          <li>{t('fp.impact.threshold', { n: impact.threshold.at_or_below, score })}</li>
        )
      ) : null}
      <li className="muted small">{t('fp.impact.limit')}</li>
    </ul>
  );
}

export function FalsePositivePanel({
  row,
  storedRequest,
  onReport,
}: {
  row: AuditRow;
  /** The stored request body, when the user read it in this page. */
  storedRequest: string | null;
  onReport: () => void;
}) {
  const { api, t, notify } = useApp();
  const { org, can } = useOrg();
  const writable = can('exemplars.write');
  const impact = useLoad(useCallback(() => api.getRequestImpact(org.id, row.id), [api, org.id, row.id]));
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<string | null>(null);
  const text = draft ?? (storedRequest ? extractPrompt(storedRequest, 'User prompt') : '');
  const [source, setSource] = useState(() => exemplarSource(row));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState(false);
  const textId = useId();
  const sourceId = useId();
  const decided = impact.data?.request.decided_by;

  const add = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.createExemplar(org.id, { label: 'allow', text: text.trim(), source: source.trim() });
      setAdded(true);
      setOpen(false);
      notify(t('fp.added'));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="fp-panel" aria-labelledby="fp-title" data-testid="fp-panel">
      <h3 id="fp-title">{t('fp.title')}</h3>
      <p className="muted small">{t('fp.intro')}</p>
      {impact.data ? <ImpactText impact={impact.data} /> : impact.notFound ? <p className="muted small">{t('fp.impact.unavailable')}</p> : <ErrorBanner error={impact.error} />}
      {decided === 'rule' ? (
        <div className="banner banner-warn small" role="note" data-testid="fp-rule-note">
          <span>
            {t('fp.ruleNote')}{' '}
            <a href={href('flow')} onClick={onLink('flow')}>
              {t('fp.openFlow')}
            </a>
          </span>
        </div>
      ) : decided === 'input' ? (
        <div className="banner banner-warn small" role="note" data-testid="fp-input-note">
          <span>
            {t('fp.inputNote')}{' '}
            <a href={href('input')} onClick={onLink('input')}>
              {t('fp.openInput')}
            </a>
          </span>
        </div>
      ) : null}
      <div className="panel-actions">
        {writable ? (
          <button type="button" className="btn btn-icon-text" aria-expanded={open} disabled={added} onClick={() => setOpen((o) => !o)}>
            <ThumbsUp size={14} aria-hidden="true" />
            <span>{added ? t('fp.addedShort') : t('fp.addExemplar')}</span>
          </button>
        ) : null}
        <button type="button" className="btn btn-icon-text" onClick={onReport}>
          <Flag size={14} aria-hidden="true" />
          <span>{t('fp.report')}</span>
        </button>
      </div>
      {!writable ? <p className="muted small">{t('fp.readOnly')}</p> : null}
      {open ? (
        <div className="stack-sm fp-form" data-testid="fp-form">
          <ErrorBanner error={error} />
          {storedRequest ? (
            <p className="small muted">{t('fp.fromStored')}</p>
          ) : (
            <p className="small muted" data-testid="fp-no-text">
              {row.has_content ? t('fp.readFirst') : t('fp.noText')}
            </p>
          )}
          <label htmlFor={textId}>{t('fp.text')}</label>
          <textarea id={textId} rows={4} maxLength={4000} value={text} onChange={(e) => setDraft(e.target.value)} />
          <label htmlFor={sourceId}>{t('ex.source')}</label>
          <input id={sourceId} maxLength={200} value={source} onChange={(e) => setSource(e.target.value)} />
          <div>
            <button type="button" className="btn btn-primary" disabled={busy || text.trim() === ''} onClick={() => void add()}>
              {t('fp.save')}
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
