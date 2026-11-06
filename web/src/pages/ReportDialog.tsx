// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { ExternalLink } from 'lucide-react';
import { useCallback, useId, useMemo, useState } from 'react';
import { CopyButton, Dialog, useLoad } from '../components/ui';
import { useApp } from '../context';
import {
  auditFields,
  defaultKind,
  detectorInfo,
  extractPrompt,
  issueLink,
  RED_TEAM_DOC_URL,
  reportMarkdown,
  SECURITY_REPORT_URL,
  WHERE_OPTIONS,
  type ReportInput,
  type ReportKind,
  type Where,
} from '../report';
import type { AuditRow } from '../types';

const WHERE_KEYS = {
  'User prompt': 'report.where.user',
  'RAG document': 'report.where.rag',
  'Tool result': 'report.where.tool',
  'MCP tool description': 'report.where.mcp',
} as const;

/**
 * Report a request log row as a bypass or a false positive: builds a
 * prefilled GitHub issue in the browser. The control plane sends nothing; the
 * user posts the issue on GitHub. Anyone who can read the request log
 * (viewers too) can report.
 */
export function ReportDialog({ row, ruleName, onClose }: { row: AuditRow; ruleName: string | null; onClose: () => void }) {
  const { api, t, notify } = useApp();
  const [kind, setKind] = useState<ReportKind>(() => defaultKind(row.action));
  const [where, setWhere] = useState<Where>('User prompt');
  const [include, setInclude] = useState(false);
  const stored = row.request_content ?? '';
  // The extracted text follows "where it appeared" until the user edits it.
  const [draft, setDraft] = useState<string | null>(null);
  const text = draft ?? (stored ? extractPrompt(stored, where) : '');
  // Version and layers for the report; the report works without them.
  const models = useLoad(useCallback(() => api.getGatewayModels(), [api]));
  const gw = models.data ?? null;
  const whereId = useId();
  const textId = useId();

  const input: ReportInput = useMemo(
    () => ({ kind, row, where, detector: detectorInfo(gw), ruleName, prompt: include && text.trim() ? text : null }),
    [kind, row, where, gw, ruleName, include, text],
  );
  const preview = useMemo(() => auditFields(input), [input]);

  const open = () => {
    const link = issueLink(input);
    if (link.tooLong) {
      // Start the copy before opening the tab: both run in the click.
      void navigator.clipboard.writeText(link.clipboard).then(
        () => notify(t('report.tooLong')),
        () => notify(t('report.copyFailed'), 'error'),
      );
    }
    window.open(link.url, '_blank', 'noopener,noreferrer');
  };

  return (
    <Dialog
      open
      wide
      title={t('report.title')}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <CopyButton text={reportMarkdown(input)} />
          <button type="button" className="btn btn-primary btn-icon-text" onClick={open}>
            <ExternalLink size={14} aria-hidden="true" />
            <span>{t('report.open')}</span>
          </button>
        </>
      }
    >
      <p className="muted">{t('report.intro')}</p>
      <div className="radio-list" role="radiogroup" aria-label={t('report.kind')}>
        {(['bypass', 'false_positive'] as const).map((k) => (
          <label key={k} className="check">
            <input type="radio" name="report-kind" checked={kind === k} onChange={() => setKind(k)} />
            <span>{t(k === 'bypass' ? 'report.kind.bypass' : 'report.kind.falsePositive')}</span>
          </label>
        ))}
      </div>
      <div className="field">
        <label htmlFor={whereId}>{t('report.where')}</label>
        <select id={whereId} value={where} onChange={(e) => setWhere(e.target.value as Where)}>
          {WHERE_OPTIONS.map((w) => (
            <option key={w} value={w}>
              {t(WHERE_KEYS[w])}
            </option>
          ))}
        </select>
      </div>
      {stored ? (
        <>
          <div className="banner banner-warn" role="note" data-testid="report-text-warning">
            <span>{t('report.textWarning')}</span>
          </div>
          <div className="field">
            <label className="check">
              <input type="checkbox" checked={include} onChange={(e) => setInclude(e.target.checked)} />
              <span>{t('report.includeText')}</span>
            </label>
          </div>
          {include ? (
            <div className="field">
              <label htmlFor={textId}>{t('report.textLabel')}</label>
              <textarea
                id={textId}
                rows={6}
                value={text}
                onChange={(e) => setDraft(e.target.value)}
              />
            </div>
          ) : null}
        </>
      ) : (
        <p className="muted small" data-testid="report-no-content">
          {t('report.noContent')}
        </p>
      )}
      <div className="field">
        <strong className="small">{t('report.preview')}</strong>
        <pre className="pre" data-testid="report-preview">
          {preview}
        </pre>
      </div>
      <p className="small">
        {t('report.severe')}{' '}
        <a href={SECURITY_REPORT_URL} target="_blank" rel="noopener noreferrer">
          {t('report.privateLink')}
        </a>
        {' · '}
        <a href={RED_TEAM_DOC_URL} target="_blank" rel="noopener noreferrer">
          {t('report.howHandled')}
        </a>
      </p>
    </Dialog>
  );
}
