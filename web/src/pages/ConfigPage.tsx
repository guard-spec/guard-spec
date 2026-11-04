// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Config as code: the org's upstreams, defaults and policies as one YAML
// document (GET/PUT /organizations/:orgId/config).

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError } from '../api';
import { CodeEditor, type EditorDiagnostic } from '../components/CodeEditor';
import { ConfirmDialog, ErrorBanner, Loading, PageHeader } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import type { ConfigChange, ConfigError } from '../types';
import { locatePath } from './yamlPath';

type Check = { kind: 'ok'; changes: ConfigChange[] } | { kind: 'errors'; errors: ConfigError[] } | null;

export default function ConfigPage() {
  const { api, t, notify } = useApp();
  const { org, reload: reloadOrg } = useOrg();
  const [loaded, setLoaded] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [check, setCheck] = useState<Check>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [confirm, setConfirm] = useState<ConfigChange[] | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const y = await api.getConfig(org.id);
      setLoaded(y);
      setText(y);
      setLoadError(null);
      setCheck(null);
    } catch (e) {
      setLoadError(errorText(e));
    }
  }, [api, org.id]);

  useEffect(() => {
    void load();
  }, [load]);

  const dryRun = async (): Promise<ConfigChange[] | null> => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.putConfig(org.id, text, true);
      setCheck({ kind: 'ok', changes: r.changes });
      return r.changes;
    } catch (e) {
      if (e instanceof ApiError && e.errors) {
        setCheck({ kind: 'errors', errors: e.errors });
      } else {
        setCheck(null);
        setError(errorText(e));
      }
      return null;
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    try {
      const r = await api.putConfig(org.id, text, false);
      notify(t('cfg.applied'));
      setConfirm(null);
      setCheck({ kind: 'ok', changes: r.changes });
      await load();
      await reloadOrg();
    } catch (e) {
      setConfirm(null);
      if (e instanceof ApiError && e.errors) setCheck({ kind: 'errors', errors: e.errors });
      else setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const diagnostics: EditorDiagnostic[] = useMemo(() => {
    if (check?.kind !== 'errors') return [];
    return check.errors.map((e) => ({ from: locatePath(text, e.path) ?? 0, message: `${e.path}: ${e.message}` }));
    // Positions are for the text that was checked.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [check]);

  if (loadError) return <ErrorBanner error={t('common.notAvailable', { error: loadError })} />;
  if (loaded === null) return <Loading />;
  const modified = text !== loaded;

  return (
    <div className="config-page">
      <PageHeader
        title={t('cfg.title')}
        help={t('cfg.help')}
        actions={
          <>
            {modified ? <span className="badge badge-warn">{t('cfg.modified')}</span> : null}
            <button type="button" className="btn" onClick={() => void load()} disabled={busy}>
              {t('cfg.reload')}
            </button>
            <button type="button" className="btn" aria-pressed={showDiff} onClick={() => setShowDiff(!showDiff)}>
              {showDiff ? t('cfg.hideDiff') : t('cfg.diff')}
            </button>
            <button type="button" className="btn" onClick={() => void dryRun()} disabled={busy}>
              {t('cfg.validate')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={async () => {
                const changes = await dryRun();
                if (changes) setConfirm(changes);
              }}
            >
              {t('cfg.apply')}
            </button>
          </>
        }
      />
      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <div className="config-layout">
        <CodeEditor
          mode="yaml"
          value={text}
          onChange={(v) => setText(v)}
          ariaLabel={t('cfg.editor')}
          diagnostics={diagnostics}
          original={showDiff ? loaded : null}
          testId="config-yaml"
        />
        <aside className="card config-side" aria-live="polite" data-testid="config-result">
          {check?.kind === 'ok' ? (
            <>
              <p className="banner banner-ok">{check.changes.length ? t('cfg.valid', { count: check.changes.length }) : t('cfg.noChanges')}</p>
              <ChangeList changes={check.changes} />
            </>
          ) : null}
          {check?.kind === 'errors' ? (
            <>
              <p className="banner banner-error">{t('cfg.invalid', { count: check.errors.length })}</p>
              <ul className="error-list">
                {check.errors.map((e, i) => (
                  <li key={`${e.path}-${i}`}>
                    <code>{e.path}</code>
                    <span>{e.message}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          {check === null ? <p className="muted small">{t('cfg.help')}</p> : null}
        </aside>
      </div>
      <ConfirmDialog
        open={confirm !== null}
        title={t('cfg.confirmTitle')}
        confirmLabel={t('cfg.apply')}
        onClose={() => setConfirm(null)}
        onConfirm={apply}
        body={
          <>
            <p>{t('cfg.confirmBody')}</p>
            {confirm && confirm.length > 0 ? <ChangeList changes={confirm} /> : <p className="muted">{t('cfg.noChanges')}</p>}
          </>
        }
      />
    </div>
  );
}

export function ChangeList({ changes }: { changes: ConfigChange[] }) {
  const { t } = useApp();
  return (
    <ul className="change-list" data-testid="change-list">
      {changes.map((c, i) => (
        <li key={`${c.kind}-${c.name}-${i}`} className={`change-${c.op}`}>
          <span className={`badge badge-${c.op}`}>{t(`cfg.op.${c.op}` as MessageKey)}</span>
          <span className="muted">{c.kind}</span> <strong>{c.name}</strong>
        </li>
      ))}
    </ul>
  );
}
