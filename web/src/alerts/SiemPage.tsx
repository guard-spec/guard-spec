// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SIEM export (docs/siem.md): the organization's sinks. Each sends the org's
// events (detections, security, configuration and admin activity; metadata
// only) as OCSF records to Splunk, Elasticsearch, Microsoft Sentinel, syslog
// over TLS or an HTTP endpoint. Admins only; the secret is a variable name
// the operator granted (ALERTS_SECRET_ORGS, kind siem).

import { Plus, Radio } from 'lucide-react';
import { useCallback, useState } from 'react';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, RelativeTime, Toggle, useLoad } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import type { SiemKind, SiemSink, SiemSinkInput } from '../types';

const KINDS: SiemKind[] = ['splunk_hec', 'elastic', 'sentinel', 'syslog', 'http'];

/** The configuration keys of each kind, required first. */
const CONFIG_KEYS: Record<SiemKind, { key: string; required?: boolean; multiline?: boolean }[]> = {
  splunk_hec: [{ key: 'url', required: true }, { key: 'index' }, { key: 'sourcetype' }],
  elastic: [{ key: 'url', required: true }, { key: 'index' }],
  sentinel: [
    { key: 'endpoint', required: true },
    { key: 'dcr_id', required: true },
    { key: 'stream', required: true },
    { key: 'tenant_id', required: true },
    { key: 'client_id', required: true },
    { key: 'authority' },
  ],
  syslog: [{ key: 'address', required: true }, { key: 'format' }, { key: 'ca_pem', multiline: true }],
  http: [{ key: 'url', required: true }],
};

const empty = (): SiemSinkInput => ({
  name: '',
  kind: 'splunk_hec',
  config: {},
  secret_env: null,
  event_types: [],
  min_severity: 'info',
  allow_private: false,
  enabled: true,
});

export default function SiemPage() {
  const { api, t, notify } = useApp();
  const { org } = useOrg();
  const list = useLoad(useCallback(() => api.listSiemSinks(org.id), [api, org.id]));
  const [editing, setEditing] = useState<{ id: string | null; draft: SiemSinkInput } | null>(null);
  const [deleting, setDeleting] = useState<SiemSink | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const save = async () => {
    if (!editing) return;
    setError(null);
    try {
      if (editing.id) await api.updateSiemSink(org.id, editing.id, editing.draft);
      else await api.createSiemSink(org.id, editing.draft);
      notify(t('common.saved'));
      setEditing(null);
      await list.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  const test = async (s: SiemSink) => {
    setTesting(s.id);
    try {
      const r = await api.testSiemSink(org.id, s.id);
      if (r.ok) notify(t('siem.testOk', { name: s.name }));
      else notify(t('siem.testFailed', { error: r.error ?? '' }), 'error');
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e), 'error');
    } finally {
      setTesting(null);
    }
  };

  const sinks = list.data ?? [];
  const d = editing?.draft;
  const set = (p: Partial<SiemSinkInput>) => editing && setEditing({ ...editing, draft: { ...editing.draft, ...p } });

  return (
    <div className="page">
      <PageHeader
        title={t('siem.title')}
        help={t('siem.subtitle')}
        actions={
          <button type="button" className="btn btn-primary btn-icon-text" onClick={() => setEditing({ id: null, draft: empty() })}>
            <Plus size={14} aria-hidden="true" />
            <span>{t('siem.add')}</span>
          </button>
        }
      />
      <ErrorBanner error={list.error} />
      {list.forbidden ? <p className="muted">{t('siem.forbidden')}</p> : null}
      {!list.loading && !list.forbidden && sinks.length === 0 ? (
        <div className="empty" data-testid="siem-empty">
          <Radio size={20} aria-hidden="true" />
          <p>{t('siem.empty')}</p>
        </div>
      ) : null}
      {sinks.length > 0 ? (
        <table className="table" data-testid="siem-table">
          <thead>
            <tr>
              <th>{t('siem.name')}</th>
              <th>{t('siem.kind')}</th>
              <th>{t('siem.status')}</th>
              <th>{t('siem.delivered')}</th>
              <th aria-label={t('common.actions')} />
            </tr>
          </thead>
          <tbody>
            {sinks.map((s) => (
              <tr key={s.id}>
                <td>
                  {s.name}
                  {!s.enabled ? <span className="muted small"> · {t('siem.disabled')}</span> : null}
                </td>
                <td className="nowrap">{t(`siem.kind.${s.kind}` as MessageKey)}</td>
                <td>
                  {s.last_error ? (
                    <span className="field-error small" title={s.last_error}>
                      {t('siem.failing', { n: String(s.failures) })}: {s.last_error.slice(0, 120)}
                    </span>
                  ) : s.last_success_at ? (
                    <span className="small">
                      {t('siem.lastSuccess')} <RelativeTime value={s.last_success_at} />
                    </span>
                  ) : (
                    <span className="muted small">{t('siem.waiting')}</span>
                  )}
                  {s.secret_env && !s.secret_set ? <div className="field-error small">{t('siem.secretMissing', { env: s.secret_env })}</div> : null}
                </td>
                <td className="nowrap">{s.delivered}</td>
                <td className="row-actions nowrap">
                  <button type="button" className="btn btn-small" disabled={testing === s.id} onClick={() => void test(s)}>
                    {t('siem.test')}
                  </button>
                  <button
                    type="button"
                    className="btn btn-small"
                    onClick={() =>
                      setEditing({
                        id: s.id,
                        draft: { name: s.name, kind: s.kind, config: { ...s.config }, secret_env: s.secret_env, event_types: s.event_types, min_severity: s.min_severity, allow_private: s.allow_private, enabled: s.enabled },
                      })
                    }
                  >
                    {t('common.edit')}
                  </button>
                  <button type="button" className="btn btn-small btn-danger" onClick={() => setDeleting(s)}>
                    {t('common.delete')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <p className="muted small">{t('siem.footnote')}</p>

      <Dialog
        open={editing !== null}
        wide
        title={editing?.id ? t('siem.edit') : t('siem.add')}
        onClose={() => setEditing(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setEditing(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void save()}>
              {t('common.save')}
            </button>
          </>
        }
      >
        {d ? (
          <div className="stack-sm">
            <ErrorBanner error={error} />
            <Field label={t('siem.name')}>{(p) => <input {...p} value={d.name} maxLength={100} onChange={(e) => set({ name: e.target.value })} />}</Field>
            <Field label={t('siem.kind')} help={t(`siem.kindHelp.${d.kind}` as MessageKey)}>
              {(p) => (
                <select {...p} value={d.kind} onChange={(e) => set({ kind: e.target.value as SiemKind, config: {} })}>
                  {KINDS.map((k) => (
                    <option key={k} value={k}>
                      {t(`siem.kind.${k}` as MessageKey)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {CONFIG_KEYS[d.kind].map(({ key, required, multiline }) => (
              <Field key={key} label={`${t(`siem.cfg.${key}` as MessageKey)}${required ? ' *' : ''}`}>
                {(p) =>
                  multiline ? (
                    <textarea {...p} rows={4} value={d.config[key] ?? ''} onChange={(e) => set({ config: { ...d.config, [key]: e.target.value } })} />
                  ) : (
                    <input {...p} value={d.config[key] ?? ''} onChange={(e) => set({ config: { ...d.config, [key]: e.target.value } })} />
                  )
                }
              </Field>
            ))}
            <Field label={t('siem.secretEnv')} help={t('siem.secretEnvHelp')}>
              {(p) => <input {...p} className="mono" value={d.secret_env ?? ''} placeholder="SIEM_SPLUNK_TOKEN" onChange={(e) => set({ secret_env: e.target.value.trim() || null })} />}
            </Field>
            <Field label={t('siem.eventTypes')} help={t('siem.eventTypesHelp')}>
              {(p) => (
                <input
                  {...p}
                  className="mono"
                  value={d.event_types.join(', ')}
                  placeholder="detection., security."
                  onChange={(e) =>
                    set({
                      event_types: e.target.value
                        .split(',')
                        .map((x) => x.trim())
                        .filter(Boolean),
                    })
                  }
                />
              )}
            </Field>
            <Field label={t('siem.minSeverity')}>
              {(p) => (
                <select {...p} value={d.min_severity} onChange={(e) => set({ min_severity: e.target.value as SiemSinkInput['min_severity'] })}>
                  {(['info', 'warning', 'critical'] as const).map((s) => (
                    <option key={s} value={s}>
                      {t(`siem.sev.${s}` as MessageKey)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Toggle label={t('siem.allowPrivate')} help={t('siem.allowPrivateHelp')} checked={d.allow_private} onChange={(v) => set({ allow_private: v })} />
            <Toggle label={t('siem.enabled')} checked={d.enabled} onChange={(v) => set({ enabled: v })} />
          </div>
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        title={t('siem.delete')}
        body={t('siem.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteSiemSink(org.id, deleting.id);
            notify(t('common.deleted'));
            setDeleting(null);
            await list.reload();
          } catch (e) {
            notify(e instanceof Error ? e.message : String(e), 'error');
          }
        }}
      />
    </div>
  );
}
