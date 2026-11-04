// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Model providers (identity contract §6): the upstreams of the gateway, with
// a provider preset, allowed models, a default model, extra headers, limits
// and a connection test. Keys stay in the gateway environment (api_key_env).

import { Cpu, ExternalLink, Pencil, Plus, Trash2, Zap } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { isNotFound } from '../api';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, NotAvailable, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, useDebounced } from '../components/ui';
import { errorText, nonEmpty, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import type { CatalogEntry, ConnectionTest, ProviderKind, Upstream, UpstreamInput } from '../types';
import { BUILTIN_CATALOG, slugName, validateProvider, VIA_OPENAI_COMPAT, type ProviderError } from './providerCatalog';

const EMPTY: UpstreamInput = {
  name: '',
  display_name: '',
  provider: 'openai_compatible',
  base_url: '',
  model: '',
  default_model: '',
  models: [],
  headers: {},
  api_key_env: '',
  timeout_ms: 300000,
  retries: 1,
  max_tokens_cap: null,
  tags: [],
  enabled: true,
};

function toInput(u: Upstream): UpstreamInput {
  return {
    name: u.name,
    display_name: u.display_name ?? '',
    provider: u.provider ?? 'openai_compatible',
    base_url: u.base_url,
    model: nonEmpty(u.default_model) ?? u.model,
    default_model: nonEmpty(u.default_model) ?? u.model,
    models: u.models ?? [],
    headers: u.headers ?? {},
    api_version: u.api_version ?? '',
    api_key_env: u.api_key_env,
    timeout_ms: u.timeout_ms,
    retries: u.retries ?? 1,
    max_tokens_cap: u.max_tokens_cap ?? null,
    tags: u.tags ?? [],
    enabled: u.enabled,
  };
}

/** What is sent: model mirrors default_model (its alias for one release). */
function toBody(v: UpstreamInput): UpstreamInput {
  const body: UpstreamInput = { ...v, model: v.default_model ?? v.model };
  if (v.provider !== 'azure_openai') delete body.api_version;
  if (!body.display_name) delete body.display_name;
  return body;
}

function providerLabel(catalog: CatalogEntry[], p: ProviderKind | undefined): string {
  return catalog.find((c) => c.provider === p)?.display_name ?? p ?? '—';
}

export function ProvidersPage() {
  const { api, t, notify } = useApp();
  const { org, projects, upstreams, upstreamError, reload, setOrg, can } = useOrg();
  const writable = can('upstreams.write');
  const [catalog, setCatalog] = useState<CatalogEntry[]>(BUILTIN_CATALOG);
  const [builtin, setBuiltin] = useState(true);
  const [q, setQ] = useState('');
  const query = useDebounced(q);
  const [editing, setEditing] = useState<{ id: string | null; value: UpstreamInput; picking: boolean } | null>(null);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyEnvError, setKeyEnvError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Upstream | null>(null);
  const [tests, setTests] = useState<Record<string, ConnectionTest | 'running' | 'unavailable' | { error: string }>>({});

  useEffect(() => {
    let live = true;
    api.getProviderCatalog().then(
      (c) => {
        if (!live || c.length === 0) return;
        setCatalog(c);
        setBuiltin(false);
      },
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [api]);

  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => api.listUpstreamsPage(org.id, { ...p, q: query || undefined }), [api, org.id, query]);
  const needle = query.trim().toLowerCase();
  const paged = usePaged<Upstream>(fetchPage, {
    clientFilter: needle
      ? (u) => [u.name, u.display_name ?? '', u.base_url, u.provider ?? '', u.default_model ?? u.model].some((s) => s.toLowerCase().includes(needle))
      : undefined,
  });

  const errs = editing ? validateProvider(editing.value) : {};
  const msgFor = (e: ProviderError | undefined): string | undefined => {
    const keys: Record<ProviderError, MessageKey> = {
      name: 'up.invalidName',
      url: 'up.invalidUrl',
      env: 'up.invalidEnv',
      header: 'prov.invalidHeader',
      number: 'prov.invalidNumber',
      defaultModel: 'prov.invalidDefault',
    };
    return e ? t(keys[e]) : undefined;
  };
  const msg = (k: keyof UpstreamInput) => {
    if (k === 'api_key_env' && keyEnvError) return keyEnvError;
    return touched ? msgFor(errs[k]) : undefined;
  };

  const reloadAll = async () => {
    await Promise.all([reload(), paged.reload()]);
  };

  const save = async () => {
    setTouched(true);
    if (!editing || Object.keys(errs).length > 0) return;
    try {
      if (editing.id) await api.updateUpstream(org.id, editing.id, toBody(editing.value));
      else await api.createUpstream(org.id, toBody(editing.value));
      setEditing(null);
      notify(t('common.saved'));
      await reloadAll();
    } catch (e) {
      const m = errorText(e);
      if (m.includes('api_key_env')) setKeyEnvError(m);
      else setError(m);
    }
  };

  const test = async (u: Upstream) => {
    setTests((s) => ({ ...s, [u.id]: 'running' }));
    try {
      const r = await api.testUpstream(org.id, u.id);
      setTests((s) => ({ ...s, [u.id]: r }));
    } catch (e) {
      setTests((s) => ({ ...s, [u.id]: isNotFound(e) ? 'unavailable' : { error: errorText(e) } }));
    }
  };

  const setDefault = async (projectId: string | null, upstreamId: string | null) => {
    try {
      if (projectId) await api.setProjectDefaultUpstream(org.id, projectId, upstreamId);
      else {
        await api.setOrgDefaultUpstream(org.id, upstreamId);
        setOrg({ ...org, default_upstream_id: upstreamId });
      }
      notify(t('common.saved'));
      await reload();
    } catch (e) {
      notify(errorText(e), 'error');
    }
  };

  const set = (patch: Partial<UpstreamInput>) => {
    if ('api_key_env' in patch) setKeyEnvError(null);
    if (editing) setEditing({ ...editing, value: { ...editing.value, ...patch } });
  };

  const pick = (c: CatalogEntry) => {
    if (!editing) return;
    const name = nonEmpty(editing.value.name) ?? slugName(c.provider === 'openai_compatible' ? '' : c.display_name);
    setEditing({
      ...editing,
      picking: false,
      value: {
        ...editing.value,
        provider: c.provider,
        name,
        display_name: nonEmpty(editing.value.display_name) ?? (c.provider === 'openai_compatible' ? '' : c.display_name),
        base_url: c.base_url,
        api_key_env: c.needs_key ? (c.env_hint ?? '') : editing.value.api_key_env,
        default_model: c.models[0] ?? '',
        model: c.models[0] ?? '',
        models: [],
      },
    });
  };

  const openNew = () => {
    setTouched(false);
    setError(null);
    setKeyEnvError(null);
    setEditing({ id: null, value: { ...EMPTY, headers: {} }, picking: true });
  };

  const list = upstreams ?? [];
  const entry = editing ? catalog.find((c) => c.provider === editing.value.provider) : undefined;

  const columns: Column<Upstream>[] = [
    {
      key: 'name',
      header: t('up.name'),
      cell: (u) => (
        <div className="cell-stack">
          <span>
            <strong className="mono">{u.name}</strong>
            {org.default_upstream_id === u.id ? <Badge tone="accent">{t('flow.defaultBadge')}</Badge> : null}
          </span>
          {u.display_name ? <span className="muted small">{u.display_name}</span> : null}
        </div>
      ),
    },
    { key: 'provider', header: t('prov.provider'), cell: (u) => <Badge>{providerLabel(catalog, u.provider)}</Badge> },
    { key: 'url', header: t('up.baseUrl'), className: 'mono small', cell: (u) => u.base_url },
    {
      key: 'model',
      header: t('prov.models'),
      cell: (u) => (
        <div className="cell-stack">
          <span className="mono small">{nonEmpty(u.default_model) ?? (nonEmpty(u.model) ?? '—')}</span>
          <span className="muted small">{u.models && u.models.length > 0 ? t('prov.allowedCount', { count: u.models.length }) : t('prov.passThrough')}</span>
        </div>
      ),
    },
    { key: 'env', header: t('up.keyEnv'), className: 'mono small', cell: (u) => (u.api_key_env ? `$${u.api_key_env}` : '—') },
    { key: 'timeout', header: t('up.timeout'), cell: (u) => u.timeout_ms },
    {
      key: 'status',
      header: t('prov.status'),
      cell: (u) => (
        <div className="cell-stack">
          <Badge tone={u.enabled ? 'ok' : 'off'}>{u.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
          <TestResult r={tests[u.id]} />
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (u) => (
        <>
          {can('upstreams.test') ? (
            <button type="button" className="btn btn-small btn-icon-text" aria-label={t('prov.testOf', { name: u.name })} disabled={tests[u.id] === 'running'} onClick={() => void test(u)}>
              <Zap size={14} aria-hidden="true" />
              <span>{t('prov.test')}</span>
            </button>
          ) : null}
          {writable ? (
            <>
              <button
                type="button"
                className="btn btn-small btn-icon-text"
                aria-label={t('up.edit', { name: u.name })}
                onClick={() => {
                  setTouched(false);
                  setError(null);
                  setKeyEnvError(null);
                  setEditing({ id: u.id, value: toInput(u), picking: false });
                }}
              >
                <Pencil size={14} aria-hidden="true" />
                <span>{t('common.edit')}</span>
              </button>
              <button type="button" className="btn btn-small btn-danger btn-icon-text" aria-label={`${t('common.delete')} ${u.name}`} onClick={() => setDeleting(u)}>
                <Trash2 size={14} aria-hidden="true" />
                <span>{t('common.delete')}</span>
              </button>
            </>
          ) : null}
        </>
      ),
    },
  ];

  const headers = Object.entries(editing?.value.headers ?? {});
  const setHeaders = (rows: [string, string][]) => set({ headers: Object.fromEntries(rows) });

  return (
    <div>
      <PageHeader
        title={t('prov.title')}
        help={t('prov.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={openNew}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('prov.new')}</span>
            </button>
          ) : null
        }
      />
      {upstreamError ? <div className="banner banner-warn">{t('common.notAvailable', { error: upstreamError })}</div> : null}
      <p className="muted small">{t('up.resolution')}</p>
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(u) => u.id}
        testId="providers-table"
        feature={t('prov.title')}
        toolbar={<SearchBox value={q} onChange={setQ} label={t('prov.search')} />}
        empty={
          <EmptyState
            icon={Cpu}
            title={t('prov.emptyTitle')}
            body={t('prov.emptyBody')}
            action={
              writable ? (
                <button type="button" className="btn btn-primary" onClick={openNew}>
                  {t('prov.new')}
                </button>
              ) : undefined
            }
          />
        }
      />

      <section className="card" aria-labelledby="defaults-title">
        <h2 id="defaults-title">{t('up.defaults')}</h2>
        <p className="muted small">{t('prov.defaultsHelp')}</p>
        <div className="form-grid">
          <DefaultSelect
            label={t('up.orgDefault')}
            value={org.default_upstream_id ?? null}
            emptyLabel={t('up.gatewayDefault')}
            upstreams={list}
            disabled={!writable}
            onChange={(id) => void setDefault(null, id)}
          />
          {projects.map((p) => (
            <DefaultSelect
              key={p.id}
              label={t('up.projectDefault', { name: p.name })}
              value={p.default_upstream_id ?? null}
              emptyLabel={t('up.inherit')}
              upstreams={list}
              disabled={!writable}
              onChange={(id) => void setDefault(p.id, id)}
            />
          ))}
        </div>
      </section>

      <Dialog
        open={editing !== null}
        wide
        title={editing?.id ? t('up.edit', { name: editing.value.name }) : t('prov.new')}
        onClose={() => setEditing(null)}
        footer={
          editing?.picking ? (
            <button type="button" className="btn" onClick={() => setEditing(null)}>
              {t('common.cancel')}
            </button>
          ) : (
            <>
              {!editing?.id ? (
                <button type="button" className="btn btn-link" onClick={() => editing && setEditing({ ...editing, picking: true })}>
                  {t('prov.changePreset')}
                </button>
              ) : null}
              <span className="spacer" />
              <button type="button" className="btn" onClick={() => setEditing(null)}>
                {t('common.cancel')}
              </button>
              <button type="button" className="btn btn-primary" onClick={() => void save()}>
                {t('common.save')}
              </button>
            </>
          )
        }
      >
        <ErrorBanner error={error} />
        {editing?.picking ? (
          <div>
            <p className="muted">{builtin ? t('prov.pickHelpBuiltin') : t('prov.pickHelp')}</p>
            <ul className="catalog" data-testid="provider-catalog">
              {catalog.map((c) => (
                <li key={c.provider}>
                  <button type="button" className="catalog-item" onClick={() => pick(c)}>
                    <span className="catalog-name">{c.display_name}</span>
                    <span className="mono small muted">{c.base_url}</span>
                    <span className="catalog-meta">
                      {c.needs_key ? <Badge tone="warn">{t('prov.needsKey')}</Badge> : <Badge>{t('prov.noKey')}</Badge>}
                      {VIA_OPENAI_COMPAT.includes(c.provider) ? <Badge tone="accent">{t('prov.viaCompat')}</Badge> : null}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {editing && !editing.picking ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            {editing.value.provider && VIA_OPENAI_COMPAT.includes(editing.value.provider) ? (
              <div className="banner banner-info">{t('prov.compatNote', { name: providerLabel(catalog, editing.value.provider) })}</div>
            ) : null}
            <fieldset>
              <legend>{t('prov.connection')}</legend>
              <div className="form-grid">
                <Field label={t('prov.provider')}>
                  {(p) => (
                    <select {...p} value={editing.value.provider ?? 'openai_compatible'} onChange={(e) => set({ provider: e.target.value as ProviderKind })}>
                      {catalog.map((c) => (
                        <option key={c.provider} value={c.provider}>
                          {c.display_name}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
                <Field label={t('prov.displayName')}>
                  {(p) => <input {...p} value={editing.value.display_name ?? ''} placeholder="GPT-4o (prod)" onChange={(e) => set({ display_name: e.target.value })} />}
                </Field>
              </div>
              <Field label={t('up.name')} help={t('up.nameHelp')} error={msg('name')}>
                {(p) => <input {...p} className="mono" value={editing.value.name} onChange={(e) => set({ name: e.target.value })} required />}
              </Field>
              <Field label={t('up.baseUrl')} help={t('up.baseUrlHelp')} error={msg('base_url')}>
                {(p) => (
                  <input
                    {...p}
                    className="mono"
                    type="url"
                    placeholder={entry?.base_url ?? 'https://api.openai.com/v1'}
                    value={editing.value.base_url}
                    onChange={(e) => set({ base_url: e.target.value })}
                    required
                  />
                )}
              </Field>
              {editing.value.provider === 'azure_openai' ? (
                <Field label={t('prov.apiVersion')} help={t('prov.apiVersionHelp')}>
                  {(p) => <input {...p} className="mono" placeholder="2024-10-21" value={editing.value.api_version ?? ''} onChange={(e) => set({ api_version: e.target.value })} />}
                </Field>
              ) : null}
              <Field label={t('up.keyEnv')} help={`${t('up.keyEnvHelp')} ${t('up.keyEnvOrgs')}`} error={msg('api_key_env')}>
                {(p) => (
                  <input
                    {...p}
                    className="mono"
                    placeholder={entry?.env_hint ?? 'UPSTREAM_KEY_MAIN'}
                    autoComplete="off"
                    spellCheck={false}
                    value={editing.value.api_key_env}
                    onChange={(e) => set({ api_key_env: e.target.value.toUpperCase() })}
                  />
                )}
              </Field>
              {entry?.docs_url ? (
                <a className="small btn-link btn-icon-text" href={entry.docs_url} target="_blank" rel="noreferrer noopener">
                  <ExternalLink size={12} aria-hidden="true" />
                  <span>{t('prov.docs', { name: entry.display_name })}</span>
                </a>
              ) : null}
            </fieldset>
            <fieldset>
              <legend>{t('prov.modelsTitle')}</legend>
              <Field label={t('prov.defaultModel')} help={t('up.modelHelp')} error={msg('default_model')}>
                {(p) => (
                  <>
                    <input
                      {...p}
                      className="mono"
                      list="known-models"
                      value={editing.value.default_model ?? ''}
                      onChange={(e) => set({ default_model: e.target.value, model: e.target.value })}
                    />
                    <datalist id="known-models">
                      {[...new Set([...(entry?.models ?? []), ...(editing.value.models ?? [])])].map((m) => (
                        <option key={m} value={m} />
                      ))}
                    </datalist>
                  </>
                )}
              </Field>
              <ChipsInput
                label={t('prov.allowedModels')}
                help={t('prov.allowedHelp')}
                values={editing.value.models ?? []}
                suggestions={entry?.models ?? []}
                placeholder={t('prov.addModel')}
                onChange={(models) => set({ models })}
              />
            </fieldset>
            <fieldset>
              <legend>{t('prov.limits')}</legend>
              <div className="form-grid form-grid-3">
                <Field label={t('up.timeout')} error={msg('timeout_ms')}>
                  {(p) => <input {...p} type="number" min={1000} step={1000} value={editing.value.timeout_ms} onChange={(e) => set({ timeout_ms: Number(e.target.value) })} />}
                </Field>
                <Field label={t('prov.retries')} error={msg('retries')}>
                  {(p) => <input {...p} type="number" min={0} max={5} value={editing.value.retries ?? 0} onChange={(e) => set({ retries: Number(e.target.value) })} />}
                </Field>
                <Field label={t('prov.maxTokens')} help={t('prov.maxTokensHelp')} error={msg('max_tokens_cap')}>
                  {(p) => (
                    <input
                      {...p}
                      type="number"
                      min={1}
                      value={editing.value.max_tokens_cap ?? ''}
                      onChange={(e) => set({ max_tokens_cap: e.target.value === '' ? null : Number(e.target.value) })}
                    />
                  )}
                </Field>
              </div>
            </fieldset>
            <fieldset>
              <legend>{t('prov.headers')}</legend>
              <p className="muted small">{t('prov.headersHelp')}</p>
              {headers.map(([k, v], i) => (
                <div key={i} className="kv-row">
                  <input
                    className="mono"
                    aria-label={t('prov.headerName', { n: i + 1 })}
                    placeholder="OpenAI-Organization"
                    value={k}
                    onChange={(e) => setHeaders(headers.map((h, j) => (j === i ? [e.target.value, h[1]] : h)))}
                  />
                  <input
                    className="mono"
                    aria-label={t('prov.headerValue', { n: i + 1 })}
                    value={v}
                    onChange={(e) => setHeaders(headers.map((h, j) => (j === i ? [h[0], e.target.value] : h)))}
                  />
                  <button type="button" className="btn-icon" aria-label={t('prov.removeHeader', { n: i + 1 })} onClick={() => setHeaders(headers.filter((_, j) => j !== i))}>
                    <Trash2 size={14} aria-hidden="true" />
                  </button>
                </div>
              ))}
              {msg('headers') ? <small className="field-error">{msg('headers')}</small> : null}
              <button type="button" className="btn btn-small btn-icon-text" onClick={() => setHeaders([...headers, ['', '']])} disabled={headers.some(([k]) => k === '')}>
                <Plus size={14} aria-hidden="true" />
                <span>{t('prov.addHeader')}</span>
              </button>
            </fieldset>
            <fieldset>
              <legend>{t('prov.other')}</legend>
              <ChipsInput label={t('prov.tags')} values={editing.value.tags ?? []} onChange={(tags) => set({ tags })} normalize={(s) => s.trim().toLowerCase()} />
              <label className="check">
                <input type="checkbox" checked={editing.value.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
                <span>{t('up.enabled')}</span>
              </label>
            </fieldset>
            <button type="submit" hidden />
          </form>
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={deleting !== null}
        title={t('common.delete')}
        body={t('common.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteUpstream(org.id, deleting.id);
            notify(t('common.deleted'));
            await reloadAll();
          } catch (e) {
            notify(t('up.inUse', { error: errorText(e) }), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}

function TestResult({ r }: { r: ConnectionTest | 'running' | 'unavailable' | { error: string } | undefined }) {
  const { t } = useApp();
  const shown = r;
  if (!shown) return null;
  if (shown === 'running') return <span className="muted small">{t('prov.testing')}</span>;
  if (shown === 'unavailable') return <NotAvailable compact />;
  if ('ok' in shown) {
    return (
      <div className="test-result small" data-testid="test-result">
        <Badge tone={shown.ok ? 'ok' : 'danger'}>{shown.ok ? t('prov.testOk') : t('prov.testFailed')}</Badge>
        {shown.latency_ms !== null ? <span className="muted"> {shown.latency_ms} ms</span> : null}
        {shown.status ? <span className="muted"> · HTTP {shown.status}</span> : null}
        {shown.models_found.length > 0 ? <div className="muted">{t('prov.modelsFound', { count: shown.models_found.length, list: shown.models_found.slice(0, 5).join(', ') })}</div> : null}
        {shown.error ? <div className="field-error">{shown.error}</div> : null}
      </div>
    );
  }
  return <div className="field-error small">{shown.error}</div>;
}

function DefaultSelect({
  label,
  value,
  emptyLabel,
  upstreams,
  onChange,
  disabled,
}: {
  label: string;
  value: string | null;
  emptyLabel: string;
  upstreams: Upstream[];
  onChange: (id: string | null) => void;
  disabled?: boolean;
}) {
  return (
    <Field label={label}>
      {(p) => (
        <select {...p} value={value ?? ''} disabled={disabled} onChange={(e) => onChange(e.target.value || null)}>
          <option value="">{emptyLabel}</option>
          {upstreams.map((u) => (
            <option key={u.id} value={u.id}>
              {u.display_name ? `${u.display_name} (${u.name})` : u.name}
            </option>
          ))}
        </select>
      )}
    </Field>
  );
}
