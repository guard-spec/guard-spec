// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Model providers (identity contract §6): the upstreams of the gateway, with
// a provider preset, allowed models, a default model, extra headers, limits
// and a connection test. Keys stay in the gateway environment (api_key_env).

import { Cpu, ExternalLink, Pencil, Plus, Trash2, X, Zap } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { isNotFound } from '../api';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, NotAvailable, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { authErrorText } from '../auth/errors';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, useDebounced } from '../components/ui';
import { nonEmpty, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import type { CatalogEntry, ConnectionTest, ProviderKind, Upstream, UpstreamInput } from '../types';
import { BUILTIN_CATALOG, providerLabel, slugName, validateProvider, viaOpenAICompat, type ProviderError } from './providerCatalog';

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
  if (!body.api_version) delete body.api_version;
  if (!body.display_name) delete body.display_name;
  return body;
}


export function ProvidersPage() {
  const { api, t, notify } = useApp();
  const { org, projects, upstreams, upstreamError, reload, setOrg, can, role } = useOrg();
  // The connection test is owner-only on the control plane (it may send a key); an unknown role tries.
  const canTest = role === null || role === 'owner';
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
      const m = authErrorText(e, t);
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
      setTests((s) => ({ ...s, [u.id]: isNotFound(e) ? 'unavailable' : { error: authErrorText(e, t) } }));
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
      notify(authErrorText(e, t), 'error');
    }
  };

  const set = (patch: Partial<UpstreamInput>) => {
    if ('api_key_env' in patch) setKeyEnvError(null);
    if (editing) setEditing({ ...editing, value: { ...editing.value, ...patch } });
  };

  const pick = (c: CatalogEntry) => {
    if (!editing) return;
    const name = nonEmpty(editing.value.name) ?? slugName(c.id === 'openai_compatible' ? '' : c.display_name);
    setEditing({
      ...editing,
      picking: false,
      value: {
        ...editing.value,
        provider: c.id,
        name,
        display_name: nonEmpty(editing.value.display_name) ?? (c.id === 'openai_compatible' ? '' : c.display_name),
        base_url: c.default_base_url,
        api_key_env: c.key_required ? (c.key_env_hint ?? '') : editing.value.api_key_env,
        default_model: c.known_models[0] ?? '',
        model: c.known_models[0] ?? '',
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
  const entry = editing ? catalog.find((c) => c.id === editing.value.provider) : undefined;

  const columns: Column<Upstream>[] = [
    {
      key: 'name',
      header: t('up.name'),
      className: 'col-name',
      cell: (u) => (
        <div className="cell-stack">
          <span className="name-line">
            <strong className="mono ellipsis" title={u.name}>
              {u.name}
            </strong>
            {org.default_upstream_id === u.id ? <Badge tone="accent">{t('flow.defaultBadge')}</Badge> : null}
          </span>
          <span className="name-line">
            <Badge>{providerLabel(catalog, u.provider)}</Badge>
            {u.display_name ? (
              <span className="muted small ellipsis" title={u.display_name}>
                {u.display_name}
              </span>
            ) : null}
          </span>
        </div>
      ),
    },
    {
      key: 'url',
      header: t('up.baseUrl'),
      className: 'col-url',
      cell: (u) => (
        <span className="mono small ellipsis" title={u.base_url}>
          {u.base_url}
        </span>
      ),
    },
    {
      key: 'model',
      header: t('prov.models'),
      className: 'col-model',
      cell: (u) => {
        const m = nonEmpty(u.default_model) ?? nonEmpty(u.model);
        return (
          <div className="cell-stack">
            <span className="mono small ellipsis" title={m}>
              {m ?? '—'}
            </span>
            <span className="muted small nowrap">{u.models && u.models.length > 0 ? t('prov.allowedCount', { count: u.models.length }) : t('prov.passThrough')}</span>
          </div>
        );
      },
    },
    {
      key: 'env',
      header: t('prov.keyEnvShort'),
      className: 'col-env',
      cell: (u) => (
        <span className="mono small ellipsis" title={u.api_key_env ? `$${u.api_key_env}` : undefined}>
          {u.api_key_env ? `$${u.api_key_env}` : '—'}
        </span>
      ),
    },
    {
      key: 'status',
      header: t('prov.status'),
      className: 'nowrap',
      cell: (u) => (
        <span className="badges">
          <Badge tone={u.enabled ? 'ok' : 'off'}>{u.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
          <TestBadge r={tests[u.id]} />
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (u) => (
        <span className="icon-actions">
          {canTest ? (
            <button
              type="button"
              className="btn btn-small btn-square"
              aria-label={t('prov.testOf', { name: u.name })}
              title={t('prov.test')}
              disabled={tests[u.id] === 'running'}
              onClick={() => void test(u)}
            >
              <Zap size={14} aria-hidden="true" />
            </button>
          ) : null}
          {writable ? (
            <>
              <button
                type="button"
                className="btn btn-small btn-square"
                aria-label={t('up.edit', { name: u.name })}
                title={t('common.edit')}
                onClick={() => {
                  setTouched(false);
                  setError(null);
                  setKeyEnvError(null);
                  setEditing({ id: u.id, value: toInput(u), picking: false });
                }}
              >
                <Pencil size={14} aria-hidden="true" />
              </button>
              <button
                type="button"
                className="btn btn-small btn-square btn-danger"
                aria-label={`${t('common.delete')} ${u.name}`}
                title={t('common.delete')}
                onClick={() => setDeleting(u)}
              >
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </>
          ) : null}
        </span>
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
        rowDetail={(u) => {
          const r = tests[u.id];
          return r && r !== 'running' ? <TestResult r={r} name={u.name} onDismiss={() => setTests((s) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== u.id)))} /> : null;
        }}
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
                <li key={c.id}>
                  <button type="button" className="catalog-item" onClick={() => pick(c)}>
                    <span className="catalog-name">{c.display_name}</span>
                    <span className="mono small muted">{c.default_base_url}</span>
                    <span className="catalog-meta">
                      {c.key_required ? <Badge tone="warn">{t('prov.needsKey')}</Badge> : <Badge>{t('prov.noKey')}</Badge>}
                      {c.openai_compatible_endpoint ? <Badge tone="accent">{t('prov.viaCompat')}</Badge> : null}
                    </span>
                    {c.notes ? <span className="small muted catalog-notes">{c.notes}</span> : null}
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
            {viaOpenAICompat(catalog, editing.value.provider) ? (
              <div className="banner banner-info">{t('prov.compatNote', { name: providerLabel(catalog, editing.value.provider) })}</div>
            ) : null}
            <fieldset>
              <legend>{t('prov.connection')}</legend>
              <div className="form-grid">
                <Field label={t('prov.provider')}>
                  {(p) => (
                    <select {...p} value={editing.value.provider ?? 'openai_compatible'} onChange={(e) => set({ provider: e.target.value as ProviderKind })}>
                      {catalog.map((c) => (
                        <option key={c.id} value={c.id}>
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
                    placeholder={entry?.default_base_url ?? 'https://api.openai.com/v1'}
                    value={editing.value.base_url}
                    onChange={(e) => set({ base_url: e.target.value })}
                    required
                  />
                )}
              </Field>
              {editing.value.provider === 'azure_openai' || entry?.needs_api_version ? (
                <Field label={t('prov.apiVersion')} help={t('prov.apiVersionHelp')}>
                  {(p) => <input {...p} className="mono" placeholder="2024-10-21" value={editing.value.api_version ?? ''} onChange={(e) => set({ api_version: e.target.value })} />}
                </Field>
              ) : null}
              <Field label={t('up.keyEnv')} help={`${t('up.keyEnvHelp')} ${t('up.keyEnvOrgs')}`} error={msg('api_key_env')}>
                {(p) => (
                  <input
                    {...p}
                    className="mono"
                    placeholder={entry?.key_env_hint ?? 'UPSTREAM_KEY_MAIN'}
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
              {entry?.notes ? <p className="small muted">{entry.notes}</p> : null}
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
                      {[...new Set([...(entry?.known_models ?? []), ...(editing.value.models ?? [])])].map((m) => (
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
                suggestions={entry?.known_models ?? []}
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
            notify(t('up.inUse', { error: authErrorText(e, t) }), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}

type TestState = ConnectionTest | 'running' | 'unavailable' | { error: string };

/** The short outcome of a connection test, in the Status column. */
function TestBadge({ r }: { r: TestState | undefined }) {
  const { t } = useApp();
  if (!r) return null;
  if (r === 'running') return <Badge>{t('prov.testing')}</Badge>;
  if (r === 'unavailable') return null;
  if ('ok' in r) return <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? t('prov.testOk') : t('prov.testFailed')}</Badge>;
  return <Badge tone="danger">{t('prov.testFailed')}</Badge>;
}

/** The full outcome of a connection test, in a line under the provider's row. */
function TestResult({ r, name, onDismiss }: { r: Exclude<TestState, 'running'>; name: string; onDismiss: () => void }) {
  const { t } = useApp();
  let body;
  if (r === 'unavailable') body = <NotAvailable compact />;
  else if ('ok' in r) {
    const models = r.models_found ?? [];
    body = (
      <>
        <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? t('prov.testOk') : t('prov.testFailed')}</Badge>
        {r.latency_ms !== null ? <span className="muted"> {r.latency_ms} ms</span> : null}
        {r.status ? <span className="muted"> · HTTP {r.status}</span> : null}
        {models.length > 0 ? <span className="muted"> · {t('prov.modelsFound', { count: models.length, list: models.slice(0, 8).join(', ') })}</span> : null}
        {r.key_sent === false ? (
          <div className="test-note" data-testid="key-not-sent">
            {nonEmpty(r.note) ?? t('prov.keyNotSent')}
          </div>
        ) : null}
        {nonEmpty(r.error) ? <div className="field-error">{r.error}</div> : null}
      </>
    );
  } else body = <span className="field-error">{r.error}</span>;
  return (
    <div className="test-result small" data-testid="test-result" role="status">
      <strong className="test-title">{t('prov.testResultOf', { name })}</strong>
      <div className="test-body">{body}</div>
      <button type="button" className="btn-icon" aria-label={t('common.dismiss')} onClick={onDismiss}>
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  );
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
