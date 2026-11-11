// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Key, Plus } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, PageHeader, useDebounced, Day, formatTime } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { ApiKey, CreatedApiKey, NewApiKey, RotatedApiKey } from '../types';

function limit(v: string): number | null {
  return v.trim() === '' ? null : Math.max(0, Math.trunc(Number(v)));
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

/** A quick client-side check of one allowed address: an IPv4/IPv6 address or CIDR. The control plane validates for real. */
export function validCidr(s: string): boolean {
  const [addr, bits, more] = s.trim().split('/');
  if (more !== undefined || !addr) return false;
  const v4 = IPV4.test(addr);
  const v6 = !v4 && addr.includes(':') && IPV6.test(addr) && addr.split('::').length <= 2;
  if (!v4 && !v6) return false;
  if (bits === undefined) return true;
  if (!/^\d{1,3}$/.test(bits)) return false;
  const n = Number(bits);
  return v4 ? n <= 32 : n <= 128;
}

/** The datetime-local value of now plus days, for the expiry field. */
export function expiryIn(days: number, now = new Date()): string {
  const d = new Date(now.getTime() + days * 24 * 3600 * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function KeysPage() {
  const { api, t, notify } = useApp();
  const { org, projects, can } = useOrg();
  const [q, setQ] = useState('');
  const [showRevoked, setShowRevoked] = useState(true);
  const query = useDebounced(q);
  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listApiKeysPage(org.id, { ...p, q: query || undefined, revoked: showRevoked ? undefined : false }),
    [api, org.id, query, showRevoked],
  );
  const needle = query.trim().toLowerCase();
  const paged = usePaged<ApiKey>(fetchPage, {
    clientFilter:
      needle || !showRevoked
        ? (k) => (showRevoked || !k.revoked) && (!needle || `${k.alias ?? ''} ${k.key_prefix}`.toLowerCase().includes(needle))
        : undefined,
  });
  const reload = paged.reload;
  const [form, setForm] = useState<{ alias: string; project: string; rpm: string; tpm: string; expires: string; cidrs: string[] } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [secret, setSecret] = useState<CreatedApiKey | RotatedApiKey | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const [rotating, setRotating] = useState<{ key: ApiKey; overlap: string } | null>(null);
  const [rotateError, setRotateError] = useState<string | null>(null);
  // The org's maximum key lifetime (security policy); null: none or unknown.
  const [maxDays, setMaxDays] = useState<number | null>(null);
  useEffect(() => {
    api.getOrgSecurity(org.id).then(
      (s) => setMaxDays(s.api_key_max_lifetime_days ?? null),
      () => setMaxDays(null),
    );
  }, [api, org.id]);

  const create = async () => {
    if (!form) return;
    setFormError(null);
    const bad = form.cidrs.find((c) => !validCidr(c));
    if (bad !== undefined) {
      setFormError(t('keys.cidrInvalid', { value: bad }));
      return;
    }
    try {
      const input: NewApiKey = { alias: form.alias, project_id: form.project || null, rpm_limit: limit(form.rpm), tpm_limit: limit(form.tpm) };
      if (form.expires) input.expires_at = new Date(form.expires).toISOString();
      if (form.cidrs.length > 0) input.allowed_cidrs = form.cidrs;
      const created = await api.createApiKey(org.id, input);
      setForm(null);
      setSecret(created);
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    }
  };

  const rotate = async () => {
    if (!rotating) return;
    setRotateError(null);
    const overlap = Number(rotating.overlap);
    if (!Number.isFinite(overlap) || overlap < 0 || overlap > 720) {
      setRotateError(t('keys.overlapError'));
      return;
    }
    try {
      const r = await api.rotateApiKey(org.id, rotating.key.key_prefix, { overlap_hours: overlap });
      setRotating(null);
      setSecret(r);
      await reload();
    } catch (e) {
      setRotateError(errorText(e));
    }
  };

  const projectName = (id: string | null) => (id ? (projects.find((p) => p.id === id)?.name ?? id) : '—');
  const writable = can('api_keys.manage');

  const columns: Column<ApiKey>[] = [
    { key: 'alias', header: t('keys.alias'), className: 'col-name', cell: (k) => <span className="ellipsis" title={k.alias ?? undefined}>{k.alias ?? '—'}</span> },
    { key: 'prefix', header: t('keys.prefix'), className: 'mono', cell: (k) => `${k.key_prefix}…` },
    { key: 'project', header: t('keys.project'), cell: (k) => projectName(k.project_id) },
    {
      key: 'limits',
      header: t('keys.limits'),
      className: 'nowrap small',
      cell: (k) => (
        <div className="cell-stack">
          <span>{t('keys.rpmShort', { n: k.rpm_limit ?? '—' })}</span>
          <span className="muted">{t('keys.tpmShort', { n: k.tpm_limit ?? '—' })}</span>
        </div>
      ),
    },
    {
      key: 'addresses',
      header: t('keys.addresses'),
      className: 'small col-wide-only',
      cell: (k) => (k.allowed_cidrs?.length ? <span className="mono" title={k.allowed_cidrs.join(', ')}>{t('keys.addressesCount', { n: k.allowed_cidrs.length })}</span> : <span className="muted">{t('keys.anyAddress')}</span>),
    },
    { key: 'created', header: t('common.created'), className: 'nowrap small col-wide-only', cell: (k) => <Day value={k.created_at} /> },
    { key: 'expires', header: t('keys.expires'), className: 'nowrap small', cell: (k) => (k.expires_at ? <Day value={k.expires_at} /> : t('keys.never')) },
    {
      key: 'status',
      header: t('keys.status'),
      cell: (k) =>
        k.revoked ? (
          <Badge tone="off">{t('keys.revoked')}</Badge>
        ) : k.rotated_to ? (
          <Badge tone="warn" title={t('keys.rotatedTo', { prefix: k.rotated_to })}>
            {t('keys.rotated')}
          </Badge>
        ) : (
          <Badge tone="ok">{t('keys.active')}</Badge>
        ),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (k) =>
        !k.revoked && writable ? (
          <>
            {!k.rotated_to ? (
              <button type="button" className="btn btn-small" aria-label={`${t('keys.rotate')} ${k.key_prefix}`} onClick={() => setRotating({ key: k, overlap: '24' })}>
                {t('keys.rotate')}
              </button>
            ) : null}{' '}
            <button type="button" className="btn btn-small btn-danger" aria-label={`${t('keys.revoke')} ${k.key_prefix}`} onClick={() => setRevoking(k)}>
              {t('keys.revoke')}
            </button>
          </>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('keys.title')}
        help={t('keys.help')}
        actions={
          writable ? (
            <button
              type="button"
              className="btn btn-primary btn-icon-text"
              onClick={() => setForm({ alias: '', project: '', rpm: '', tpm: '', expires: maxDays ? expiryIn(maxDays) : '', cidrs: [] })}
            >
              <Plus size={16} aria-hidden="true" />
              <span>{t('keys.new')}</span>
            </button>
          ) : null
        }
      />
      {maxDays ? <p className="banner banner-info">{t('keys.maxLifetime', { days: maxDays })}</p> : null}
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(k) => k.key_prefix}
        rowClassName={(k) => (k.revoked ? 'row-muted' : '')}
        testId="keys-table"
        toolbar={
          <>
            <SearchBox value={q} onChange={setQ} label={t('keys.search')} />
            <label className="check">
              <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} />
              <span>{t('keys.showRevoked')}</span>
            </label>
          </>
        }
        empty={<EmptyState icon={Key} title={t('keys.emptyTitle')} body={t('keys.emptyBody')} />}
      />

      <Dialog
        open={form !== null}
        title={t('keys.new')}
        onClose={() => setForm(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setForm(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void create()}>
              {t('common.create')}
            </button>
          </>
        }
      >
        <ErrorBanner error={formError} />
        {form ? (
          <>
            <Field label={t('keys.alias')}>{(p) => <input {...p} value={form.alias} onChange={(e) => setForm({ ...form, alias: e.target.value })} />}</Field>
            <Field label={t('keys.project')}>
              {(p) => (
                <select {...p} value={form.project} onChange={(e) => setForm({ ...form, project: e.target.value })}>
                  <option value="">{t('common.none')}</option>
                  {projects.map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <div className="form-grid">
              <Field label={t('keys.rpm')} help={t('keys.limitHelp')}>
                {(p) => <input {...p} type="number" min={0} value={form.rpm} onChange={(e) => setForm({ ...form, rpm: e.target.value })} />}
              </Field>
              <Field label={t('keys.tpm')} help={t('keys.limitHelp')}>
                {(p) => <input {...p} type="number" min={0} value={form.tpm} onChange={(e) => setForm({ ...form, tpm: e.target.value })} />}
              </Field>
            </div>
            <Field label={t('keys.expires')} help={maxDays ? t('keys.expiresMaxHelp', { days: maxDays }) : undefined}>
              {(p) => <input {...p} type="datetime-local" value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })} />}
            </Field>
            <ChipsInput label={t('keys.addresses')} values={form.cidrs} onChange={(cidrs) => setForm({ ...form, cidrs })} placeholder="203.0.113.0/24" help={t('keys.addressesHelp')} />
          </>
        ) : null}
      </Dialog>

      <Dialog
        open={rotating !== null}
        title={t('keys.rotateTitle', { name: rotating?.key.alias ?? rotating?.key.key_prefix ?? '' })}
        onClose={() => setRotating(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setRotating(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void rotate()}>
              {t('keys.rotate')}
            </button>
          </>
        }
      >
        <ErrorBanner error={rotateError} />
        <p>{t('keys.rotateHelp')}</p>
        {rotating ? (
          <Field label={t('keys.overlap')} help={t('keys.overlapHelp')}>
            {(p) => <input {...p} type="number" min={0} max={720} value={rotating.overlap} onChange={(e) => setRotating({ ...rotating, overlap: e.target.value })} />}
          </Field>
        ) : null}
      </Dialog>

      <Dialog
        open={secret !== null}
        title={secret && 'rotated_from' in secret ? t('keys.rotatedTitle') : t('keys.secretTitle')}
        onClose={() => setSecret(null)}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => setSecret(null)}>
            {t('common.close')}
          </button>
        }
      >
        <p className="banner banner-warn">{t('keys.secretHelp')}</p>
        {secret && 'rotated_from' in secret ? <p className="small muted">{t('keys.oldKeyUntil', { prefix: secret.rotated_from, when: formatTime(secret.old_expires_at) })}</p> : null}
        <div className="secret-row">
          <code className="secret" data-testid="new-key-secret">
            {secret?.key}
          </code>
          {secret ? <CopyButton text={secret.key} /> : null}
        </div>
      </Dialog>

      <ConfirmDialog
        open={revoking !== null}
        title={t('keys.revoke')}
        body={t('keys.confirmRevoke', { name: revoking?.alias ?? revoking?.key_prefix ?? '' })}
        confirmLabel={t('keys.revoke')}
        danger
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await api.revokeApiKey(org.id, revoking.key_prefix);
            await reload();
          } catch (e) {
            notify(errorText(e), 'error');
          }
          setRevoking(null);
        }}
      />
    </div>
  );
}
