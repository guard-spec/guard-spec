// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Users of the instance (identity contract §4), for instance admins.

import { Pencil, Plus, Trash2, UserCog } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Badge, DataTable, EmptyState, InstanceAdminOnly, SearchBox, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, formatTime, PageHeader, useDebounced } from '../components/ui';
import { authErrorText } from '../auth/errors';
import { nonEmpty, useApp } from '../context';
import type { InstanceUser } from '../types';

interface Draft {
  id: string | null;
  email: string;
  display_name: string;
  password: string;
  disabled: boolean;
  is_instance_admin: boolean;
}

export default function AdminUsersPage() {
  const { api, t, notify, me } = useApp();
  const [q, setQ] = useState('');
  const query = useDebounced(q);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<InstanceUser | null>(null);
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => api.listUsers({ ...p, q: query || undefined }), [api, query]);
  const needle = query.trim().toLowerCase();
  const paged = usePaged<InstanceUser>(fetchPage, {
    clientFilter: needle ? (u) => `${u.email} ${u.display_name ?? ''}`.toLowerCase().includes(needle) : undefined,
  });

  if (me && !me.is_instance_admin) {
    return (
      <div>
        <PageHeader title={t('admin.usersTitle')} />
        <InstanceAdminOnly />
      </div>
    );
  }

  const save = async () => {
    if (!draft) return;
    setError(null);
    try {
      if (draft.id) {
        await api.updateUser(draft.id, { display_name: draft.display_name || null, disabled: draft.disabled, is_instance_admin: draft.is_instance_admin });
      } else {
        if (draft.password && draft.password.length < 12) {
          setError(t('account.passwordShort'));
          return;
        }
        await api.createUser({ email: draft.email.trim(), display_name: draft.display_name, ...(draft.password ? { password: draft.password } : {}) });
      }
      setDraft(null);
      notify(t('common.saved'));
      await paged.reload();
    } catch (e) {
      setError(authErrorText(e, t));
    }
  };

  const columns: Column<InstanceUser>[] = [
    {
      key: 'user',
      header: t('members.user'),
      cell: (u) => (
        <div className="cell-stack">
          <strong>{nonEmpty(u.display_name) ?? u.email}</strong>
          {u.display_name ? <span className="muted small">{u.email}</span> : null}
        </div>
      ),
    },
    {
      key: 'flags',
      header: t('admin.flags'),
      cell: (u) => (
        <span className="badges">
          {u.is_instance_admin ? <Badge tone="accent">{t('profile.instanceAdmin')}</Badge> : null}
          {u.disabled ? <Badge tone="off">{t('members.disabled')}</Badge> : <Badge tone="ok">{t('admin.active')}</Badge>}
          {u.mfa_enabled ? <Badge tone="ok">2FA</Badge> : null}
        </span>
      ),
    },
    { key: 'last', header: t('members.lastLogin'), className: 'nowrap small', cell: (u) => formatTime(u.last_login_at) },
    { key: 'created', header: t('common.created'), className: 'nowrap small', cell: (u) => formatTime(u.created_at) },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (u) => (
        <>
          <button
            type="button"
            className="btn btn-small btn-icon-text"
            aria-label={`${t('common.edit')}: ${u.email}`}
            onClick={() => {
              setError(null);
              setDraft({ id: u.id, email: u.email, display_name: u.display_name ?? '', password: '', disabled: u.disabled, is_instance_admin: u.is_instance_admin });
            }}
          >
            <Pencil size={14} aria-hidden="true" />
            <span>{t('common.edit')}</span>
          </button>
          {u.id !== me?.id ? (
            <button type="button" className="btn btn-small btn-danger btn-icon-text" aria-label={`${t('common.delete')}: ${u.email}`} onClick={() => setDeleting(u)}>
              <Trash2 size={14} aria-hidden="true" />
              <span>{t('common.delete')}</span>
            </button>
          ) : null}
        </>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('admin.usersTitle')}
        help={t('admin.usersHelp')}
        actions={
          <button
            type="button"
            className="btn btn-primary btn-icon-text"
            onClick={() => {
              setError(null);
              setDraft({ id: null, email: '', display_name: '', password: '', disabled: false, is_instance_admin: false });
            }}
          >
            <Plus size={16} aria-hidden="true" />
            <span>{t('admin.newUser')}</span>
          </button>
        }
      />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(u) => u.id}
        rowClassName={(u) => (u.disabled ? 'row-muted' : '')}
        testId="users-table"
        feature={t('admin.usersTitle')}
        toolbar={<SearchBox value={q} onChange={setQ} label={t('members.search')} />}
        empty={<EmptyState icon={UserCog} title={needle ? t('table.noMatch') : t('admin.noUsers')} />}
      />
      <Dialog
        open={draft !== null}
        title={draft?.id ? t('admin.editUser', { email: draft.email }) : t('admin.newUser')}
        onClose={() => setDraft(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setDraft(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void save()}>
              {t('common.save')}
            </button>
          </>
        }
      >
        <ErrorBanner error={error} />
        {draft ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            {draft.id ? null : (
              <Field label={t('login.email')}>{(p) => <input {...p} type="email" required value={draft.email} onChange={(e) => setDraft({ ...draft, email: e.target.value })} />}</Field>
            )}
            <Field label={t('account.displayName')}>
              {(p) => <input {...p} value={draft.display_name} onChange={(e) => setDraft({ ...draft, display_name: e.target.value })} />}
            </Field>
            {draft.id ? (
              <>
                <label className="check">
                  <input type="checkbox" checked={draft.disabled} disabled={draft.id === me?.id} onChange={(e) => setDraft({ ...draft, disabled: e.target.checked })} />
                  <span>{t('admin.disabled')}</span>
                </label>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={draft.is_instance_admin}
                    disabled={draft.id === me?.id}
                    onChange={(e) => setDraft({ ...draft, is_instance_admin: e.target.checked })}
                  />
                  <span>{t('profile.instanceAdmin')}</span>
                </label>
              </>
            ) : (
              <Field label={t('admin.initialPassword')} help={t('admin.initialPasswordHelp')}>
                {(p) => (
                  <input {...p} type="password" autoComplete="new-password" minLength={12} value={draft.password} onChange={(e) => setDraft({ ...draft, password: e.target.value })} />
                )}
              </Field>
            )}
            <button type="submit" hidden />
          </form>
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        title={t('admin.deleteUser')}
        body={t('admin.confirmDelete', { email: deleting?.email ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await api.deleteUser(deleting.id);
            notify(t('common.deleted'));
            await paged.reload();
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}
