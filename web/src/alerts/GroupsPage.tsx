// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// User groups (contract §3): named sets of org members that alert rules
// notify. Only members of the organization can be added.

import { Eye, Pencil, Plus, Trash2, UserPlus, UsersRound } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { authErrorText } from '../auth/errors';
import { DataTable, EmptyState, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, Loading, PageHeader } from '../components/ui';
import { nonEmpty, useApp, useOrg } from '../context';
import type { Member } from '../types';
import { MemberPicker, memberName, useAlertsApi, useMembers } from './shared';
import type { UserGroup } from './types';

/** The member ids of a group in either shape the server may send. */
export function groupMemberIds(g: UserGroup): string[] | null {
  if (Array.isArray(g.user_ids)) return g.user_ids;
  if (Array.isArray(g.members)) return g.members.map((m) => m.user_id);
  return null;
}

export function groupMemberCount(g: UserGroup): number | null {
  if (typeof g.member_count === 'number') return g.member_count;
  return groupMemberIds(g)?.length ?? null;
}

export default function GroupsPage() {
  const { t, notify } = useApp();
  const { org, can } = useOrg();
  const a = useAlertsApi();
  const writable = can('alerts.write');
  const { members } = useMembers();
  const [editing, setEditing] = useState<UserGroup | 'new' | null>(null);
  const [picking, setPicking] = useState<UserGroup | null>(null);
  const [deleting, setDeleting] = useState<UserGroup | null>(null);
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => a.listGroups(org.id, p), [a, org.id]);
  const paged = usePaged<UserGroup>(fetchPage);
  const byId = new Map(members.map((m) => [m.user_id, m]));

  const columns: Column<UserGroup>[] = [
    {
      key: 'name',
      header: t('common.name'),
      className: 'col-name',
      cell: (g) => (
        <strong className="ellipsis" title={g.name}>
          {g.name}
        </strong>
      ),
    },
    {
      key: 'description',
      header: t('alerts.group.description'),
      className: 'small',
      cell: (g) => (
        <span className="muted ellipsis group-desc" title={g.description ?? undefined}>
          {nonEmpty(g.description) ?? '—'}
        </span>
      ),
    },
    {
      key: 'members',
      header: t('alerts.group.members'),
      className: 'small',
      cell: (g) => {
        const ids = groupMemberIds(g);
        const n = groupMemberCount(g);
        const names = (ids ?? []).slice(0, 3).map((id) => {
          const m = byId.get(id) ?? g.members?.find((x) => x.user_id === id);
          return m ? memberName({ email: m.email ?? id, display_name: m.display_name ?? null }) : id.slice(0, 8);
        });
        return (
          <div className="cell-stack">
            <span className="nowrap">{n === null ? '—' : t('alerts.group.nMembers', { count: n })}</span>
            {names.length ? (
              <span className="muted ellipsis group-names" title={names.join(', ')}>
                {names.join(', ')}
                {ids && ids.length > 3 ? ` +${ids.length - 3}` : ''}
              </span>
            ) : null}
          </div>
        );
      },
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (g) => (
        <span className="icon-actions">
          <button
            type="button"
            className="btn btn-small btn-square"
            aria-label={writable ? t('alerts.group.membersOf', { name: g.name }) : t('alerts.viewOf', { name: g.name })}
            title={writable ? t('alerts.group.editMembers') : t('alerts.view')}
            onClick={() => setPicking(g)}
          >
            {writable ? <UserPlus size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
          </button>
          {writable ? (
            <>
              <button type="button" className="btn btn-small btn-square" aria-label={t('alerts.group.editOf', { name: g.name })} title={t('common.edit')} onClick={() => setEditing(g)}>
                <Pencil size={14} aria-hidden="true" />
              </button>
              <button type="button" className="btn btn-small btn-square btn-danger" aria-label={`${t('common.delete')} ${g.name}`} title={t('common.delete')} onClick={() => setDeleting(g)}>
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title={t('nav.alertGroups')}
        help={t('alerts.groups.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={() => setEditing('new')}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('alerts.group.new')}</span>
            </button>
          ) : null
        }
      />
      {!writable ? <p className="banner banner-info small">{t('alerts.readOnly')}</p> : null}
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(g) => g.id}
        testId="groups-table"
        feature={t('nav.alertGroups')}
        empty={
          <EmptyState
            icon={UsersRound}
            title={t('alerts.groups.empty')}
            body={t('alerts.groups.emptyBody')}
            action={
              writable ? (
                <button type="button" className="btn btn-primary" onClick={() => setEditing('new')}>
                  {t('alerts.group.new')}
                </button>
              ) : null
            }
          />
        }
      />
      {editing ? (
        <GroupDialog
          group={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async (g) => {
            const wasNew = editing === 'new';
            setEditing(null);
            await paged.reload();
            // A new group goes straight to its members.
            if (wasNew && g) setPicking(g);
          }}
        />
      ) : null}
      {picking ? (
        <MembersDialog
          key={picking.id}
          group={picking}
          members={members}
          readOnly={!writable}
          onClose={() => setPicking(null)}
          onSaved={async () => {
            setPicking(null);
            await paged.reload();
          }}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        title={t('alerts.group.delete')}
        body={t('alerts.group.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await a.deleteGroup(org.id, deleting.id);
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

function GroupDialog({ group, onClose, onSaved }: { group: UserGroup | null; onClose: () => void; onSaved: (g: UserGroup | null) => Promise<void> }) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [name, setName] = useState(group?.name ?? '');
  const [description, setDescription] = useState(group?.description ?? '');
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const nameError = touched && name.trim() === '' ? t('alerts.err.required') : undefined;
  const save = async () => {
    setTouched(true);
    if (name.trim() === '') return;
    setSaving(true);
    setError(null);
    try {
      const body = { name: name.trim(), description: description.trim() || null };
      const g = group ? await a.updateGroup(org.id, group.id, body) : await a.createGroup(org.id, body);
      notify(t('common.saved'));
      await onSaved(g);
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setSaving(false);
    }
  };
  return (
    <Dialog
      open
      title={group ? t('alerts.group.edit') : t('alerts.group.new')}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn btn-primary" disabled={saving} onClick={() => void save()}>
            {saving ? t('common.saving') : t('common.save')}
          </button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <ErrorBanner error={error} />
        <Field label={t('common.name')} error={nameError}>
          {(p) => <input {...p} value={name} maxLength={120} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label={t('alerts.group.description')}>{(p) => <textarea {...p} rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function MembersDialog({
  group,
  members,
  readOnly,
  onClose,
  onSaved,
}: {
  group: UserGroup;
  members: Member[];
  readOnly: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [selected, setSelected] = useState<string[] | null>(groupMemberIds(group));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // The list may not carry member ids: read the group itself.
  useEffect(() => {
    let live = true;
    a.getGroup(org.id, group.id).then(
      (g) => live && setSelected((s) => groupMemberIds(g) ?? s ?? []),
      () => live && setSelected((s) => s ?? []),
    );
    return () => {
      live = false;
    };
  }, [a, org.id, group.id]);
  const save = async () => {
    if (!selected) return;
    setSaving(true);
    setError(null);
    try {
      await a.setGroupMembers(org.id, group.id, selected);
      notify(t('alerts.group.membersSaved', { name: group.name, count: selected.length }));
      await onSaved();
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setSaving(false);
    }
  };
  return (
    <Dialog
      open
      title={t('alerts.group.membersTitle', { name: group.name })}
      onClose={onClose}
      footer={
        readOnly ? (
          <button type="button" className="btn" onClick={onClose}>
            {t('common.close')}
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={saving || selected === null} onClick={() => void save()}>
              {saving ? t('common.saving') : t('alerts.group.saveMembers')}
            </button>
          </>
        )
      }
    >
      <ErrorBanner error={error} />
      <p className="muted small">{t('alerts.group.membersHelp')}</p>
      {selected === null ? (
        <Loading />
      ) : (
        <MemberPicker label={t('alerts.group.members')} members={members} selected={selected} onChange={setSelected} disabled={readOnly} testId="group-members-picker" />
      )}
    </Dialog>
  );
}
