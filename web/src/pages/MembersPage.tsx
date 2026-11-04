// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Members and invites of the organization (identity contract §4).

import { LogOut, Mail, ShieldOff, Trash2, UserPlus, Users } from 'lucide-react';
import { useCallback, useId, useState, type ReactNode } from 'react';
import { methodLabel, useLoginProviders } from '../auth/methods';
import { canManageMember, grantableRoles } from '../auth/permissions';
import { Badge, DataTable, EmptyState, SearchBox, type Column, type Tone } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, PageHeader, useDebounced, RelativeTime, Day } from '../components/ui';
import { authErrorText } from '../auth/errors';
import { nonEmpty, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href } from '../router';
import { ROLES, type CreatedInvite, type Invite, type Member, type Role } from '../types';

type Pending =
  | { kind: 'role'; member: Member; role: Role }
  | { kind: 'remove'; member: Member }
  | { kind: 'resetMfa'; member: Member }
  | { kind: 'revokeSessions'; member: Member }
  | { kind: 'revokeInvite'; invite: Invite };

/** The acceptance page of an invite token (InvitePage). */
export function inviteLink(token: string): string {
  return `${window.location.origin}${href('invite')}?token=${encodeURIComponent(token)}`;
}

const STATUS_TONE:Record<Invite['status'], Tone> = { pending: 'accent', accepted: 'ok', revoked: 'off', expired: 'warn' };

export function MembersPage() {
  const { t } = useApp();
  const [tab, setTab] = useState<'members' | 'invites'>('members');
  const [inviting, setInviting] = useState(false);
  const [invitesVersion, setInvitesVersion] = useState(0);
  const { can } = useOrg();
  return (
    <div>
      <PageHeader
        title={t('members.title')}
        help={t('members.help')}
        actions={
          can('members.write') ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={() => setInviting(true)}>
              <UserPlus size={16} aria-hidden="true" />
              <span>{t('members.invite')}</span>
            </button>
          ) : null
        }
      />
      <div className="tabs" role="tablist" aria-label={t('members.title')}>
        {(['members', 'invites'] as const).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            id={`tab-${k}`}
            aria-selected={tab === k}
            aria-controls={`panel-${k}`}
            className={tab === k ? 'tab tab-active' : 'tab'}
            onClick={() => setTab(k)}
          >
            {t(k === 'members' ? 'members.tabMembers' : 'members.tabInvites')}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'members' ? <MembersTable /> : <InvitesTable key={invitesVersion} />}
      </div>
      <InviteDialog
        open={inviting}
        onClose={() => setInviting(false)}
        onCreated={() => {
          setTab('invites');
          setInvitesVersion((v) => v + 1);
        }}
      />
    </div>
  );
}

function MembersTable() {
  const { api, t, notify, me } = useApp();
  const { org, role: myRole, can } = useOrg();
  const providers = useLoginProviders();
  const [q, setQ] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const query = useDebounced(q);
  const [pending, setPending] = useState<Pending | null>(null);
  const roleId = useId();

  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => api.listMembers(org.id, { ...p, q: query || undefined, role: roleFilter || undefined }),
    [api, org.id, query, roleFilter],
  );
  const needle = query.trim().toLowerCase();
  const paged = usePaged<Member>(fetchPage, {
    clientFilter:
      needle || roleFilter
        ? (m) => (!roleFilter || m.role === roleFilter) && (!needle || `${m.email} ${m.display_name ?? ''}`.toLowerCase().includes(needle))
        : undefined,
  });
  const grantable = grantableRoles(myRole);

  const act = async (p: Pending) => {
    try {
      switch (p.kind) {
        case 'role':
          await api.setMemberRole(org.id, p.member.user_id, p.role);
          notify(t('members.roleChanged', { email: p.member.email, role: t(`org.role.${p.role}` as MessageKey) }));
          break;
        case 'remove':
          await api.removeMember(org.id, p.member.user_id);
          notify(t('members.removed', { email: p.member.email }));
          break;
        case 'resetMfa':
          await api.resetMemberMfa(org.id, p.member.user_id);
          notify(t('members.mfaReset', { email: p.member.email }));
          break;
        case 'revokeSessions':
          await api.revokeMemberSessions(org.id, p.member.user_id);
          notify(t('members.sessionsRevoked', { email: p.member.email }));
          break;
        default:
          return;
      }
      await paged.reload();
    } catch (e) {
      notify(authErrorText(e, t), 'error');
    }
    setPending(null);
  };

  const columns: Column<Member>[] = [
    {
      key: 'user',
      header: t('members.user'),
      cell: (m) => (
        <div className="user-cell">
          <span className="avatar avatar-sm" aria-hidden="true">
            {(nonEmpty(m.display_name) ?? m.email).slice(0, 1).toUpperCase()}
          </span>
          <div className="cell-stack">
            <strong>{nonEmpty(m.display_name) ?? m.email}</strong>
            {m.display_name ? <span className="muted small">{m.email}</span> : null}
          </div>
          {m.user_id === me?.id ? <Badge tone="accent">{t('members.you')}</Badge> : null}
          {m.disabled ? <Badge tone="off">{t('members.disabled')}</Badge> : null}
        </div>
      ),
    },
    {
      key: 'role',
      header: t('members.role'),
      cell: (m) =>
        can('members.write') && canManageMember(myRole, m.role) && m.user_id !== me?.id ? (
          <>
            <label className="sr-only" htmlFor={`role-${m.user_id}`}>
              {t('members.roleOf', { email: m.email })}
            </label>
            <select
              id={`role-${m.user_id}`}
              value={m.role}
              onChange={(e) => setPending({ kind: 'role', member: m, role: e.target.value as Role })}
            >
              {ROLES.filter((r) => grantable.includes(r) || r === m.role).map((r) => (
                <option key={r} value={r}>
                  {t(`org.role.${r}` as MessageKey)}
                </option>
              ))}
            </select>
          </>
        ) : (
          <Badge tone={m.role === 'owner' ? 'accent' : 'neutral'}>{t(`org.role.${m.role}` as MessageKey)}</Badge>
        ),
    },
    {
      key: 'mfa',
      header: t('members.mfa'),
      cell: (m) => <Badge tone={m.mfa_enabled ? 'ok' : 'warn'}>{m.mfa_enabled ? t('common.enabled') : t('members.mfaOff')}</Badge>,
    },
    {
      key: 'methods',
      header: t('members.methods'),
      cell: (m) => (
        <span className="badges">
          {m.login_methods.map((x) => (
            <Badge key={x} title={x}>
              {methodLabel(x, providers ?? [], t)}
            </Badge>
          ))}
        </span>
      ),
    },
    { key: 'last', header: t('members.lastLogin'), className: 'nowrap small', cell: (m) => <RelativeTime value={m.last_login_at} /> },
    { key: 'joined', header: t('members.joined'), className: 'nowrap small col-wide-only', cell: (m) => <Day value={m.joined_at} /> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (m) => {
        if (m.user_id === me?.id || !can('members.write') || !canManageMember(myRole, m.role)) return null;
        const btn = (label: string, icon: ReactNode, p: Pending, danger = false) => (
          <button type="button" className={`btn btn-small btn-square${danger ? ' btn-danger' : ''}`} aria-label={`${label}: ${m.email}`} title={label} onClick={() => setPending(p)}>
            {icon}
          </button>
        );
        return (
          <>
            {m.mfa_enabled && can('members.reset_mfa') ? btn(t('members.resetMfa'), <ShieldOff size={14} aria-hidden="true" />, { kind: 'resetMfa', member: m }) : null}
            {btn(t('members.revokeSessions'), <LogOut size={14} aria-hidden="true" />, { kind: 'revokeSessions', member: m })}
            {btn(t('members.remove'), <Trash2 size={14} aria-hidden="true" />, { kind: 'remove', member: m }, true)}
          </>
        );
      },
    },
  ];

  let confirm: { title: string; body: string; label: string; danger: boolean } | null = null;
  if (pending && pending.kind !== 'revokeInvite') {
    const email = pending.member.email;
    switch (pending.kind) {
      case 'role':
        confirm = {
          title: t('members.changeRole'),
          body: t('members.confirmRole', { email, role: t(`org.role.${pending.role}` as MessageKey) }),
          label: t('members.changeRole'),
          danger: false,
        };
        break;
      case 'remove':
        confirm = { title: t('members.remove'), body: t('members.confirmRemove', { email, org: org.name }), label: t('members.remove'), danger: true };
        break;
      case 'resetMfa':
        confirm = { title: t('members.resetMfa'), body: t('members.confirmResetMfa', { email }), label: t('members.resetMfa'), danger: true };
        break;
      case 'revokeSessions':
        confirm = { title: t('members.revokeSessions'), body: t('members.confirmRevokeSessions', { email }), label: t('members.revokeSessions'), danger: true };
        break;
    }
  }

  return (
    <>
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(m) => m.user_id}
        rowClassName={(m) => (m.disabled ? 'row-muted' : '')}
        testId="members-table"
        feature={t('members.title')}
        toolbar={
          <>
            <SearchBox value={q} onChange={setQ} label={t('members.search')} />
            <div className="field field-inline">
              <label htmlFor={roleId}>{t('members.role')}</label>
              <select id={roleId} value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {t(`org.role.${r}` as MessageKey)}
                  </option>
                ))}
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={Users} title={needle || roleFilter ? t('table.noMatch') : t('members.empty')} />}
      />
      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.title ?? ''}
        body={confirm?.body ?? ''}
        confirmLabel={confirm?.label ?? ''}
        danger={confirm?.danger}
        onClose={() => setPending(null)}
        onConfirm={() => (pending ? act(pending) : undefined)}
      />
    </>
  );
}

function InvitesTable() {
  const { api, t, notify } = useApp();
  const { org, can } = useOrg();
  const [revoking, setRevoking] = useState<Invite | null>(null);
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => api.listInvites(org.id, p), [api, org.id]);
  const paged = usePaged<Invite>(fetchPage);
  const columns: Column<Invite>[] = [
    { key: 'email', header: t('login.email'), cell: (i) => i.email },
    { key: 'role', header: t('members.role'), cell: (i) => <Badge>{t(`org.role.${i.role}` as MessageKey)}</Badge> },
    { key: 'status', header: t('members.status'), cell: (i) => <Badge tone={STATUS_TONE[i.status]}>{t(`invite.${i.status}` as MessageKey)}</Badge> },
    { key: 'expires', header: t('keys.expires'), className: 'nowrap small', cell: (i) => <Day value={i.expires_at} /> },
    { key: 'created', header: t('common.created'), className: 'nowrap small', cell: (i) => <Day value={i.created_at} /> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (i) =>
        i.status === 'pending' && can('members.write') ? (
          <button type="button" className="btn btn-small btn-danger" aria-label={`${t('invite.revoke')}: ${i.email}`} onClick={() => setRevoking(i)}>
            {t('invite.revoke')}
          </button>
        ) : null,
    },
  ];
  return (
    <>
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(i) => i.id}
        testId="invites-table"
        feature={t('members.tabInvites')}
        empty={<EmptyState icon={Mail} title={t('invite.empty')} />}
      />
      <ConfirmDialog
        open={revoking !== null}
        title={t('invite.revoke')}
        body={t('invite.confirmRevoke', { email: revoking?.email ?? '' })}
        confirmLabel={t('invite.revoke')}
        danger
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await api.revokeInvite(org.id, revoking.id);
            await paged.reload();
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setRevoking(null);
        }}
      />
    </>
  );
}

function InviteDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const { api, t } = useApp();
  const { org, role } = useOrg();
  const [email, setEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<Role>('member');
  const [ttl, setTtl] = useState('168');
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedInvite | null>(null);
  const close = () => {
    setEmail('');
    setError(null);
    setCreated(null);
    onClose();
  };
  const submit = async () => {
    setError(null);
    try {
      setCreated(await api.createInvite(org.id, email.trim(), inviteRole, Number(ttl) || undefined));
      onCreated();
    } catch (e) {
      setError(authErrorText(e, t));
    }
  };
  return (
    <Dialog
      open={open}
      title={created ? t('invite.createdTitle') : t('members.invite')}
      onClose={close}
      footer={
        created ? (
          <button type="button" className="btn btn-primary" onClick={close}>
            {t('common.close')}
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={close}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void submit()}>
              {t('invite.send')}
            </button>
          </>
        )
      }
    >
      <ErrorBanner error={error} />
      {created ? (
        <>
          <p className="banner banner-warn">{t('invite.tokenHelp', { email: created.email })}</p>
          <span className="muted small">{t('invite.link')}</span>
          <div className="secret-row">
            <code className="secret" data-testid="invite-link">
              {inviteLink(created.token)}
            </code>
            <CopyButton text={inviteLink(created.token)} />
          </div>
          <span className="muted small">{t('invite.token')}</span>
          <div className="secret-row">
            <code className="secret" data-testid="invite-token">
              {created.token}
            </code>
          </div>
        </>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Field label={t('login.email')}>{(p) => <input {...p} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />}</Field>
          <div className="form-grid">
            <Field label={t('members.role')}>
              {(p) => (
                <select {...p} value={inviteRole} onChange={(e) => setInviteRole(e.target.value as Role)}>
                  {grantableRoles(role).map((r) => (
                    <option key={r} value={r}>
                      {t(`org.role.${r}` as MessageKey)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field label={t('invite.ttl')} help={t('invite.ttlHelp')}>
              {(p) => <input {...p} type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(e.target.value)} />}
            </Field>
          </div>
          <button type="submit" hidden />
        </form>
      )}
    </Dialog>
  );
}
