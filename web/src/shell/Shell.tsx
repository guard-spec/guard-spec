// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The app shell: a grouped sidebar (a drawer on narrow screens), the header
// with breadcrumbs, and the profile menu at the bottom of the sidebar.

import { ArrowLeftRight, ChevronDown, ChevronRight, ChevronsUpDown, LogOut, Menu, PanelLeftClose, PanelLeftOpen, UserRound, X } from 'lucide-react';
import { useCallback, useEffect, useId, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { NotificationBell } from '../alerts/notifications';
import { nonEmpty, useApp } from '../context';
import type { MessageKey } from '../i18n';
import { NAV, navEntry, type NavGroup } from '../nav';
import { href, navigate, type Route } from '../router';
import { prefs } from '../session';
import type { Org } from '../types';
import { Preferences } from './Preferences';

const PAGE_TITLES: Partial<Record<Route, MessageKey>> = {
  account: 'nav.account',
  orgs: 'org.title',
};

function readCollapsedGroups(): string[] {
  try {
    const v = JSON.parse(prefs.get('navCollapsed') ?? '[]') as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function linkClick(route: Route, after?: () => void) {
  return (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(route);
    after?.();
  };
}

export function Shell({
  children,
  route,
  org,
  visible,
}: {
  children: ReactNode;
  route: Route;
  org: Org | null;
  /** Whether a nav item shows (capability and instance admin checks). */
  visible: (group: NavGroup, capability: string | undefined) => boolean;
}) {
  const { t } = useApp();
  const [rail, setRail] = useState(() => prefs.get('sidebar') === 'rail');
  const [drawer, setDrawer] = useState(false);
  const [collapsed, setCollapsed] = useState<string[]>(readCollapsedGroups);
  const menuButton = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);

  const closeDrawer = useCallback(() => {
    setDrawer(false);
    menuButton.current?.focus();
  }, []);

  useEffect(() => {
    if (!drawer) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDrawer();
    };
    window.addEventListener('keydown', onKey);
    sidebarRef.current?.querySelector<HTMLElement>('a[aria-current="page"], nav a')?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [drawer, closeDrawer]);

  // The nav scrolls on its own: keep the current page in view.
  useEffect(() => {
    sidebarRef.current?.querySelector<HTMLElement>('.nav a[aria-current="page"]')?.scrollIntoView({ block: 'nearest' });
  }, [route, drawer]);

  const toggleRail = () => {
    setRail((r) => {
      prefs.set('sidebar', r ? 'full' : 'rail');
      return !r;
    });
  };
  const toggleGroup = (id: string) => {
    setCollapsed((c) => {
      const next = c.includes(id) ? c.filter((x) => x !== id) : [...c, id];
      prefs.set('navCollapsed', JSON.stringify(next));
      return next;
    });
  };

  const entry = navEntry(route);
  const titleKey = entry?.item.label ?? PAGE_TITLES[route];

  return (
    <div className={['shell', rail ? 'shell-rail' : '', drawer ? 'shell-drawer-open' : ''].join(' ')}>
      <a className="skip-link" href="#main">
        {t('app.skip')}
      </a>
      {drawer ? <div className="drawer-backdrop" aria-hidden="true" onClick={closeDrawer} /> : null}
      <aside className="sidebar" ref={sidebarRef} aria-label={t('app.sidebar')}>
        <div className="sidebar-top">
          <a
            className="brand"
            href={href('dashboard')}
            onClick={linkClick('dashboard', () => setDrawer(false))}
            aria-label={`${t('app.title')} ${t('app.subtitle')}`}
          >
            <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
              <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" className="brand-shield" />
              <path d="m10 16 4 4 8-9" className="brand-check" />
            </svg>
            <span className="brand-text">
              <strong>{t('app.title')}</strong>
              <span className="muted">{t('app.subtitle')}</span>
            </span>
          </a>
          <button
            type="button"
            className="btn-icon nav-rail-toggle"
            onClick={toggleRail}
            aria-pressed={rail}
            aria-label={rail ? t('app.expand') : t('app.collapse')}
            title={rail ? t('app.expand') : t('app.collapse')}
          >
            {rail ? <PanelLeftOpen size={16} aria-hidden="true" /> : <PanelLeftClose size={16} aria-hidden="true" />}
          </button>
          <button type="button" className="btn-icon drawer-close" aria-label={t('app.closeMenu')} onClick={closeDrawer}>
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        {org ? (
          <a
            className="org-switch"
            href={href('orgs')}
            onClick={linkClick('orgs', () => setDrawer(false))}
            title={`${t('app.switchOrg')}: ${org.name}`}
          >
            <span className="org-avatar" aria-hidden="true">
              {org.name.slice(0, 1).toUpperCase()}
            </span>
            <span className="org-switch-text">
              <span className="muted small">{t('app.org')}</span>
              <strong>{org.name}</strong>
            </span>
            <ChevronsUpDown size={14} aria-hidden="true" className="org-switch-icon" />
            <span className="sr-only">{t('app.switchOrg')}</span>
          </a>
        ) : null}
        {org ? (
          <nav aria-label={t('app.mainNav')} className="nav">
            {NAV.map((g) => {
              const items = g.items.filter((i) => visible(g, i.capability));
              if (items.length === 0) return null;
              const open = rail || !collapsed.includes(g.id) || items.some((i) => i.route === route);
              const listId = `nav-${g.id}`;
              return (
                <div key={g.id} className="nav-group">
                  <button type="button" className="nav-group-toggle" aria-expanded={open} aria-controls={listId} onClick={() => toggleGroup(g.id)}>
                    <span>{t(g.label)}</span>
                    {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
                  </button>
                  <ul id={listId} hidden={!open}>
                    {items.map((n) => {
                      const Icon = n.icon;
                      const label = t(n.label);
                      return (
                        <li key={n.route}>
                          <a
                            href={href(n.route)}
                            aria-current={route === n.route ? 'page' : undefined}
                            title={rail ? label : undefined}
                            onClick={linkClick(n.route, () => setDrawer(false))}
                          >
                            <Icon size={16} aria-hidden="true" className="nav-icon" />
                            <span className="nav-label">{label}</span>
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </nav>
        ) : (
          <div className="spacer" />
        )}
        <div className="sidebar-foot">
          <ProfileMenu onNavigate={() => setDrawer(false)} />
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button
            ref={menuButton}
            type="button"
            className="btn-icon menu-button"
            aria-label={t('app.openMenu')}
            aria-expanded={drawer}
            onClick={() => setDrawer(true)}
          >
            <Menu size={18} aria-hidden="true" />
          </button>
          <nav aria-label={t('app.breadcrumbs')} className="breadcrumbs">
            <ol>
              {org ? (
                <li>
                  <a href={href('dashboard')} onClick={linkClick('dashboard')}>
                    {org.name}
                  </a>
                </li>
              ) : null}
              {entry ? <li className="muted">{t(entry.group.label)}</li> : null}
              {titleKey ? <li aria-current="page">{t(titleKey)}</li> : null}
            </ol>
          </nav>
          <div className="topbar-actions">
            <NotificationBell />
          </div>
        </header>
        <main id="main" className="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}

function initials(name: string): string {
  const parts = name.split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? '')).toUpperCase();
}

/** Where the profile panel goes: above the button, within the viewport (8px margins). */
export function panelPosition(r: { left: number; top: number }, vw: number, vh: number): { left: number; bottom: number; width: number } {
  const width = Math.min(288, vw - 16);
  const left = Math.max(8, Math.min(r.left, vw - width - 8));
  return { left, bottom: Math.max(8, vh - r.top + 6), width };
}

function ProfileMenu({ onNavigate }: { onNavigate: () => void }) {
  const { t, me, logout } = useApp();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const wrap = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState<{ left: number; bottom: number; width: number } | null>(null);

  useEffect(() => {
    if (!open) return;
    // The panel lives in document.body (the sidebar clips overflow): place it
    // above the button, inside the viewport.
    const place = () => {
      const r = button.current?.getBoundingClientRect();
      if (!r) return;
      setPos(panelPosition(r, window.innerWidth, window.innerHeight));
    };
    place();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        button.current?.focus();
      }
    };
    const onDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!wrap.current?.contains(target) && !panel.current?.contains(target)) setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('pointerdown', onDown);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('pointerdown', onDown);
      window.removeEventListener('resize', place);
    };
  }, [open]);

  useEffect(() => {
    if (open && pos) panel.current?.querySelector<HTMLElement>('a, button, select')?.focus();
  }, [open, pos]);

  const name = nonEmpty(me?.display_name) ?? nonEmpty(me?.email) ?? t('profile.you');
  return (
    <div className="profile" ref={wrap}>
      {open && pos
        ? createPortal(
        <div
          id={panelId}
          ref={panel}
          className="profile-panel"
          role="group"
          aria-label={t('profile.menu')}
          style={{ left: pos.left, bottom: pos.bottom, width: pos.width }}
        >
          {me ? (
            <div className="profile-who">
              <strong>{name}</strong>
              {me.email && me.email !== name ? <span className="muted small">{me.email}</span> : null}
            </div>
          ) : null}
          <a
            className="profile-item"
            href={href('account')}
            onClick={linkClick('account', () => {
              setOpen(false);
              onNavigate();
            })}
          >
            <UserRound size={16} aria-hidden="true" />
            <span>{t('nav.account')}</span>
          </a>
          <a
            className="profile-item"
            href={href('orgs')}
            onClick={linkClick('orgs', () => {
              setOpen(false);
              onNavigate();
            })}
          >
            <ArrowLeftRight size={16} aria-hidden="true" />
            <span>{t('app.switchOrgLong')}</span>
          </a>
          <Preferences />
          <button type="button" className="profile-item profile-logout" onClick={logout}>
            <LogOut size={16} aria-hidden="true" />
            <span>{t('app.logout')}</span>
          </button>
        </div>,
            document.body,
          )
        : null}
      <button
        ref={button}
        type="button"
        className="profile-button"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={t('profile.open', { name })}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="avatar" aria-hidden="true">
          {initials(name)}
        </span>
        <span className="profile-text">
          <strong>{name}</strong>
          {me?.is_instance_admin ? <span className="muted small">{t('profile.instanceAdmin')}</span> : null}
        </span>
        <ChevronsUpDown size={14} aria-hidden="true" className="profile-chevron" />
      </button>
    </div>
  );
}
