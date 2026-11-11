// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The command palette (Ctrl+K, Cmd+K on a Mac): go to any page, policy,
// project, model provider or API key by typing. A combobox with a listbox
// (WAI-ARIA combobox pattern): arrows move, Enter opens, Escape closes.

import { Search } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Dialog } from '../components/ui';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import { NAV, type NavGroup } from '../nav';
import { navigate } from '../router';
import type { Org } from '../types';
import { isPaletteShortcut, matchItems, moveActive, type PaletteItem } from './palette';

const KIND_LABEL: Record<PaletteItem['kind'], MessageKey> = {
  page: 'palette.kind.page',
  policy: 'palette.kind.policy',
  project: 'palette.kind.project',
  provider: 'palette.kind.provider',
  key: 'palette.kind.key',
};

/** The topbar button and the dialog; the shortcut works on every page. */
export function CommandPalette({ org, visible }: { org: Org | null; visible: (group: NavGroup, capability: string | undefined) => boolean }) {
  const { api, t } = useApp();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [objects, setObjects] = useState<PaletteItem[]>([]);
  const button = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const inputId = useId();
  const optionId = (i: number) => `${listId}-o${i}`;

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (!isPaletteShortcut(e)) return;
      e.preventDefault();
      setOpen((o) => !o);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // The org's objects, read when the palette opens; each list is optional.
  useEffect(() => {
    if (!open || !org) return;
    let live = true;
    const canKeys = NAV.some((g) => g.items.some((i) => i.route === 'keys' && visible(g, i.capability)));
    const settle = <T,>(p: Promise<T>, f: (v: T) => PaletteItem[]) => p.then(f, () => [] as PaletteItem[]);
    void Promise.all([
      settle(api.listPolicies(org.id), (ps) =>
        ps.map((p) => ({ id: `policy-${p.id}`, kind: 'policy' as const, label: p.name, hint: t('nav.flow'), route: 'flow' as const, params: { policy: p.id } })),
      ),
      settle(api.listProjects(org.id), (ps) =>
        ps.map((p) => ({ id: `project-${p.id}`, kind: 'project' as const, label: p.name, hint: t('nav.projects'), route: 'projects' as const })),
      ),
      settle(api.listUpstreams(org.id), (us) =>
        us.map((u) => ({ id: `provider-${u.id}`, kind: 'provider' as const, label: u.display_name ?? u.name, hint: `${t('nav.providers')} · ${u.name}`, route: 'providers' as const })),
      ),
      canKeys
        ? settle(api.listApiKeys(org.id), (ks) =>
            ks
              .filter((k) => !k.revoked)
              .map((k) => ({ id: `key-${k.key_prefix}`, kind: 'key' as const, label: k.alias ?? k.key_prefix, hint: `${t('nav.keys')} · ${k.key_prefix}`, route: 'keys' as const })),
          )
        : Promise.resolve([] as PaletteItem[]),
    ]).then((lists) => live && setObjects(lists.flat()));
    return () => {
      live = false;
    };
  }, [open, org, api, t, visible]);

  const pages = useMemo<PaletteItem[]>(() => {
    const out: PaletteItem[] = [];
    if (org) {
      for (const g of NAV) {
        for (const i of g.items) {
          if (visible(g, i.capability)) out.push({ id: `page-${i.route}`, kind: 'page', label: t(i.label), hint: t(g.label), route: i.route });
        }
      }
    }
    out.push({ id: 'page-account', kind: 'page', label: t('nav.account'), hint: t('profile.menu'), route: 'account' });
    out.push({ id: 'page-orgs', kind: 'page', label: t('app.switchOrgLong'), hint: t('profile.menu'), route: 'orgs' });
    return out;
  }, [org, visible, t]);

  const results = useMemo(() => matchItems([...pages, ...objects], query), [pages, objects, query]);
  const current = active >= 0 && active < results.length ? active : -1;
  // The palette exists to type into: focus goes to its input once the
  // dialog is shown (showModal focuses its first button).
  useEffect(() => {
    if (!open) return;
    const id = window.requestAnimationFrame(() => input.current?.focus());
    return () => window.cancelAnimationFrame(id);
  }, [open]);

  // Keep the active option in view as the arrows move it.
  useEffect(() => {
    if (open && current >= 0) document.getElementById(optionId(current))?.scrollIntoView({ block: 'nearest' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, current]);

  const close = () => {
    setOpen(false);
    setQuery('');
    setActive(0);
    button.current?.focus();
  };
  const choose = (item: PaletteItem) => {
    setOpen(false);
    setQuery('');
    setActive(0);
    navigate(item.route, false, item.params);
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || ((e.key === 'Home' || e.key === 'End') && e.ctrlKey)) {
      e.preventDefault();
      setActive(moveActive(current, results.length, e.key));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const item = results[current];
      if (item) choose(item);
    }
  };

  return (
    <>
      <button
        ref={button}
        type="button"
        className="btn palette-button"
        aria-label={t('palette.open')}
        aria-keyshortcuts="Control+K Meta+K"
        aria-haspopup="dialog"
        onClick={() => setOpen(true)}
      >
        <Search size={14} aria-hidden="true" />
        <span className="palette-button-text">{t('palette.open')}</span>
        <kbd aria-hidden="true">Ctrl K</kbd>
      </button>
      <Dialog open={open} title={t('palette.title')} onClose={close}>
        <div className="palette" data-testid="palette">
          <label htmlFor={inputId} className="sr-only">
            {t('palette.label')}
          </label>
          <input
            id={inputId}
            ref={input}
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={current >= 0 ? optionId(current) : undefined}
            placeholder={t('palette.placeholder')}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
          />
          <div id={listId} role="listbox" aria-label={t('palette.results')} className="palette-list">
            {results.map((item, i) => (
              // Options are chosen by click or by Enter in the combobox, which keeps focus.
              // eslint-disable-next-line jsx-a11y/click-events-have-key-events
              <div
                key={item.id}
                id={optionId(i)}
                role="option"
                tabIndex={-1}
                aria-selected={i === current}
                className={i === current ? 'palette-item is-active' : 'palette-item'}
                onPointerMove={() => i !== current && setActive(i)}
                onClick={() => choose(item)}
              >
                <span className="palette-label">{item.label}</span>
                <span className="palette-hint muted small">
                  {t(KIND_LABEL[item.kind])} · {item.hint}
                </span>
              </div>
            ))}
          </div>
          {results.length === 0 ? (
            <p className="muted" role="status">
              {t('palette.none', { q: query })}
            </p>
          ) : (
            <p className="sr-only" role="status">
              {t('palette.count', { n: results.length })}
            </p>
          )}
          <p className="muted small palette-help">{t('palette.help')}</p>
        </div>
      </Dialog>
    </>
  );
}
