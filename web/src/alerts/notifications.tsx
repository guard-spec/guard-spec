// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// In-app notifications: the unread count and the latest notifications,
// kept live by the stream (GET /v1/notifications/stream), and the header bell.

import { Bell, Check, CheckCheck } from 'lucide-react';
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { isNotFound } from '../api';
import { normalizePage } from '../paging';
import { RelativeTime } from '../components/ui';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import { href, navigate } from '../router';
import { session } from '../session';
import { alertsApi, asNotification } from './api';
import { nextUnread } from './model';
import { backoffDelay, readStream, type SseEvent } from './sse';
import type { AppNotification } from './types';

export const STREAM_URL = '/v1/notifications/stream';
const LIST_SIZE = 20;

export interface NotificationsState {
  /** false: this control plane has no notifications API (404). */
  available: boolean;
  unread: number;
  items: AppNotification[];
  /** The stream is connected. */
  live: boolean;
  markRead: (ids: string[] | 'all') => Promise<void>;
  refresh: () => Promise<void>;
}

const Ctx = createContext<NotificationsState | null>(null);

export function useNotifications(): NotificationsState | null {
  return useContext(Ctx);
}

/** Applies a stream event to the list; returns the new list and how many unread it added. */
export function applyEvent(items: AppNotification[], e: SseEvent): { items: AppNotification[]; added: number; read?: string[] | 'all' } | null {
  let data: unknown;
  try {
    data = JSON.parse(e.data) as unknown;
  } catch {
    return null;
  }
  if (e.event === 'read') {
    const d = (data ?? {}) as { ids?: unknown; all?: unknown };
    if (d.all === true) return { items: items.map((n) => ({ ...n, read_at: n.read_at ?? new Date().toISOString() })), added: 0, read: 'all' };
    const ids = Array.isArray(d.ids) ? d.ids.filter((x): x is string => typeof x === 'string') : [];
    return { items: items.map((n) => (ids.includes(n.id) && !n.read_at ? { ...n, read_at: new Date().toISOString() } : n)), added: 0, read: ids.filter((id) => items.some((n) => n.id === id && !n.read_at)) };
  }
  if (e.event !== 'notification' && e.event !== 'message') return null;
  const n = asNotification(data);
  if (!n || items.some((x) => x.id === n.id)) return null;
  return { items: [n, ...items].slice(0, LIST_SIZE), added: n.read_at ? 0 : 1 };
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const id = window.setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      window.clearTimeout(id);
      resolve();
    });
  });
}

export function NotificationsProvider({ children }: { children: ReactNode }) {
  const { api } = useApp();
  const a = useMemo(() => alertsApi(api), [api]);
  const [available, setAvailable] = useState(false);
  const [unread, setUnread] = useState(0);
  const [items, setItems] = useState<AppNotification[]>([]);
  const [live, setLive] = useState(false);
  const itemsRef = useRef(items);
  useEffect(() => {
    itemsRef.current = items;
  }, [items]);

  const refresh = useCallback(async () => {
    try {
      const [list, un] = await Promise.all([a.listNotifications({ limit: LIST_SIZE }), a.listNotifications({ unread: 1, limit: 1 })]);
      const page = normalizePage<unknown>(list);
      setItems(page.items.map(asNotification).filter((n): n is AppNotification => n !== null));
      const u = normalizePage<unknown>(un);
      setUnread(u.total ?? u.items.length);
      setAvailable(true);
    } catch (e) {
      if (isNotFound(e)) setAvailable(false);
    }
  }, [a]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // The stream: reconnect with backoff; stop on 401 or 404.
  useEffect(() => {
    if (!available) return;
    const ctrl = new AbortController();
    const aborted = () => ctrl.signal.aborted;
    void (async () => {
      let attempt = 0;
      while (!ctrl.signal.aborted) {
        const token = session.token();
        if (!token) break;
        const started = Date.now();
        const seen = { event: false };
        try {
          const end = await readStream({
            url: STREAM_URL,
            token,
            signal: ctrl.signal,
            onOpen: () => {
              setLive(true);
              // Catch up on what arrived while disconnected.
              if (attempt > 0) void refresh();
            },
            onEvent: (e) => {
              seen.event = true;
              if (e.event === 'unread') {
                try {
                  const c = (JSON.parse(e.data) as { count?: unknown }).count;
                  if (typeof c === 'number') setUnread(c);
                } catch {
                  // not JSON: ignore
                }
                return;
              }
              const r = applyEvent(itemsRef.current, e);
              if (!r) return;
              itemsRef.current = r.items;
              setItems(r.items);
              if (r.read === 'all') setUnread(0);
              else setUnread((c) => nextUnread(c, { added: r.added, read: Array.isArray(r.read) ? r.read.length : 0 }));
            },
          });
          if (end !== 'closed') break;
        } catch {
          if (aborted()) break;
        }
        setLive(false);
        if (seen.event || Date.now() - started > 5000) attempt = 0;
        await sleep(backoffDelay(attempt), ctrl.signal);
        attempt += 1;
      }
      setLive(false);
    })();
    return () => ctrl.abort();
  }, [available, refresh]);

  const markRead = useCallback(
    async (ids: string[] | 'all') => {
      await a.markRead(ids);
      const now = new Date().toISOString();
      if (ids === 'all') {
        setItems((xs) => xs.map((n) => ({ ...n, read_at: n.read_at ?? now })));
        setUnread(0);
        return;
      }
      const fresh = itemsRef.current.filter((n) => ids.includes(n.id) && !n.read_at).length;
      setItems((xs) => xs.map((n) => (ids.includes(n.id) ? { ...n, read_at: n.read_at ?? now } : n)));
      setUnread((c) => nextUnread(c, { read: fresh }));
    },
    [a],
  );

  const value = useMemo<NotificationsState>(() => ({ available, unread, items, live, markRead, refresh }), [available, unread, items, live, markRead, refresh]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

const SEV_KEY: Record<string, MessageKey> = { info: 'alerts.sev.info', warning: 'alerts.sev.warning', critical: 'alerts.sev.critical' };

/** The header bell: unread count and a dropdown of the latest notifications. */
export function NotificationBell() {
  const { t, notify } = useApp();
  const n = useNotifications();
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panelId = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        button.current?.focus();
      }
    };
    const onDown = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('pointerdown', onDown);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('pointerdown', onDown);
    };
  }, [open]);

  if (!n?.available) return null;
  const label = n.unread > 0 ? t('bell.labelUnread', { count: n.unread }) : t('bell.label');
  const mark = async (ids: string[] | 'all') => {
    try {
      await n.markRead(ids);
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e), 'error');
    }
  };
  return (
    <div className="bell" ref={wrap}>
      <button
        ref={button}
        type="button"
        className="btn-icon bell-button"
        aria-label={label}
        title={label}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
        data-testid="bell"
      >
        <Bell size={18} aria-hidden="true" />
        {n.unread > 0 ? (
          <span className="bell-count" aria-hidden="true" data-testid="bell-count">
            {n.unread > 99 ? '99+' : n.unread}
          </span>
        ) : null}
        <span className={n.live ? 'bell-live is-live' : 'bell-live'} aria-hidden="true" />
      </button>
      {open ? (
        <div id={panelId} className="bell-panel" role="group" aria-label={t('bell.title')}>
          <div className="bell-head">
            <strong>{t('bell.title')}</strong>
            <span className="muted small">{n.live ? t('bell.live') : t('bell.reconnecting')}</span>
            <button type="button" className="btn btn-small btn-icon-text" disabled={n.unread === 0} onClick={() => void mark('all')}>
              <CheckCheck size={14} aria-hidden="true" />
              <span>{t('bell.markAll')}</span>
            </button>
          </div>
          {n.items.length === 0 ? (
            <p className="muted bell-empty">{t('bell.empty')}</p>
          ) : (
            <ul className="bell-list" data-testid="bell-list">
              {n.items.map((x) => (
                <li key={x.id} className={x.read_at ? 'bell-item' : 'bell-item is-unread'}>
                  <span className={`sev-dot sev-${x.severity}`} title={t(SEV_KEY[x.severity] ?? 'alerts.sev.info')} aria-hidden="true" />
                  <a
                    className="bell-text"
                    href={x.alert_id ? `${href('alert-history')}?id=${encodeURIComponent(x.alert_id)}` : href('alert-history')}
                    onClick={(e) => {
                      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
                      e.preventDefault();
                      if (!x.read_at) void mark([x.id]);
                      setOpen(false);
                      navigate('alert-history', false, x.alert_id ? { id: x.alert_id } : undefined);
                    }}
                  >
                    <strong>{x.title}</strong>
                    {x.body ? <span className="small muted bell-body">{x.body}</span> : null}
                    <span className="small muted">
                      <RelativeTime value={x.created_at} />
                    </span>
                  </a>
                  {x.read_at ? null : (
                    <button type="button" className="btn-icon" aria-label={t('bell.markRead', { title: x.title })} title={t('bell.markReadShort')} onClick={() => void mark([x.id])}>
                      <Check size={14} aria-hidden="true" />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          <div className="bell-foot">
            <a
              href={href('alert-history')}
              onClick={(e) => {
                e.preventDefault();
                setOpen(false);
                navigate('alert-history');
              }}
            >
              {t('bell.history')}
            </a>
          </div>
        </div>
      ) : null}
    </div>
  );
}
