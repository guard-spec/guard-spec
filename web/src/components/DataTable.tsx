// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { ChevronLeft, ChevronRight, Inbox, Lock, PlugZap, RefreshCw, Search, UserCog, type LucideIcon } from 'lucide-react';
import { useId, type ReactNode } from 'react';
import { useApp } from '../context';
import { PAGE_SIZES, type PageSize } from '../paging';
import type { UsePaged } from './usePaged';

/** The control plane version that brings the identity and access API (N15). */
export const IDENTITY_API_VERSION = '0.3';

export type Tone = 'neutral' | 'ok' | 'warn' | 'danger' | 'accent' | 'off';

export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  body,
  action,
  compact,
}: {
  icon?: LucideIcon;
  title: string;
  body?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={compact ? 'empty empty-compact' : 'empty'}>
      <span className="empty-icon" aria-hidden="true">
        <Icon size={20} />
      </span>
      <strong>{title}</strong>
      {body ? <p className="muted">{body}</p> : null}
      {action ? <div className="empty-action">{action}</div> : null}
    </div>
  );
}

/** A feature the control plane does not have yet (its endpoint answered 404). */
export function NotAvailable({ feature, compact }: { feature?: string; compact?: boolean }) {
  const { t } = useApp();
  return (
    <EmptyState
      icon={PlugZap}
      compact={compact}
      title={t('na.title')}
      body={
        <>
          {feature ? <span>{t('na.feature', { feature })} </span> : null}
          {t('na.body', { version: IDENTITY_API_VERSION })}
        </>
      }
    />
  );
}

/** A page of the instance admin group, opened by someone else. */
export function InstanceAdminOnly() {
  const { t } = useApp();
  return <EmptyState icon={UserCog} title={t('admin.onlyTitle')} body={t('admin.onlyBody')} />;
}

/** The caller's role may not see this (403): no retry, it would fail again. */
export function Forbidden({ compact }: { compact?: boolean }) {
  const { t } = useApp();
  return <EmptyState icon={Lock} compact={compact} title={t('forbidden.title')} body={t('forbidden.body')} />;
}

export function Pager<T>({ paged, label }: { paged: UsePaged<T>; label?: string }) {
  const { t } = useApp();
  const id = useId();
  const { from, to, total } = paged.range;
  return (
    <nav className="pager" aria-label={label ?? t('pager.label')}>
      <div className="pager-size">
        <label htmlFor={id}>{t('pager.rows')}</label>
        <select id={id} value={paged.state.pageSize} onChange={(e) => paged.setPageSize(Number(e.target.value) as PageSize)}>
          {PAGE_SIZES.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </div>
      <span className="pager-range muted" aria-live="polite">
        {from === 0 ? t('pager.none') : total === null ? t('pager.range', { from, to }) : paged.range.capped ? t('pager.rangeOfCapped', { from, to, total }) : t('pager.rangeOf', { from, to, total })}
      </span>
      <div className="pager-buttons">
        <button type="button" className="btn btn-icon-text" disabled={!paged.hasPrev || paged.state.loading} onClick={paged.prev}>
          <ChevronLeft size={16} aria-hidden="true" />
          <span>{t('pager.prev')}</span>
        </button>
        <button type="button" className="btn btn-icon-text" disabled={!paged.hasNext || paged.state.loading} onClick={paged.next}>
          <span>{t('pager.next')}</span>
          <ChevronRight size={16} aria-hidden="true" />
        </button>
      </div>
    </nav>
  );
}

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
  /** The header is read by screen readers only (an actions column). */
  hiddenHeader?: boolean;
}

/**
 * A table over a usePaged list: toolbar slot (search, filters), loading,
 * error with retry, "not on this control plane", empty state and the pager.
 */
export function DataTable<T>({
  columns,
  paged,
  rowKey,
  rowClassName,
  toolbar,
  empty,
  feature,
  testId,
  caption,
}: {
  columns: Column<T>[];
  paged: UsePaged<T>;
  rowKey: (row: T) => string;
  rowClassName?: (row: T) => string;
  toolbar?: ReactNode;
  empty?: ReactNode;
  /** Named in the "not available" state. */
  feature?: string;
  testId?: string;
  caption?: string;
}) {
  const { t } = useApp();
  const s = paged.state;
  let body: ReactNode = null;
  if (s.unavailable) {
    body = <NotAvailable feature={feature} />;
  } else if (s.forbidden) {
    body = <Forbidden />;
  } else if (s.error && paged.rows.length === 0) {
    body = (
      <div className="empty" role="alert">
        <strong>{t('table.error')}</strong>
        <p className="muted">{s.error}</p>
        <button type="button" className="btn btn-icon-text" onClick={() => void paged.reload()}>
          <RefreshCw size={14} aria-hidden="true" />
          <span>{t('table.retry')}</span>
        </button>
      </div>
    );
  } else if (!s.loading && paged.rows.length === 0) {
    body = empty ?? <EmptyState title={t('common.empty')} />;
  }
  return (
    <div className="data-table">
      {toolbar ? <div className="toolbar">{toolbar}</div> : null}
      <div className="card table-wrap" aria-busy={s.loading}>
        {s.error && paged.rows.length > 0 ? (
          <div className="banner banner-error table-banner" role="alert">
            {s.error}
          </div>
        ) : null}
        {body ?? (
          <table data-testid={testId}>
            {caption ? <caption className="sr-only">{caption}</caption> : null}
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c.key} scope="col" className={c.className}>
                    {c.hiddenHeader ? <span className="sr-only">{c.header}</span> : c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {s.loading && paged.rows.length === 0
                ? [0, 1, 2].map((i) => (
                    <tr key={`sk-${i}`} className="skeleton-row" aria-hidden="true">
                      {columns.map((c) => (
                        <td key={c.key}>
                          <span className="skeleton" />
                        </td>
                      ))}
                    </tr>
                  ))
                : paged.rows.map((r) => (
                    <tr key={rowKey(r)} className={rowClassName?.(r)}>
                      {columns.map((c) => (
                        <td key={c.key} className={c.className}>
                          {c.cell(r)}
                        </td>
                      ))}
                    </tr>
                  ))}
            </tbody>
          </table>
        )}
      </div>
      {s.unavailable || s.forbidden ? null : <Pager paged={paged} />}
    </div>
  );
}

/** A search box for a table toolbar. */
export function SearchBox({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  const id = useId();
  return (
    <div className="search-box">
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <Search size={14} aria-hidden="true" className="search-icon" />
      <input id={id} type="search" placeholder={label} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
