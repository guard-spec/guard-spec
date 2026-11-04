// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { isForbidden, isNotFound } from '../api';
import { errorText, useApp } from '../context';

export function PageHeader({ title, help, actions }: { title: string; help?: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {help ? <p className="muted">{help}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function ErrorBanner({ error, onDismiss }: { error: string | null; onDismiss?: () => void }) {
  if (!error) return null;
  return (
    <div className="banner banner-error" role="alert">
      <span>{error}</span>
      {onDismiss ? (
        <button type="button" className="btn-icon" aria-label="Dismiss" onClick={onDismiss}>
          ×
        </button>
      ) : null}
    </div>
  );
}

export function Field({
  label,
  help,
  error,
  children,
}: {
  label: string;
  help?: string | undefined;
  error?: string | undefined;
  children: (props: { id: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean }) => ReactNode;
}) {
  const id = useId();
  const helpId = `${id}-help`;
  const errId = `${id}-err`;
  const describedBy = [help ? helpId : '', error ? errId : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {help ? (
        <small id={helpId} className="muted">
          {help}
        </small>
      ) : null}
      {error ? (
        <small id={errId} className="field-error">
          {error}
        </small>
      ) : null}
    </div>
  );
}

/** A modal dialog on the native <dialog> element (focus trap and Escape for free). */
export function Dialog({
  open,
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const openRef = useRef(open);
  // Set when this component closes the element (the parent set open=false).
  const closing = useRef(false);
  // When Escape was last pressed in the dialog.
  const escapeAt = useRef(0);
  useEffect(() => {
    openRef.current = open;
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) {
      closing.current = true;
      d.close();
    }
  }, [open]);
  // Only the user closes a dialog: Escape or its buttons. The browser also
  // sends close requests of its own (Chrome treats a history step as one),
  // which would otherwise dismiss a dialog such as "leave unsaved changes?".
  const byEscape = () => Date.now() - escapeAt.current < 1000;
  useEffect(() => {
    // On the window: focus may have left the dialog (a clicked button that
    // went away), and Escape must still close it.
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') escapeAt.current = Date.now();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? 'dialog dialog-wide' : 'dialog'}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        if (byEscape()) onClose();
      }}
      onClose={() => {
        if (closing.current) {
          closing.current = false;
          return;
        }
        if (byEscape()) onClose();
        else if (openRef.current) ref.current?.showModal();
      }}
    >
      {open ? (
        <>
          <header className="dialog-header">
            <h2 id={titleId}>{title}</h2>
            <button type="button" className="btn-icon" aria-label="Close" onClick={onClose}>
              ×
            </button>
          </header>
          <div className="dialog-body">{children}</div>
          {footer ? <footer className="dialog-footer">{footer}</footer> : null}
        </>
      ) : null}
    </dialog>
  );
}

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  danger,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
  onClose: () => void;
}) {
  const { t } = useApp();
  const [busy, setBusy] = useState(false);
  return (
    <Dialog
      open={open}
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className={danger ? 'btn btn-danger' : 'btn btn-primary'}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onConfirm();
              } finally {
                setBusy(false);
              }
            }}
          >
            {confirmLabel}
          </button>
        </>
      }
    >
      {body}
    </Dialog>
  );
}

/** Loads data with fn, a memoized loader (useCallback), and reloads when it changes. */
export function useLoad<T>(fn: () => Promise<T>): {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  /** The caller's role may not read it (403). */
  forbidden: boolean;
  /** The endpoint does not exist on this control plane (404). */
  notFound: boolean;
  reload: () => Promise<void>;
} {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [forbidden, setForbidden] = useState(false);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await fn());
      setError(null);
      setNotFound(false);
      setForbidden(false);
    } catch (e) {
      setError(errorText(e));
      setNotFound(isNotFound(e));
      setForbidden(isForbidden(e));
    } finally {
      setLoading(false);
    }
  }, [fn]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, notFound, forbidden, reload };
}

/** A checkbox with a title and a help line. */
export function Toggle({
  label,
  help,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  help?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="switch-row">
      <input id={id} type="checkbox" checked={checked} disabled={disabled} aria-describedby={help ? `${id}-help` : undefined} onChange={(e) => onChange(e.target.checked)} />
      <div className="switch-text">
        <label htmlFor={id}>{label}</label>
        {help ? (
          <small id={`${id}-help`} className="muted">
            {help}
          </small>
        ) : null}
      </div>
    </div>
  );
}

/** value, once it has not changed for ms (search boxes). */
export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(id);
  }, [value, ms]);
  return v;
}

/** Offers text as a file download (recovery codes). A blob: URL, allowed by the CSP for downloads. */
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Loading() {
  const { t } = useApp();
  return (
    <p className="muted" role="status">
      {t('app.loading')}
    </p>
  );
}

export function formatTime(s: string | null | undefined): string {
  if (!s) return '—';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

export function CopyButton({ text }: { text: string }) {
  const { t } = useApp();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
        } catch {
          setDone(false);
        }
      }}
    >
      {done ? t('common.copied') : t('common.copy')}
    </button>
  );
}
