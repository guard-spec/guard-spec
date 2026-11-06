// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// A "?" button with a tooltip. The tooltip shows on hover and on keyboard
// focus, Escape hides it, and the button names it with aria-describedby, so a
// screen reader reads the help with the button. It is positioned against the
// viewport (fixed), so a scrolling side panel does not clip it.

import { useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useApp } from '../context';

export interface HelpTipProps {
  /** What the help is about, for the button's name ("About {name}"). */
  name: string;
  children: ReactNode;
  testId?: string;
}

const GAP = 6;
const MARGIN = 8;

export function HelpTip({ name, children, testId }: HelpTipProps) {
  const { t } = useApp();
  const id = useId();
  const [hover, setHover] = useState(false);
  const [focus, setFocus] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const tip = useRef<HTMLSpanElement>(null);
  const open = (hover || focus) && !dismissed;

  useLayoutEffect(() => {
    const b = btn.current;
    const el = tip.current;
    if (!open || !b || !el) return;
    // Measure at the top left corner, where nothing narrows it.
    el.style.left = '0px';
    el.style.top = '0px';
    const r = b.getBoundingClientRect();
    const w = el.offsetWidth;
    const h = el.offsetHeight;
    let left = r.left + r.width / 2 - w / 2;
    left = Math.max(MARGIN, Math.min(left, window.innerWidth - w - MARGIN));
    let top = r.bottom + GAP;
    if (top + h > window.innerHeight - MARGIN) top = Math.max(MARGIN, r.top - GAP - h);
    el.style.left = `${Math.round(left)}px`;
    el.style.top = `${Math.round(top)}px`;
  }, [open]);

  return (
    <span className="help-tip">
      <button
        ref={btn}
        type="button"
        className="help-tip-btn"
        aria-label={t('help.about', { name })}
        aria-describedby={id}
        aria-expanded={open}
        data-testid={testId}
        onMouseEnter={() => {
          setHover(true);
          setDismissed(false);
        }}
        onMouseLeave={() => setHover(false)}
        onFocus={() => {
          setFocus(true);
          setDismissed(false);
        }}
        onBlur={() => setFocus(false)}
        onClick={(e) => {
          // Inside a label or a clickable row, the button only toggles its help.
          e.preventDefault();
          e.stopPropagation();
          setDismissed(open);
          if (!open) setFocus(true);
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && open) {
            e.stopPropagation();
            setDismissed(true);
          }
        }}
      >
        ?
      </button>
      {/* Always in the DOM, so aria-describedby resolves; shown when open. A span, so it may sit in a label or a paragraph. */}
      <span ref={tip} id={id} role="tooltip" className={open ? 'help-tip-pop is-open' : 'help-tip-pop'}>
        {children}
      </span>
    </span>
  );
}
