// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { X } from 'lucide-react';
import { useId, useState, type KeyboardEvent } from 'react';
import { useApp } from '../context';

/** A list of short strings (models, tags, domains): Enter or comma adds, × removes. */
export function ChipsInput({
  label,
  values,
  onChange,
  suggestions = [],
  placeholder,
  help,
  normalize = (s) => s.trim(),
}: {
  label: string;
  values: string[];
  onChange: (v: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
  help?: string;
  normalize?: (s: string) => string;
}) {
  const { t } = useApp();
  const id = useId();
  const [draft, setDraft] = useState('');
  const add = (raw: string) => {
    const items = raw.split(',').map(normalize).filter(Boolean);
    const next = [...values];
    for (const v of items) if (!next.includes(v)) next.push(v);
    onChange(next);
    setDraft('');
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if ((e.key === 'Enter' || e.key === ',') && draft.trim()) {
      e.preventDefault();
      add(draft);
    } else if (e.key === 'Backspace' && draft === '' && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };
  const open = suggestions.filter((s) => !values.includes(s));
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="chips">
        {values.map((v) => (
          <span key={v} className="chip">
            <span className="mono">{v}</span>
            <button type="button" aria-label={t('chips.remove', { value: v })} onClick={() => onChange(values.filter((x) => x !== v))}>
              <X size={12} aria-hidden="true" />
            </button>
          </span>
        ))}
        <input
          id={id}
          className="chips-input"
          value={draft}
          list={open.length ? `${id}-list` : undefined}
          placeholder={placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKey}
          onBlur={() => draft.trim() && add(draft)}
          aria-describedby={help ? `${id}-help` : undefined}
        />
        {open.length ? (
          <datalist id={`${id}-list`}>
            {open.map((s) => (
              <option key={s} value={s} />
            ))}
          </datalist>
        ) : null}
      </div>
      {open.length > 0 ? (
        <div className="chip-suggestions">
          {open.slice(0, 8).map((s) => (
            <button key={s} type="button" className="chip chip-add" onClick={() => add(s)}>
              + <span className="mono">{s}</span>
            </button>
          ))}
        </div>
      ) : null}
      {help ? (
        <small id={`${id}-help`} className="muted">
          {help}
        </small>
      ) : null}
    </div>
  );
}
