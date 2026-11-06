// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The condition builder's field and operator controls. The field picker is a
// button with the full field name that opens a searchable list, grouped like
// the help (Detection scores, Anomalies, Indirect content, Request, MCP), with
// each field's description; the operator select has the operator's help.

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { FieldSelectorProps, OperatorSelectorProps } from 'react-querybuilder';
import { useApp } from '../context';
import type { FieldType } from '../types';
import { descKey, groupFields, groupKey, variableHelp } from './help';
import { OperatorTip, VariableTip } from './HelpText';

interface PickerOption {
  name: string;
  label: string;
  title?: string;
}

function flatOptions(options: FieldSelectorProps['options']): PickerOption[] {
  const out: PickerOption[] = [];
  for (const o of options as unknown as ({ name: string; label: string; title?: string } | { options: { name: string; label: string; title?: string }[] })[]) {
    if ('options' in o) out.push(...o.options.map((x) => ({ name: x.name, label: x.label, title: x.title })));
    else out.push({ name: o.name, label: o.label, title: o.title });
  }
  return out;
}

/** The fields matching a search, by name, group or description. */
export function filterFields<T extends { name: string }>(fields: readonly T[], q: string, describe: (name: string) => string): T[] {
  const s = q.trim().toLowerCase();
  if (!s) return [...fields];
  return fields.filter((f) => f.name.toLowerCase().includes(s) || describe(f.name).toLowerCase().includes(s));
}

export function FieldPicker(props: FieldSelectorProps) {
  const { t } = useApp();
  const options = useMemo(() => flatOptions(props.options), [props.options]);
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const listId = useId();
  const root = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const describe = (name: string) => (variableHelp(name) ? t(descKey(name)) : (options.find((o) => o.name === name)?.title ?? ''));
  const matches = filterFields(options, q, describe);
  const groups = groupFields(matches);
  const ordered = groups.flatMap((g) => g.fields);
  const current = props.value ?? '';

  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  const choose = (name: string) => {
    setOpen(false);
    setQ('');
    if (name !== current) props.handleOnChange(name);
    button.current?.focus();
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, ordered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const f = ordered[active];
      if (f) choose(f.name);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      button.current?.focus();
    }
  };

  const optionId = (name: string) => `${listId}-${name.replace(/[^a-z0-9]/gi, '_')}`;
  const activeName = ordered[active]?.name;

  return (
    <div className={`field-picker ${props.className ?? ''}`} ref={root} data-testid="field-picker">
      <div className="field-picker-row">
        <button
          ref={button}
          type="button"
          className="field-picker-btn mono"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-label={current ? t('picker.field', { name: current }) : t('picker.choose')}
          disabled={props.disabled}
          onClick={() => {
            setOpen(!open);
            setActive(Math.max(0, ordered.findIndex((f) => f.name === current)));
          }}
        >
          <span className="field-picker-value">{current || t('picker.choose')}</span>
          <span aria-hidden="true" className="field-picker-caret">
            ▾
          </span>
        </button>
        {current ? <VariableTip name={current} fallback={describe(current)} /> : null}
      </div>
      {open ? (
        <div className="field-picker-pop">
          <input
            ref={input}
            type="search"
            role="combobox"
            aria-label={t('picker.search')}
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={activeName ? optionId(activeName) : undefined}
            aria-autocomplete="list"
            placeholder={t('picker.search')}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKey}
          />
          <div id={listId} role="listbox" aria-label={t('picker.choose')} className="field-picker-list">
            {groups.length === 0 ? <p className="muted small">{t('picker.none', { q })}</p> : null}
            {groups.map((g) => (
              <div key={g.group} role="group" aria-label={t(groupKey(g.group))}>
                <div className="field-picker-group" aria-hidden="true">
                  {t(groupKey(g.group))}
                </div>
                {g.fields.map((f) => (
                  <div
                    key={f.name}
                    id={optionId(f.name)}
                    role="option"
                    aria-selected={f.name === current}
                    tabIndex={-1}
                    className={['field-picker-option', f.name === activeName ? 'is-active' : '', f.name === current ? 'is-current' : ''].join(' ')}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => choose(f.name)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') choose(f.name);
                    }}
                    onMouseEnter={() => setActive(ordered.indexOf(f))}
                  >
                    <span className="mono">{f.name}</span>
                    <span className="small muted">{describe(f.name)}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** The operator select, with the selected operator's help. */
export function OperatorSelect(props: OperatorSelectorProps) {
  const { t } = useApp();
  const opts = props.options as unknown as { name: string; label: string }[];
  const type = (props.fieldData as { type?: FieldType } | undefined)?.type;
  const value = props.value ?? '';
  const label = opts.find((o) => o.name === value)?.label ?? value;
  return (
    <div className={`operator-select ${props.className ?? ''}`}>
      <select
        value={value}
        title={props.title}
        aria-label={t('rule.operator')}
        disabled={props.disabled}
        onChange={(e) => props.handleOnChange(e.target.value)}
      >
        {opts.map((o) => (
          <option key={o.name} value={o.name}>
            {o.label}
          </option>
        ))}
      </select>
      {value ? <OperatorTip op={value} type={type} label={label} /> : null}
    </div>
  );
}
