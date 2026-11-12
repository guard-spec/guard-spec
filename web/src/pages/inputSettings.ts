// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The rules of the organization's input settings (migration 030), as the
// control plane applies them (internal/indirect/input.go): no React here, so
// the e2e mock uses them too.

import type { MessageKey, Translate } from '../i18n';
import type { InputSettings } from '../types';

/** The draft: inherit, or the org's own settings. */
export interface InputDraft {
  inherit: boolean;
  settings: InputSettings;
}

export const DEFAULT_INPUT: InputSettings = { input_mode: 'text_only', max_input_tokens: null, allowed_file_types: [], unreadable_file_action: 'block' };

/** What going from from to to loosens (null: the instance's behaviour). */
export function loosened(from: InputSettings | null, to: InputSettings | null): string[] {
  if (from === null) return [];
  if (to === null) return ['inherit'];
  const out: string[] = [];
  if (from.input_mode === 'text_only' && to.input_mode === 'hybrid') out.push('input_mode');
  if (from.max_input_tokens !== null && (to.max_input_tokens === null || to.max_input_tokens > from.max_input_tokens)) out.push('max_input_tokens');
  if (to.input_mode === 'hybrid' && to.allowed_file_types.some((x) => !from.allowed_file_types.includes(x))) out.push('allowed_file_types');
  if (from.unreadable_file_action === 'block' && to.unreadable_file_action === 'pass') out.push('unreadable_file_action');
  return out;
}

/** Field errors of the draft: tokens out of 1..ceiling. */
export function validateInput(d: InputDraft, ceiling: number): string[] {
  if (d.inherit) return [];
  const n = d.settings.max_input_tokens;
  if (n !== null && (!Number.isInteger(n) || n < 1 || n > ceiling)) return ['tokens'];
  return [];
}

/** The PUT body: no file types in text_only. */
export function inputBody(s: InputSettings): InputSettings {
  return { ...s, allowed_file_types: s.input_mode === 'hybrid' ? [...s.allowed_file_types].sort() : [] };
}

/** The loosened settings of a pending request (its payload), in words. */
export function pendingText(t: Translate, payload: Record<string, unknown>): string {
  const list = Array.isArray(payload.loosened) ? (payload.loosened as string[]) : [];
  return list.map((k) => t(`input.loosened.${k}` as MessageKey)).join(', ');
}
