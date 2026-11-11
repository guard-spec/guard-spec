// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Guard settings edited on the Flow page: staged with the rule edits and
// saved by the same Save changes. The control plane stores guard settings
// and policies through separate endpoints, so a save makes up to two kinds of
// request: the guard settings first (one request), then each changed policy.
// Each part that fails keeps its local edits and its own error message.

import type { ApiClient } from '../api';
import { MAX_ORG_THRESHOLD, type GuardSettings } from '../types';
import { savePolicies, type SaveApi, type SaveResult } from './save';
import type { EditablePolicy } from './model';

/** The body PUT /guard-settings stores: unset values left out, empty role map dropped. */
export function guardBody(s: GuardSettings): GuardSettings {
  const out: GuardSettings = {};
  if (s.scan_roles && Object.keys(s.scan_roles).length > 0) out.scan_roles = { ...s.scan_roles };
  if (s.spotlight) out.spotlight = s.spotlight;
  if (s.indirect_action) out.indirect_action = s.indirect_action;
  if (s.injection_threshold !== undefined) out.injection_threshold = s.injection_threshold;
  if (s.indirect_threshold !== undefined) out.indirect_threshold = s.indirect_threshold;
  if (s.conversation_window !== undefined) out.conversation_window = s.conversation_window;
  if (s.conversation_window_turns !== undefined) out.conversation_window_turns = s.conversation_window_turns;
  if (s.conversation_window_bytes !== undefined) out.conversation_window_bytes = s.conversation_window_bytes;
  if (s.input_pii !== undefined) out.input_pii = s.input_pii;
  if (s.input_pii_action && s.input_pii_action !== 'off') {
    out.input_pii_action = s.input_pii_action;
    if (s.input_pii_kinds?.length) out.input_pii_kinds = [...s.input_pii_kinds];
  }
  if (s.unscanned_parts) out.unscanned_parts = s.unscanned_parts;
  if (s.max_scan_tokens !== undefined) out.max_scan_tokens = s.max_scan_tokens;
  return out;
}

function canonical(s: GuardSettings | null): string {
  if (!s) return '{}';
  const b = guardBody(s);
  const roles = b.scan_roles ? Object.fromEntries(Object.entries(b.scan_roles).sort(([a], [c]) => (a < c ? -1 : 1))) : undefined;
  return JSON.stringify({ ...b, scan_roles: roles });
}

/** Whether the draft differs from what the server has. */
export function guardChanged(saved: GuardSettings | null, draft: GuardSettings | null): boolean {
  if (draft === null) return false;
  return canonical(saved) !== canonical(draft);
}

/**
 * Reads a threshold field: undefined for empty (the gateway default), the
 * number when it is in (0, MAX_ORG_THRESHOLD], or 'invalid'.
 */
export function parseThreshold(text: string): number | undefined | 'invalid' {
  const s = text.trim().replace(',', '.');
  if (s === '') return undefined;
  if (!/^(\d+\.?\d*|\.\d+)$/.test(s)) return 'invalid';
  const n = Number(s);
  if (!(n > 0 && n <= MAX_ORG_THRESHOLD)) return 'invalid';
  return n;
}

/**
 * Reads a conversation window size: undefined for empty (the gateway
 * default), the whole number when it is in [min, max], or 'invalid'.
 */
export function parseWindowSize(text: string, bounds: { min: number; max: number }): number | undefined | 'invalid' {
  const s = text.trim();
  if (s === '') return undefined;
  if (!/^\d+$/.test(s)) return 'invalid';
  const n = Number(s);
  return n >= bounds.min && n <= bounds.max ? n : 'invalid';
}

export type SaveAllApi = SaveApi & Pick<ApiClient, 'putGuardSettings'>;

export interface SaveAllResult extends SaveResult {
  /** The stored guard settings when they were saved; undefined when not sent. */
  guard?: GuardSettings;
  /** Why the guard settings were not saved. */
  guardError?: string;
}

/**
 * Saves the staged guard settings (when changed), then the dirty policies.
 * A guard failure does not stop the policies from being saved, and the
 * other way round: the result says which parts failed.
 */
export async function saveAll(
  api: SaveAllApi,
  orgId: string,
  guard: { saved: GuardSettings | null; draft: GuardSettings | null },
  policies: EditablePolicy[],
): Promise<SaveAllResult> {
  const out: SaveAllResult = { errors: [], ruleErrors: {}, keep: [], pending: [] };
  if (guard.draft && guardChanged(guard.saved, guard.draft)) {
    try {
      out.guard = await api.putGuardSettings(orgId, guardBody(guard.draft));
    } catch (e) {
      out.guardError = e instanceof Error ? e.message : String(e);
    }
  }
  const r = await savePolicies(api, orgId, policies);
  return { ...out, errors: r.errors, ruleErrors: r.ruleErrors, keep: r.keep, pending: r.pending };
}
