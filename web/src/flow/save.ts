// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Saving the Flow page's policies: one request per changed policy, then a
// merge of the server's list with what could not be saved.

import type { ApiClient } from '../api';
import { ruleNameInError, toWireRules, type EditablePolicy } from './model';

export type SaveApi = Pick<ApiClient, 'createPolicy' | 'updatePolicy'>;

export interface SaveResult {
  /** One per policy that was not saved. */
  errors: { policy: string; message: string }[];
  /** Server errors that name a rule, by rule key. */
  ruleErrors: Record<string, string>;
  /** Local versions of the policies that were not saved, to keep editing. */
  keep: EditablePolicy[];
}

/**
 * Saves every dirty policy. A new policy is created in one request, enabled
 * or not as the user left it, so a disabled one is never live, not even
 * briefly. A policy that fails keeps its local version; one the server
 * created is never posted again (it is in the server's list with its id).
 */
export async function savePolicies(api: SaveApi, orgId: string, policies: EditablePolicy[]): Promise<SaveResult> {
  const out: SaveResult = { errors: [], ruleErrors: {}, keep: [] };
  for (const p of policies.filter((x) => x.dirty)) {
    try {
      const rules = toWireRules(p.rules);
      if (p.id) {
        await api.updatePolicy(orgId, p.id, { name: p.name, rules, enabled: p.enabled, log_only: p.log_only });
      } else {
        await api.createPolicy(orgId, { name: p.name, rules, project_id: p.project_id, enabled: p.enabled, log_only: p.log_only });
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      out.errors.push({ policy: p.name, message });
      out.keep.push(p);
      const bad = ruleNameInError(message);
      for (const r of p.rules) if (bad !== undefined && r.name === bad) out.ruleErrors[r.key] = message;
    }
  }
  return out;
}

/**
 * The server's policies after a save, with the local versions of the ones
 * that failed: an existing policy keeps its unsaved edits (still dirty), and
 * a new policy that could not be created stays a draft.
 */
export function mergeAfterSave(fresh: EditablePolicy[], keep: EditablePolicy[]): EditablePolicy[] {
  const byId = new Map(keep.filter((k) => k.id).map((k) => [k.id, k]));
  return [...fresh.map((f) => byId.get(f.id) ?? f), ...keep.filter((k) => !k.id)];
}
