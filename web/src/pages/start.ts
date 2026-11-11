// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The getting started checklist (GET /organizations/:orgId/getting-started):
// which steps are done, which page fixes each, and whether the user put the
// page away for this organization.

import type { Route } from '../router';
import { prefs } from '../session';
import type { GettingStarted } from '../types';

export type StepId = 'provider' | 'key' | 'policy' | 'models' | 'alerts' | 'input';
/** done; todo (not started); warn (set up, but something is wrong). */
export type StepState = 'done' | 'todo' | 'warn';

export interface Step {
  id: StepId;
  state: StepState;
  /** Required for protection; the others are recommended. */
  required: boolean;
  /** The page that fixes it. */
  route: Route;
}

function providerState(s: GettingStarted): StepState {
  if (!s.upstream.configured) return 'todo';
  return s.upstream.reachable === false ? 'warn' : 'done';
}

function modelsState(s: GettingStarted): StepState {
  if (!s.models.configured) return 'todo';
  return s.models.reachable && s.models.layers.length > 0 ? 'done' : 'warn';
}

/** The steps in the order the page shows them. */
export function startSteps(s: GettingStarted): Step[] {
  return [
    { id: 'provider', state: providerState(s), required: true, route: 'providers' },
    { id: 'key', state: s.api_keys > 0 ? 'done' : 'todo', required: true, route: 'keys' },
    { id: 'policy', state: s.policies > 0 ? 'done' : 'todo', required: true, route: 'flow' },
    { id: 'models', state: modelsState(s), required: true, route: 'models' },
    { id: 'alerts', state: s.alert_channels > 0 ? 'done' : 'todo', required: false, route: 'alert-channels' },
    { id: 'input', state: s.input_settings ? 'done' : 'todo', required: false, route: 'input' },
  ];
}

/** How many steps are done, of how many. */
export function progress(steps: readonly Step[]): { done: number; total: number; requiredLeft: number } {
  return {
    done: steps.filter((x) => x.state === 'done').length,
    total: steps.length,
    requiredLeft: steps.filter((x) => x.required && x.state !== 'done').length,
  };
}

/** Layer ids as the UI writes them: l1 → L1. */
export function layerNames(layers: readonly string[]): string {
  return layers.map((l) => l.toUpperCase()).join(', ');
}

const dismissKey = (orgId: string) => `start.dismissed.${orgId}`;

/** The user put the getting started page away for this organization (this browser). */
export function isStartDismissed(orgId: string): boolean {
  return prefs.get(dismissKey(orgId)) === '1';
}

export function setStartDismissed(orgId: string, dismissed: boolean): void {
  prefs.set(dismissKey(orgId), dismissed ? '1' : '');
}

/** Whether the dashboard shows the setup card. */
export function showSetupCard(s: GettingStarted | undefined, dismissed: boolean): boolean {
  return s !== undefined && !s.complete && !dismissed;
}

/**
 * Whether a landing on the dashboard goes to getting started instead: for an
 * organization still missing a provider, an API key or a policy. A gateway
 * whose layers cannot be read is the instance's problem, not a new org's:
 * the dashboard's setup card shows it.
 */
export function landOnStart(s: GettingStarted | undefined, dismissed: boolean): boolean {
  return s !== undefined && !dismissed && (!s.upstream.configured || s.api_keys === 0 || s.policies === 0);
}
