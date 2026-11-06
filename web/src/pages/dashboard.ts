// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Dashboard helpers. The numbers come from GET /organizations/:orgId/dashboard,
// aggregated by the control plane over the whole window.

import type { DashboardStats, DashboardWindow, Policy } from '../types';

/** The windows the dashboard offers; the first is the default. */
export const DASH_WINDOWS: readonly DashboardWindow[] = ['24h', '7d', '30d'];

/** A detector label in one case: the gateway stores BENIGN, the classifier jailbreak. */
export function normLabel(label: string | null | undefined): string | null {
  const l = label?.trim().toLowerCase();
  return l === undefined || l === '' ? null : l;
}

/** Rule id → rule and policy names, for logs that store rule ids. */
export function ruleNames(policies: readonly Policy[]): Map<string, { rule: string; policy: string }> {
  const out = new Map<string, { rule: string; policy: string }>();
  for (const p of policies) for (const r of p.rules) if (r.id) out.set(r.id, { rule: r.name, policy: p.name });
  return out;
}

/** count as a share of total, 0 when total is 0. */
export function share(count: number, total: number): number {
  return total > 0 ? count / total : 0;
}

export interface VolumeBar {
  start: number;
  count: number;
  blocked: number;
}

/** The series as bars (start in ms) and the tallest count, at least 1. */
export function volumeBars(stats: Pick<DashboardStats, 'series'>): { bars: VolumeBar[]; max: number } {
  const bars = stats.series.map((b) => ({ start: Date.parse(b.start), count: b.count, blocked: b.blocked }));
  return { bars, max: Math.max(1, ...bars.map((b) => b.count)) };
}
