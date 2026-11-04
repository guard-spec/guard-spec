// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Dashboard numbers from a sample of the request log.
// TODO(N15+): use a server-side aggregate endpoint when the control plane has
// one; until then the dashboard reads the latest pages of /requests.

import type { AuditRow, Policy } from '../types';

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

export interface Stats {
  count: number;
  blocked: number;
  blockRate: number;
  byAction: { action: string; count: number }[];
  topLabels: { label: string; count: number }[];
  p50: number | null;
  p99: number | null;
  /** Requests per bucket, oldest first. */
  volume: { start: number; count: number }[];
  bucketMs: number;
  from: number | null;
  to: number | null;
}

/** The q quantile (0..1) of sorted values, nearest rank. */
export function quantile(sorted: number[], q: number): number | null {
  if (sorted.length === 0) return null;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
  return sorted[i] ?? null;
}

export function computeStats(rows: AuditRow[], buckets = 24): Stats {
  const byAction = new Map<string, number>();
  const byLabel = new Map<string, number>();
  const lat: number[] = [];
  let from = Infinity;
  let to = -Infinity;
  for (const r of rows) {
    byAction.set(r.action, (byAction.get(r.action) ?? 0) + 1);
    // The gateway stores labels in upper case (BENIGN): compare and group case-insensitively.
    const label = normLabel(r.injection_label);
    if (label && label !== 'benign') byLabel.set(label, (byLabel.get(label) ?? 0) + 1);
    if (typeof r.latency_ms === 'number') lat.push(r.latency_ms);
    const at = Date.parse(r.created_at);
    if (!Number.isNaN(at)) {
      from = Math.min(from, at);
      to = Math.max(to, at);
    }
  }
  lat.sort((a, b) => a - b);
  const blocked = byAction.get('block') ?? 0;
  const span = Number.isFinite(from) ? Math.max(to - from, 60_000) : 0;
  const bucketMs = span > 0 ? Math.ceil(span / buckets) : 0;
  const volume: { start: number; count: number }[] = [];
  if (bucketMs > 0) {
    for (let i = 0; i < buckets; i++) volume.push({ start: from + i * bucketMs, count: 0 });
    for (const r of rows) {
      const at = Date.parse(r.created_at);
      if (Number.isNaN(at)) continue;
      const b = volume[Math.min(buckets - 1, Math.floor((at - from) / bucketMs))];
      if (b) b.count += 1;
    }
  }
  const sortDesc = <K extends string>(m: Map<string, number>, k: K) =>
    [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([key, count]) => ({ [k]: key, count }) as Record<K, string> & { count: number });
  return {
    count: rows.length,
    blocked,
    blockRate: rows.length ? blocked / rows.length : 0,
    byAction: sortDesc(byAction, 'action'),
    topLabels: sortDesc(byLabel, 'label').slice(0, 5),
    p50: quantile(lat, 0.5),
    p99: quantile(lat, 0.99),
    volume,
    bucketMs,
    from: Number.isFinite(from) ? from : null,
    to: Number.isFinite(to) ? to : null,
  };
}
