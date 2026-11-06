// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Models page helpers: the shadow comparison from GET /organizations/:orgId/shadow.

import type { ShadowSummary } from '../types';

/** Requests the shadow model could not score, of any reason. */
export function notComparedTotal(s: Pick<ShadowSummary, 'not_compared'>): number {
  const n = s.not_compared;
  return n.timeout + n.skipped + n.error;
}

/** The tallest histogram bin of either model, at least 1 (bars scale to it). */
export function histogramMax(bins: ShadowSummary['scores']['histogram']): number {
  return Math.max(1, ...bins.map((b) => Math.max(b.active, b.shadow)));
}

/** A score bin as "0.0–0.1". */
export function binLabel(b: { from: number; to: number }): string {
  return `${b.from.toFixed(1)}–${b.to.toFixed(1)}`;
}
