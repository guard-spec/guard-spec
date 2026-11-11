// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Helpers of the false-positive panel of the request log.

import type { AuditRow } from '../types';

export const LAYERS = ['l1', 'l2', 'l3'] as const;

/** A score with two decimals, as the request log shows it. */
export function scoreText(v: number): string {
  return v.toFixed(2);
}

/** The source of an allow exemplar added from a row: where it came from, no content. */
export function exemplarSource(row: Pick<AuditRow, 'id' | 'created_at'>): string {
  return `false positive ${row.created_at.slice(0, 10)} request ${row.id.slice(0, 8)}`;
}

/** Whether the details offer the false-positive fixes: the row was refused, or a log-only rule would have. */
export function offersFix(row: Pick<AuditRow, 'action' | 'pii_entities'>): boolean {
  return row.action === 'block' || (row.pii_entities ?? []).some((t) => t.startsWith('policy:would_block='));
}
