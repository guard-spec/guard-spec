// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Security overview helpers.

import type { DashboardStats, GatewayModels } from '../types';
import { volumeBars, type VolumeBar } from './dashboard';

/** The refused requests per period, and the tallest, at least 1. */
export function attackBars(stats: Pick<DashboardStats, 'series'>): { bars: VolumeBar[]; max: number } {
  const { bars } = volumeBars(stats);
  return { bars, max: Math.max(1, ...bars.map((b) => b.blocked)) };
}

/**
 * The detection models at a glance: ok (every layer the gateway reports, a
 * verified classifier, no reload error), degraded (it answers, something is
 * off), down (the control plane cannot read it).
 */
export function modelHealth(gw: GatewayModels | undefined): 'ok' | 'degraded' | 'down' {
  if (!gw?.configured || !gw.reachable) return 'down';
  const layers = gw.layers ?? [];
  if (gw.reload.error || (gw.l2_model && !gw.l2_verified) || !layers.includes('l2') || !layers.includes('l3')) return 'degraded';
  return 'ok';
}
