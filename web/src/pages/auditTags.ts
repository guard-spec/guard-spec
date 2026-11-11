// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The request log's tags (requests.pii_entities): counts the gateway wrote,
// never values. Known tags get a readable label, the rest show as written.

import type { MessageKey, Translate } from '../i18n';
import { PII_KINDS, UNSCANNED_KINDS, type AuditRow, type PiiKind, type UnscannedKind } from '../types';

export type AuditTag =
  | { type: 'unscanned'; kind: UnscannedKind; n: number; raw: string }
  | { type: 'pii'; kind: PiiKind; n: number; raw: string }
  | { type: 'piiProtected'; verb: 'redacted' | 'tokenized'; kind: PiiKind; n: number; raw: string }
  | { type: 'wouldDecide'; action: 'block' | 'allow' | 'route'; ruleId: string; raw: string }
  | { type: 'layer'; layer: 'l1' | 'l2' | 'l3'; score: number; raw: string }
  | { type: 'detectorRule'; rule: string; raw: string }
  | { type: 'other'; raw: string };

const isPii = (k: string): k is PiiKind => (PII_KINDS as string[]).includes(k);
const isUnscanned = (k: string): k is UnscannedKind => (UNSCANNED_KINDS as string[]).includes(k);

/** Reads one tag: "input:unscanned_image=2", "input:pii_email=1", "input:pii_redacted_card=1" or another. */
export function parseAuditTag(raw: string): AuditTag {
  // "policy:would_block=<rule id>": a log-only policy's decision (migration 026).
  const w = /^policy:would_(block|allow|route)=([0-9a-f-]{36})$/.exec(raw);
  if (w) return { type: 'wouldDecide', action: w[1] as 'block' | 'allow' | 'route', ruleId: w[2] ?? '', raw };
  // The detector's explanation (cmd/gateway/detector_tags.go).
  const l = /^detector:(l[123])=(\d+(?:\.\d+)?)$/.exec(raw);
  if (l) return { type: 'layer', layer: l[1] as 'l1' | 'l2' | 'l3', score: Number(l[2]), raw };
  const r = /^detector:rule=(.+)$/.exec(raw);
  if (r) return { type: 'detectorRule', rule: r[1] ?? '', raw };
  const m = /^input:(unscanned|pii)_([a-z0-9_]+)=(\d+)$/.exec(raw);
  if (!m) return { type: 'other', raw };
  const [, family, rest = '', count = '0'] = m;
  const n = Number(count);
  if (family === 'unscanned') return isUnscanned(rest) ? { type: 'unscanned', kind: rest, n, raw } : { type: 'other', raw };
  if (isPii(rest)) return { type: 'pii', kind: rest, n, raw };
  const p = /^(redacted|tokenized)_(.+)$/.exec(rest);
  if (p && isPii(p[2] ?? '')) return { type: 'piiProtected', verb: p[1] as 'redacted' | 'tokenized', kind: p[2] as PiiKind, n, raw };
  return { type: 'other', raw };
}

export function parseAuditTags(tags: readonly string[] | null | undefined): AuditTag[] {
  return (tags ?? []).map(parseAuditTag);
}

/** The unscanned parts a row records, in tag order. */
export function unscannedOf(row: Pick<AuditRow, 'pii_entities'>): { kind: UnscannedKind; n: number }[] {
  return parseAuditTags(row.pii_entities).flatMap((t) => (t.type === 'unscanned' ? [{ kind: t.kind, n: t.n }] : []));
}

/** A tag as the page shows it. */
export function auditTagLabel(t: Translate, tag: AuditTag): string {
  switch (tag.type) {
    case 'unscanned':
      return t(`audit.tag.unscanned.${tag.kind}` as MessageKey, { n: tag.n });
    case 'pii':
      return t('audit.tag.pii', { kind: t(`guard.piiKind.${tag.kind}`), n: tag.n });
    case 'piiProtected':
      return t(`audit.tag.pii.${tag.verb}` as MessageKey, { kind: t(`guard.piiKind.${tag.kind}`), n: tag.n });
    case 'wouldDecide':
      return t(tag.action === 'block' ? 'audit.tag.wouldBlock' : tag.action === 'route' ? 'audit.tag.wouldRoute' : 'audit.tag.wouldAllow');
    default:
      return tag.raw;
  }
}

/**
 * Why the gateway refused the row, when the page knows the reason: the
 * unscanned_content refusal (UNSCANNED_PARTS or the org's unscanned_parts set
 * to block). The gateway stores the code as the label, or (older shape) a
 * block with no rule and no label but unscanned tags.
 */
export function blockReason(row: Pick<AuditRow, 'action' | 'injection_label' | 'rule_id' | 'pii_entities'>): 'unscanned_content' | null {
  if (row.action !== 'block') return null;
  const label = row.injection_label?.trim().toLowerCase() ?? '';
  if (label === 'unscanned_content') return 'unscanned_content';
  if (!row.rule_id && label === '' && unscannedOf(row).length > 0) return 'unscanned_content';
  return null;
}

/** The detector's explanation of a row: the score of each layer that ran and the rules and categories that fired. */
export interface DetectorExplanation {
  layers: Partial<Record<'l1' | 'l2' | 'l3', number>>;
  rules: string[];
}

/** null when the row records no detector tags (an older gateway, or refused before the scan). */
export function detectorOf(row: Pick<AuditRow, 'pii_entities'>): DetectorExplanation | null {
  const out: DetectorExplanation = { layers: {}, rules: [] };
  let any = false;
  for (const tag of parseAuditTags(row.pii_entities)) {
    if (tag.type === 'layer') out.layers[tag.layer] = tag.score;
    else if (tag.type === 'detectorRule') out.rules.push(tag.rule);
    else continue;
    any = true;
  }
  return any ? out : null;
}

/** The log-only policy rules that would have decided the row. */
export function wouldDecideOf(row: Pick<AuditRow, 'pii_entities'>): { action: 'block' | 'allow' | 'route'; ruleId: string }[] {
  return parseAuditTags(row.pii_entities).flatMap((t) => (t.type === 'wouldDecide' ? [{ action: t.action, ruleId: t.ruleId }] : []));
}

/** The tags the details list as badges: the detector's are shown on their own. */
export function badgeTags(tags: readonly string[] | null | undefined): AuditTag[] {
  return parseAuditTags(tags).filter((t) => t.type !== 'layer' && t.type !== 'detectorRule');
}
