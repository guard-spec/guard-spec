// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The detector's explanation in the request log (cmd/gateway/detector_tags.go)
// and the helpers of the false-positive panel.

import { describe, expect, it } from 'vitest';
import detectorTagsGo from '../../../cmd/gateway/detector_tags.go?raw';
import { badgeTags, detectorOf, parseAuditTag, wouldDecideOf } from './auditTags';
import { exemplarSource, offersFix, scoreText } from './falsePositive';

const RULE = '3f2c1a9e-0b7d-4c5e-9f10-123456789abc';

describe('detector tags', () => {
  it('reads layer scores and fired rules as the gateway writes them', () => {
    // The gateway's format, as its comment documents it.
    expect(detectorTagsGo).toContain('detector:l1=0.912');
    expect(detectorTagsGo).toContain('detector:rule=');
    expect(parseAuditTag('detector:l2=0.351')).toEqual({ type: 'layer', layer: 'l2', score: 0.351, raw: 'detector:l2=0.351' });
    expect(parseAuditTag('detector:rule=l2:jailbreak')).toMatchObject({ type: 'detectorRule', rule: 'l2:jailbreak' });
    expect(parseAuditTag('detector:l4=1')).toMatchObject({ type: 'other' });
  });

  it('explains a row, or says it cannot', () => {
    const row = { pii_entities: ['input:pii_email=1', 'detector:l1=0.990', 'detector:l3=0.020', 'detector:rule=di.override', `policy:would_block=${RULE}`] };
    expect(detectorOf(row)).toEqual({ layers: { l1: 0.99, l3: 0.02 }, rules: ['di.override'] });
    expect(detectorOf({ pii_entities: ['input:pii_email=1'] })).toBeNull();
    expect(detectorOf({ pii_entities: null })).toBeNull();
    expect(wouldDecideOf(row)).toEqual([{ action: 'block', ruleId: RULE }]);
    expect(badgeTags(row.pii_entities).map((t) => t.raw)).toEqual(['input:pii_email=1', `policy:would_block=${RULE}`]);
  });
});

describe('false-positive panel', () => {
  it('offers a fix for refused rows and log-only refusals', () => {
    expect(offersFix({ action: 'block', pii_entities: null })).toBe(true);
    expect(offersFix({ action: 'allow', pii_entities: [`policy:would_block=${RULE}`] })).toBe(true);
    expect(offersFix({ action: 'allow', pii_entities: ['detector:l1=0.100'] })).toBe(false);
    expect(offersFix({ action: 'route', pii_entities: null })).toBe(false);
  });

  it('names an exemplar after its request, without content', () => {
    expect(exemplarSource({ id: '7c1ea5b2-0000-4000-8000-000000000001', created_at: '2026-11-04T07:52:00Z' })).toBe('false positive 2026-11-04 request 7c1ea5b2');
    expect(scoreText(0.705)).toBe('0.70');
  });
});
