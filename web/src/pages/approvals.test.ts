// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { translator } from '../i18n';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import type { OrgSecurity } from '../types';
import { ApiError } from '../api';
import { approvalText, cancelledOnApprove, decidable, orgLabel } from './ApprovalsPage';
import { securityBody, validateSecurity } from './SecurityPage';

const base: OrgSecurity = { require_mfa: false, sso_satisfies_mfa: false, allowed_login_methods: null, domain_join: [], session_lifetime_hours: 12 };

describe('two-person approval', () => {
  const t = translator('en');

  it('names a request by its kind and target', () => {
    expect(approvalText(t, { kind: 'policy.disable', target: 'id', target_label: 'strict' })).toBe('Disable policy “strict”');
    expect(approvalText(t, { kind: 'policy.delete', target: 'id', target_label: null })).toBe('Delete policy “id”');
    expect(approvalText(t, { kind: 'content_storage.enable', target: 'org' })).toBe('Store prompt and answer content in the request log');
    expect(approvalText(translator('vi'), { kind: 'org.delete', target: 'org' })).toBe(vi['approvals.kind.org.delete']);
  });

  it('decides only pending requests before their time', () => {
    const now = Date.parse('2026-11-11T00:00:00Z');
    expect(decidable({ status: 'pending', expires_at: '2026-11-12T00:00:00Z' }, now)).toBe(true);
    expect(decidable({ status: 'pending', expires_at: '2026-11-10T00:00:00Z' }, now)).toBe(false);
    expect(decidable({ status: 'approved', expires_at: '2026-11-12T00:00:00Z' }, now)).toBe(false);
  });

  it('reads a cancelled approval and names the organization of an instance-wide deletion', () => {
    expect(cancelledOnApprove(new ApiError(409, 'the policy no longer exists; the request is cancelled', { code: 'approval_cancelled' }))).toBe(true);
    expect(cancelledOnApprove(new ApiError(409, 'this request is no longer pending', { code: 'approval_not_pending' }))).toBe(false);
    expect(cancelledOnApprove(new Error('x'))).toBe(false);
    expect(orgLabel({ payload: { name: 'Acme', slug: 'acme-prod' }, org_id: 'o' })).toBe('Acme (acme-prod)');
    expect(orgLabel({ payload: { slug: 'acme' }, org_id: 'o' })).toBe('acme');
    expect(orgLabel({ payload: {}, org_id: 'o' })).toBe('o');
    expect(t('approvals.status.cancelled')).toBe('Cancelled');
  });

  it('validates and sends the security settings', () => {
    expect(validateSecurity({ ...base, two_person_approval: true, approval_expiry_hours: 48 })).toEqual([]);
    expect(validateSecurity({ ...base, approval_expiry_hours: 0 })).toEqual(['approvalExpiry']);
    expect(validateSecurity({ ...base, approval_expiry_hours: 721 })).toEqual(['approvalExpiry']);
    expect(securityBody(base, false)).toMatchObject({ two_person_approval: false, approval_expiry_hours: 24 });
    expect(securityBody({ ...base, two_person_approval: true, approval_expiry_hours: 6 }, false)).toMatchObject({ two_person_approval: true, approval_expiry_hours: 6 });
  });

  it('has every approval message in both languages', () => {
    for (const key of Object.keys(en).filter((k) => k.startsWith('approvals.') || k.startsWith('sec.twoPerson') || k.startsWith('sec.approval') || k === 'policy.deleteNeedsDisabled' || k === 'history.rolledBackDisablePending')) {
      expect(vi, key).toHaveProperty(key);
    }
  });
});
