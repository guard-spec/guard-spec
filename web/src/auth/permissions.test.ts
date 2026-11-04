// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { PermissionMatrix } from '../types';
import { atLeast, can, canManageMember, grantableRoles, roleHas } from './permissions';

const server: PermissionMatrix = {
  roles: ['viewer', 'member', 'admin', 'owner'],
  capabilities: [
    { key: 'policies.write', min_role: 'member' },
    { key: 'custom.thing', min_role: 'owner' },
  ],
};

describe('permissions', () => {
  it('orders roles', () => {
    expect(atLeast('owner', 'admin')).toBe(true);
    expect(atLeast('member', 'admin')).toBe(false);
    expect(atLeast('viewer', 'viewer')).toBe(true);
  });

  it('uses the built-in table without GET /permissions', () => {
    expect(can('viewer', 'policies.write')).toBe(false);
    expect(can('admin', 'policies.write')).toBe(true);
    expect(can('admin', 'security.write')).toBe(false);
    expect(can('owner', 'security.write')).toBe(true);
    expect(can('admin', 'members.reset_mfa')).toBe(false);
  });

  it('prefers the server table and falls back per capability', () => {
    expect(can('member', 'policies.write', server)).toBe(true);
    expect(can('admin', 'custom.thing', server)).toBe(false);
    expect(can('admin', 'api_keys.write', server)).toBe(true); // from the built-in table
  });

  it('lets the server decide for an unknown role or capability', () => {
    expect(can(null, 'security.write')).toBe(true);
    expect(can('viewer', 'no.such.capability')).toBe(true);
  });

  it('gates role changes like the contract: only owners grant or change owner', () => {
    expect(grantableRoles('owner')).toEqual(['viewer', 'member', 'admin', 'owner']);
    expect(grantableRoles('admin')).toEqual(['viewer', 'member', 'admin']);
    expect(grantableRoles('member')).toEqual([]);
    expect(canManageMember('admin', 'member')).toBe(true);
    expect(canManageMember('admin', 'owner')).toBe(false);
    expect(canManageMember('owner', 'owner')).toBe(true);
    expect(canManageMember('member', 'viewer')).toBe(false);
    expect(canManageMember(null, 'owner')).toBe(true);
  });

  it('fills the matrix cells', () => {
    expect(roleHas(server, 'viewer', 'policies.write')).toBe(false);
    expect(roleHas(server, 'member', 'policies.write')).toBe(true);
    expect(roleHas(server, 'owner', 'missing')).toBe(false);
  });
});
