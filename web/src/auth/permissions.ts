// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Role gating of buttons. The control plane's role middleware stays the
// source of truth: the UI only hides what would be refused. GET /permissions
// gives the table (identity contract §4); FALLBACK_MATRIX mirrors the routes
// of a control plane without it.

import { ROLES, type PermissionMatrix, type Role } from '../types';

export const FALLBACK_MATRIX: PermissionMatrix = {
  roles: [...ROLES],
  capabilities: [
    { key: 'org.read', min_role: 'viewer' },
    { key: 'requests.read', min_role: 'viewer' },
    { key: 'policies.read', min_role: 'viewer' },
    { key: 'policies.simulate', min_role: 'viewer' },
    { key: 'policies.write', min_role: 'admin' },
    { key: 'upstreams.write', min_role: 'admin' },
    { key: 'upstreams.test', min_role: 'admin' },
    { key: 'projects.write', min_role: 'admin' },
    { key: 'api_keys.write', min_role: 'admin' },
    { key: 'exemplars.write', min_role: 'admin' },
    { key: 'guard.write', min_role: 'admin' },
    { key: 'config.write', min_role: 'admin' },
    { key: 'members.read', min_role: 'admin' },
    { key: 'members.write', min_role: 'admin' },
    { key: 'invites.write', min_role: 'admin' },
    { key: 'activity.read', min_role: 'admin' },
    { key: 'security.read', min_role: 'admin' },
    { key: 'security.write', min_role: 'owner' },
    { key: 'members.reset_mfa', min_role: 'owner' },
    { key: 'org.write', min_role: 'owner' },
  ],
};

export function roleRank(r: Role): number {
  return ROLES.indexOf(r);
}

export function atLeast(role: Role, min: Role): boolean {
  return roleRank(role) >= roleRank(min);
}

/**
 * Whether role may use capability. An unknown role (null: the control plane
 * did not say) or an unknown capability is allowed: the server decides.
 */
export function can(role: Role | null, capability: string, matrix: PermissionMatrix | null = null): boolean {
  if (role === null) return true;
  const cap = matrix?.capabilities.find((c) => c.key === capability) ?? FALLBACK_MATRIX.capabilities.find((c) => c.key === capability);
  if (!cap) return true;
  return atLeast(role, cap.min_role);
}

/** The roles actor may give a member (identity contract §4: only an owner grants owner). */
export function grantableRoles(actor: Role | null): Role[] {
  if (actor === null || actor === 'owner') return [...ROLES];
  if (actor === 'admin') return ROLES.filter((r) => r !== 'owner');
  return [];
}

/** Whether actor may change or remove a member who has role target. */
export function canManageMember(actor: Role | null, target: Role): boolean {
  if (actor === null) return true;
  if (!atLeast(actor, 'admin')) return false;
  return target !== 'owner' || actor === 'owner';
}

/** Whether a role column of the matrix includes capability (min_role at or below it). */
export function roleHas(matrix: PermissionMatrix, role: Role, capability: string): boolean {
  const cap = matrix.capabilities.find((c) => c.key === capability);
  return cap ? atLeast(role, cap.min_role) : false;
}
