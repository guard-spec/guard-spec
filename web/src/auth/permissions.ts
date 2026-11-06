// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Role gating of buttons. The control plane's role middleware stays the
// source of truth: the UI only hides what would be refused. GET /permissions
// gives the table (identity contract §4); FALLBACK_MATRIX mirrors the routes
// of a control plane without it.

import { ROLES, type PermissionMatrix, type Role } from '../types';

// Mirrors `capabilities` in cmd/control-plane/members.go (N15); a unit test
// checks that every key the UI gates on is listed here.
export const FALLBACK_MATRIX: PermissionMatrix = {
  roles: [...ROLES],
  capabilities: [
    { key: 'org.read', min_role: 'viewer', description: 'View the organization, its projects, upstreams and settings' },
    { key: 'org.settings.write', min_role: 'admin', description: 'Change organization settings and guard settings' },
    { key: 'policies.read', min_role: 'viewer', description: 'View policies and run the simulator' },
    { key: 'policies.write', min_role: 'admin', description: 'Create, edit and delete policies' },
    { key: 'requests.read', min_role: 'viewer', description: 'View the request log' },
    { key: 'exemplars.read', min_role: 'viewer', description: 'View L3 exemplars' },
    { key: 'exemplars.write', min_role: 'admin', description: 'Create, edit and delete L3 exemplars' },
    { key: 'upstreams.write', min_role: 'admin', description: 'Manage model providers, defaults and connection tests' },
    { key: 'projects.write', min_role: 'admin', description: 'Create projects and manage project members' },
    { key: 'config.write', min_role: 'admin', description: 'Apply the configuration file' },
    { key: 'api_keys.manage', min_role: 'admin', description: 'Create, change and revoke API keys' },
    { key: 'members.read', min_role: 'admin', description: 'View members and invites' },
    { key: 'members.write', min_role: 'admin', description: 'Invite members, change roles below owner, remove members, revoke sessions' },
    { key: 'members.owner', min_role: 'owner', description: 'Grant the owner role and change or remove owners' },
    { key: 'members.reset_mfa', min_role: 'owner', description: "Reset a member's two-factor authentication" },
    { key: 'activity.read', min_role: 'admin', description: 'View the activity log' },
    { key: 'security.read', min_role: 'admin', description: 'View the security policy' },
    { key: 'alerts.read', min_role: 'viewer', description: 'View alert rules, channels, groups and alert history' },
    { key: 'alerts.write', min_role: 'admin', description: 'Manage alert rules, notification channels and user groups; send tests' },
    { key: 'shadow.read', min_role: 'viewer', description: 'View the classifier models and the shadow comparison' },
    { key: 'shadow.disagreements.read', min_role: 'admin', description: 'View the requests where the shadow model disagrees' },
    { key: 'alerts.deliveries.read', min_role: 'admin', description: 'View the notification delivery log' },
    { key: 'security.write', min_role: 'owner', description: 'Change the security policy (2FA, login methods, domain join)' },
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
