// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The address of each page under the Vite base (/ui/). Its own module, free
// of import.meta, so that the e2e tests (Node) can visit every page.

export const PATHS = {
  dashboard: 'dashboard',
  'getting-started': 'start',
  threats: 'threats',
  flow: 'flow',
  'policy-history': 'policies/history',
  guard: 'guard',
  input: 'input',
  exemplars: 'exemplars',
  simulator: 'simulator',
  providers: 'providers',
  projects: 'projects',
  models: 'models',
  requests: 'requests',
  activity: 'activity',
  members: 'members',
  roles: 'roles',
  keys: 'keys',
  security: 'security',
  approvals: 'approvals',
  provisioning: 'provisioning',
  config: 'config',
  organization: 'organization',
  'alert-rules': 'alerts/rules',
  'alert-channels': 'alerts/channels',
  'alert-groups': 'alerts/groups',
  'alert-history': 'alerts/history',
  'alert-deliveries': 'alerts/deliveries',
  'siem-export': 'alerts/siem',
  'admin-users': 'admin/users',
  'admin-idps': 'admin/identity-providers',
  'admin-activity': 'admin/activity',
  account: 'account',
  invite: 'invite',
  orgs: 'orgs',
  login: 'login',
  'auth-callback': 'auth/callback',
} as const;
