// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The sidebar (identity contract §8): groups in sentence case, one lucide
// icon per page. Instance admin pages show only to instance admins.

import { Bell, BellRing, Boxes, Building2, ClipboardCheck, Cpu, FileCode, FileInput, Fingerprint, FlaskConical, FolderKanban, History, Key, KeyRound, LayoutDashboard, Library, ListChecks, Lock, Radio, ScrollText, Send, ShieldCheck, UserCheck, UserCog, Users, UsersRound, Workflow, type LucideIcon } from 'lucide-react';
import type { MessageKey } from './i18n';
import type { Route } from './router';

export interface NavItem {
  route: Route;
  label: MessageKey;
  icon: LucideIcon;
  /** Shown only with this capability (see auth/permissions). */
  capability?: string;
}

export interface NavGroup {
  id: string;
  label: MessageKey;
  items: NavItem[];
  instanceAdmin?: boolean;
}

export const NAV: NavGroup[] = [
  { id: 'overview', label: 'navg.overview', items: [{ route: 'dashboard', label: 'nav.dashboard', icon: LayoutDashboard }] },
  {
    id: 'protection',
    label: 'navg.protection',
    items: [
      { route: 'flow', label: 'nav.flow', icon: Workflow },
      { route: 'guard', label: 'nav.guard', icon: ShieldCheck },
      { route: 'input', label: 'nav.input', icon: FileInput },
      { route: 'exemplars', label: 'nav.exemplars', icon: Library },
      { route: 'simulator', label: 'nav.simulator', icon: FlaskConical },
      { route: 'policy-history', label: 'nav.policyHistory', icon: History },
    ],
  },
  {
    id: 'models',
    label: 'navg.models',
    items: [
      { route: 'providers', label: 'nav.providers', icon: Cpu },
      { route: 'projects', label: 'nav.projects', icon: FolderKanban },
      { route: 'models', label: 'nav.models', icon: Boxes },
    ],
  },
  {
    id: 'observability',
    label: 'navg.observability',
    items: [
      { route: 'requests', label: 'nav.requests', icon: ScrollText },
      { route: 'activity', label: 'nav.activity', icon: History, capability: 'activity.read' },
    ],
  },
  {
    id: 'alerts',
    label: 'navg.alerts',
    items: [
      { route: 'alert-rules', label: 'nav.alertRules', icon: Bell },
      { route: 'alert-channels', label: 'nav.alertChannels', icon: Send },
      { route: 'alert-groups', label: 'nav.alertGroups', icon: UsersRound },
      { route: 'alert-history', label: 'nav.alertHistory', icon: BellRing },
      { route: 'alert-deliveries', label: 'nav.alertDeliveries', icon: ListChecks, capability: 'alerts.deliveries.read' },
      { route: 'siem-export', label: 'nav.siem', icon: Radio, capability: 'siem.manage' },
    ],
  },
  {
    id: 'access',
    label: 'navg.access',
    items: [
      { route: 'members', label: 'nav.members', icon: Users, capability: 'members.read' },
      { route: 'roles', label: 'nav.roles', icon: KeyRound },
      { route: 'keys', label: 'nav.keys', icon: Key, capability: 'api_keys.manage' },
      { route: 'security', label: 'nav.security', icon: Lock, capability: 'security.read' },
      { route: 'approvals', label: 'nav.approvals', icon: ClipboardCheck, capability: 'approvals.read' },
      { route: 'provisioning', label: 'nav.provisioning', icon: UserCheck, capability: 'security.read' },
    ],
  },
  {
    id: 'settings',
    label: 'navg.settings',
    items: [
      { route: 'config', label: 'nav.config', icon: FileCode },
      { route: 'organization', label: 'nav.organization', icon: Building2 },
    ],
  },
  {
    id: 'instance',
    label: 'navg.instance',
    instanceAdmin: true,
    items: [
      { route: 'admin-users', label: 'nav.adminUsers', icon: UserCog },
      { route: 'admin-idps', label: 'nav.adminIdps', icon: Fingerprint },
      { route: 'admin-activity', label: 'nav.adminActivity', icon: ScrollText },
    ],
  },
];

/** The group and item of a page, for the breadcrumbs. */
export function navEntry(route: Route): { group: NavGroup; item: NavItem } | null {
  for (const group of NAV) {
    const item = group.items.find((i) => i.route === route);
    if (item) return { group, item };
  }
  return null;
}
