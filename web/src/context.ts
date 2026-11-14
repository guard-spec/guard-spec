// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { createContext, useContext } from 'react';
import type { ApiClient } from './api';
import type { Lang, Translate } from './i18n';
import type { Me, Org, PermissionMatrix, Project, Role, Upstream } from './types';

export type Theme = 'light' | 'dark';
/** The user's choice; system follows the OS. */
export type ThemePref = Theme | 'system';

export interface AppState {
  api: ApiClient;
  t: Translate;
  lang: Lang;
  setLang: (l: Lang) => void;
  /** The theme in effect. */
  theme: Theme;
  themePref: ThemePref;
  setThemePref: (t: ThemePref) => void;
  notify: (message: string, kind?: 'ok' | 'error') => void;
  /** GET /auth/me; null while loading or on a control plane without it. */
  me: Me | null;
  reloadMe: () => Promise<void>;
  logout: () => void;
}

export interface OrgState {
  org: Org;
  projects: Project[];
  /** The model providers (custom backends left out); null: the control plane has no upstream API. */
  upstreams: Upstream[] | null;
  upstreamError: string | null;
  reload: () => Promise<void>;
  setOrg: (org: Org) => void;
  /** The user's role in this org; null when the control plane did not say. */
  role: Role | null;
  /** GET /permissions, or null (the built-in table applies). */
  permissions: PermissionMatrix | null;
  can: (capability: string) => boolean;
}

export const AppContext = createContext<AppState | null>(null);
export const OrgContext = createContext<OrgState | null>(null);

export function useApp(): AppState {
  const v = useContext(AppContext);
  if (!v) throw new Error('useApp outside AppContext');
  return v;
}

export function useOrg(): OrgState {
  const v = useContext(OrgContext);
  if (!v) throw new Error('useOrg outside OrgContext');
  return v;
}

/** s, or undefined when it is empty: for `nonEmpty(a) ?? b` fallbacks. */
export function nonEmpty(s: string | null | undefined): string | undefined {
  return s === '' || s === null ? undefined : s;
}

export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
