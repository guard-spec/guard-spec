// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { createContext, useContext } from 'react';
import type { ApiClient } from './api';
import type { Lang, Translate } from './i18n';
import type { Org, Project, Upstream } from './types';

export type Theme = 'light' | 'dark';

export interface AppState {
  api: ApiClient;
  t: Translate;
  lang: Lang;
  theme: Theme;
  notify: (message: string, kind?: 'ok' | 'error') => void;
}

export interface OrgState {
  org: Org;
  projects: Project[];
  /** null: the control plane has no upstream API (needs the routing backend). */
  upstreams: Upstream[] | null;
  upstreamError: string | null;
  reload: () => Promise<void>;
  setOrg: (org: Org) => void;
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

export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
