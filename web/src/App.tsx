// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { CircleCheck, CircleX, X } from 'lucide-react';
import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ComponentType } from 'react';
import { ApiClient, isNotFound } from './api';
import { authErrorText } from './auth/errors';
import { can as canDo } from './auth/permissions';
import { Loading } from './components/ui';
import { AppContext, errorText, OrgContext, useApp, type AppState, type OrgState, type Theme, type ThemePref } from './context';
import { translator, type Lang } from './i18n';
import type { NavGroup } from './nav';
import { ActivityPage } from './pages/ActivityPage';
import { DashboardPage } from './pages/DashboardPage';
import { ExemplarsPage } from './pages/ExemplarsPage';
import { GuardPage } from './pages/GuardPage';
import { KeysPage } from './pages/KeysPage';
import { LoginPage } from './pages/LoginPage';
import { MembersPage } from './pages/MembersPage';
import { OrganizationPage } from './pages/OrganizationPage';
import { OrgPicker } from './pages/OrgPicker';
import { ProjectsPage } from './pages/ProjectsPage';
import { ProvidersPage } from './pages/ProvidersPage';
import { RequestLogPage } from './pages/RequestLogPage';
import { RolesPage } from './pages/RolesPage';
import { SecurityPage } from './pages/SecurityPage';
import { clearHash, href, navigate, useRoute, type Route } from './router';
import { prefs, session } from './session';
import { Shell } from './shell/Shell';
import type { Me, Org, PermissionMatrix, Project, Role, Upstream } from './types';

const FlowPage = lazy(() => import('./flow/FlowPage'));
const ConfigPage = lazy(() => import('./pages/ConfigPage'));
const SimulatorPage = lazy(() => import('./pages/SimulatorPage'));
const AccountPage = lazy(() => import('./pages/AccountPage'));
const AdminUsersPage = lazy(() => import('./pages/AdminUsersPage'));
const IdentityProvidersPage = lazy(() => import('./pages/IdentityProvidersPage'));

/** Pages of an organization. */
const ORG_PAGES: Partial<Record<Route, ComponentType>> = {
  dashboard: DashboardPage,
  flow: FlowPage,
  guard: GuardPage,
  exemplars: ExemplarsPage,
  simulator: SimulatorPage,
  providers: ProvidersPage,
  projects: ProjectsPage,
  requests: RequestLogPage,
  activity: ActivityPage,
  members: MembersPage,
  roles: RolesPage,
  keys: KeysPage,
  security: SecurityPage,
  config: ConfigPage,
  organization: OrganizationPage,
};

/** Pages that need no organization. */
const USER_PAGES: Partial<Record<Route, ComponentType>> = {
  account: AccountPage,
  'admin-users': AdminUsersPage,
  'admin-idps': IdentityProvidersPage,
};

function initialThemePref(): ThemePref {
  const saved = prefs.get('theme');
  return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'system';
}

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function initialLang(): Lang {
  return prefs.get('lang') === 'vi' ? 'vi' : 'en';
}

interface Toast {
  id: number;
  message: string;
  kind: 'ok' | 'error';
}

export function App() {
  const [themePref, setThemePref] = useState<ThemePref>(initialThemePref);
  const [sysTheme, setSysTheme] = useState<Theme>(systemTheme);
  const [lang, setLang] = useState<Lang>(initialLang);
  const [token, setToken] = useState<string | null>(session.token);
  const [expired, setExpired] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const route = useRoute();
  const theme: Theme = themePref === 'system' ? sysTheme : themePref;

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const on = () => setSysTheme(mq.matches ? 'dark' : 'light');
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    prefs.set('theme', themePref);
  }, [theme, themePref]);
  useEffect(() => {
    document.documentElement.lang = lang;
    prefs.set('lang', lang);
  }, [lang]);

  const endSession = useCallback((wasExpired: boolean) => {
    session.clear();
    // Org names are not left behind on a shared browser.
    prefs.clearRecentOrgs();
    setToken(null);
    setMe(null);
    setExpired(wasExpired);
    navigate('login', true, undefined, true);
  }, []);

  const api = useMemo(
    () =>
      new ApiClient({
        getToken: () => session.token(),
        onUnauthorized: () => endSession(true),
      }),
    [endSession],
  );

  const logout = useCallback(() => {
    // Revoke the session on the server (identity contract §1); older control planes have no such call.
    void api.logout().catch(() => undefined);
    endSession(false);
  }, [api, endSession]);

  const reloadMe = useCallback(async () => {
    if (!session.token()) return;
    try {
      setMe(await api.getMe());
    } catch {
      setMe(null);
    }
  }, [api]);

  useEffect(() => {
    if (token) void reloadMe();
  }, [token, reloadMe]);

  const t = useMemo(() => translator(lang), [lang]);
  const dismiss = useCallback((id: number) => setToasts((ts) => ts.filter((x) => x.id !== id)), []);
  const notify = useCallback(
    (message: string, kind: 'ok' | 'error' = 'ok') => {
      const id = Date.now() + Math.random();
      setToasts((ts) => [...ts, { id, message, kind }]);
      window.setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 5000);
    },
    [dismiss],
  );

  const app: AppState = useMemo(
    () => ({ api, t, lang, setLang, theme, themePref, setThemePref, notify, me, reloadMe, logout }),
    [api, t, lang, theme, themePref, notify, me, reloadMe, logout],
  );

  // Back from linking an SSO identity while signed in: the account page shows it.
  useEffect(() => {
    if (token && route === 'auth-callback') {
      // N15 sends ?linked=<providerId> on success, ?error=<code> on failure.
      const q = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
      const err = q.get('error');
      clearHash();
      if (err) notify(t('account.linkFailed', { error: authErrorText(err, t) }), 'error');
      else if (q.get('linked')) {
        notify(t('account.linked'));
        void reloadMe();
      }
      navigate('account', true);
    }
  }, [token, route, notify, t, reloadMe]);

  let content;
  if (!token) {
    content = (
      <LoginPage
        // A callback that arrives on an open sign-in page (a hash change) starts over.
        key={route === 'auth-callback' ? 'callback' : 'login'}
        expired={expired}
        callback={route === 'auth-callback'}
        onLogin={(tok) => {
          session.setToken(tok);
          setToken(tok);
          setExpired(false);
          navigate(session.orgId() ? 'dashboard' : 'orgs', true);
        }}
      />
    );
  } else {
    content = <Authed route={route} />;
  }

  return (
    <AppContext.Provider value={app}>
      {content}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className={`toast toast-${x.kind}`}>
            {x.kind === 'ok' ? <CircleCheck size={16} aria-hidden="true" className="toast-icon" /> : <CircleX size={16} aria-hidden="true" className="toast-icon" />}
            <span>{x.message}</span>
            <button type="button" className="btn-icon" aria-label={t('common.dismiss')} onClick={() => dismiss(x.id)}>
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        ))}
      </div>
    </AppContext.Provider>
  );
}

function Authed({ route }: { route: Route }) {
  const { api, t, me } = useApp();
  const [org, setOrgState] = useState<Org | null>(null);
  const [orgError, setOrgError] = useState<string | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [upstreams, setUpstreams] = useState<Upstream[] | null>(null);
  const [upstreamError, setUpstreamError] = useState<string | null>(null);
  const [orgId, setOrgId] = useState<string | null>(session.orgId);
  const [role, setRole] = useState<Role | null>(null);
  const [permissions, setPermissions] = useState<PermissionMatrix | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      const [o, p] = await Promise.all([api.getOrg(orgId), api.listProjects(orgId)]);
      setOrgState(o);
      setProjects(p);
      setOrgError(null);
      prefs.addRecentOrg({ id: o.id, name: o.name });
    } catch (e) {
      setOrgError(errorText(e));
    }
    try {
      setUpstreams(await api.listUpstreams(orgId));
      setUpstreamError(null);
    } catch (e) {
      setUpstreams(null);
      setUpstreamError(errorText(e));
    }
  }, [api, orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  // The role in this org (from the org list) and the permission table; both optional.
  useEffect(() => {
    if (!orgId) return;
    let live = true;
    api.listMyOrgs().then(
      (ms) => live && setRole(ms.find((m) => m.id === orgId)?.role ?? null),
      () => live && setRole(null),
    );
    api.getPermissions().then(
      (p) => live && setPermissions(p),
      (e: unknown) => live && !isNotFound(e) && setPermissions(null),
    );
    return () => {
      live = false;
    };
  }, [api, orgId]);

  const choose = useCallback((o: Org) => {
    session.setOrgId(o.id);
    setOrgId(o.id);
    setOrgState(o);
    navigate('dashboard');
  }, []);

  const visible = useCallback(
    (group: NavGroup, capability: string | undefined) => {
      if (group.instanceAdmin) return me?.is_instance_admin === true;
      return capability ? canDo(role, capability, permissions) : true;
    },
    [me, role, permissions],
  );

  const UserPage = USER_PAGES[route];
  if (UserPage) {
    return (
      <Shell route={route} org={org} visible={visible}>
        <Suspense fallback={<Loading />}>
          <UserPage />
        </Suspense>
      </Shell>
    );
  }

  if (!orgId || route === 'orgs' || route === 'login' || route === 'auth-callback') {
    return (
      <Shell route="orgs" org={null} visible={visible}>
        <OrgPicker onChoose={choose} />
      </Shell>
    );
  }
  if (!org) {
    return (
      <Shell route={route} org={null} visible={visible}>
        {orgError ? (
          <div className="banner banner-error" role="alert">
            {t('org.notFound', { error: orgError })}{' '}
            <a
              href={href('orgs')}
              onClick={(e) => {
                e.preventDefault();
                navigate('orgs');
              }}
            >
              {t('app.switchOrg')}
            </a>
          </div>
        ) : (
          <Loading />
        )}
      </Shell>
    );
  }

  const orgState: OrgState = {
    org,
    projects,
    upstreams,
    upstreamError,
    reload: load,
    setOrg: setOrgState,
    role,
    permissions,
    can: (capability: string) => canDo(role, capability, permissions),
  };
  const Page = ORG_PAGES[route] ?? DashboardPage;
  return (
    <OrgContext.Provider value={orgState}>
      <Shell route={route} org={org} visible={visible}>
        <Suspense fallback={<Loading />}>
          <Page />
        </Suspense>
      </Shell>
    </OrgContext.Provider>
  );
}
