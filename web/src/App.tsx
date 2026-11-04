// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ApiClient } from './api';
import { Loading } from './components/ui';
import { AppContext, errorText, OrgContext, useApp, type AppState, type OrgState, type Theme } from './context';
import { translator, type Lang, type MessageKey } from './i18n';
import { AuditPage } from './pages/AuditPage';
import { ExemplarsPage } from './pages/ExemplarsPage';
import { GuardPage } from './pages/GuardPage';
import { KeysPage } from './pages/KeysPage';
import { LoginPage } from './pages/LoginPage';
import { OrgPicker } from './pages/OrgPicker';
import { ProjectsPage } from './pages/ProjectsPage';
import { UpstreamsPage } from './pages/UpstreamsPage';
import { href, navigate, useRoute, type Route } from './router';
import { prefs, session } from './session';
import type { Org, Project, Upstream } from './types';

const FlowPage = lazy(() => import('./flow/FlowPage'));
const ConfigPage = lazy(() => import('./pages/ConfigPage'));

const NAV: { route: Route; label: MessageKey }[] = [
  { route: 'flow', label: 'nav.flow' },
  { route: 'upstreams', label: 'nav.upstreams' },
  { route: 'config', label: 'nav.config' },
  { route: 'guard', label: 'nav.guard' },
  { route: 'keys', label: 'nav.keys' },
  { route: 'projects', label: 'nav.projects' },
  { route: 'exemplars', label: 'nav.exemplars' },
  { route: 'audit', label: 'nav.audit' },
];

function initialTheme(): Theme {
  const saved = prefs.get('theme');
  if (saved === 'light' || saved === 'dark') return saved;
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
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [lang, setLang] = useState<Lang>(initialLang);
  const [token, setToken] = useState<string | null>(session.token);
  const [expired, setExpired] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const route = useRoute();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    prefs.set('theme', theme);
  }, [theme]);
  useEffect(() => {
    document.documentElement.lang = lang;
    prefs.set('lang', lang);
  }, [lang]);

  const logout = useCallback((wasExpired = false) => {
    session.clear();
    // Org names are not left behind on a shared browser.
    prefs.clearRecentOrgs();
    setToken(null);
    setExpired(wasExpired);
    navigate('login', true, undefined, true);
  }, []);

  const api = useMemo(
    () =>
      new ApiClient({
        getToken: () => session.token(),
        onUnauthorized: () => logout(true),
      }),
    [logout],
  );

  const t = useMemo(() => translator(lang), [lang]);
  const notify = useCallback((message: string, kind: 'ok' | 'error' = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts((ts) => [...ts, { id, message, kind }]);
    window.setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 5000);
  }, []);

  const app: AppState = useMemo(() => ({ api, t, lang, theme, notify }), [api, t, lang, theme, notify]);

  const controls = (
    <div className="top-controls">
      <label className="sr-only" htmlFor="lang-select">
        {t('app.language')}
      </label>
      <select id="lang-select" value={lang} onChange={(e) => setLang(e.target.value as Lang)}>
        <option value="en">English</option>
        <option value="vi">Tiếng Việt</option>
      </select>
      <button
        type="button"
        className="btn"
        aria-label={`${t('app.theme')}: ${theme === 'dark' ? t('app.themeDark') : t('app.themeLight')}`}
        onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
      >
        {theme === 'dark' ? '☾' : '☀'} {theme === 'dark' ? t('app.themeDark') : t('app.themeLight')}
      </button>
    </div>
  );

  let content: ReactNode;
  if (!token) {
    content = (
      <LoginPage
        expired={expired}
        controls={controls}
        onLogin={(tok) => {
          session.setToken(tok);
          setToken(tok);
          setExpired(false);
          navigate(session.orgId() ? 'flow' : 'orgs', true);
        }}
      />
    );
  } else {
    content = <Authed route={route} controls={controls} onLogout={() => logout(false)} />;
  }

  return (
    <AppContext.Provider value={app}>
      {content}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className={`toast toast-${x.kind}`}>
            {x.message}
          </div>
        ))}
      </div>
    </AppContext.Provider>
  );
}

function Authed({ route, controls, onLogout }: { route: Route; controls: ReactNode; onLogout: () => void }) {
  const { api, t } = useApp();
  const [org, setOrgState] = useState<Org | null>(null);
  const [orgError, setOrgError] = useState<string | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [upstreams, setUpstreams] = useState<Upstream[] | null>(null);
  const [upstreamError, setUpstreamError] = useState<string | null>(null);
  const [orgId, setOrgId] = useState<string | null>(session.orgId);

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

  const choose = useCallback((o: Org) => {
    session.setOrgId(o.id);
    setOrgId(o.id);
    setOrgState(o);
    navigate('flow');
  }, []);

  if (!orgId || route === 'orgs' || route === 'login') {
    return (
      <Shell controls={controls} onLogout={onLogout} route={route} org={null}>
        <OrgPicker onChoose={choose} />
      </Shell>
    );
  }
  if (!org) {
    return (
      <Shell controls={controls} onLogout={onLogout} route={route} org={null}>
        {orgError ? (
          <div className="banner banner-error" role="alert">
            {t('org.notFound', { error: orgError })}{' '}
            <a href={href('orgs')} onClick={(e) => {
                e.preventDefault();
                navigate('orgs');
              }}>
              {t('app.switchOrg')}
            </a>
          </div>
        ) : (
          <Loading />
        )}
      </Shell>
    );
  }

  const orgState: OrgState = { org, projects, upstreams, upstreamError, reload: load, setOrg: setOrgState };
  return (
    <OrgContext.Provider value={orgState}>
      <Shell controls={controls} onLogout={onLogout} route={route} org={org}>
        <Suspense fallback={<Loading />}>
          {route === 'flow' && <FlowPage />}
          {route === 'upstreams' && <UpstreamsPage />}
          {route === 'config' && <ConfigPage />}
          {route === 'guard' && <GuardPage />}
          {route === 'keys' && <KeysPage />}
          {route === 'projects' && <ProjectsPage />}
          {route === 'exemplars' && <ExemplarsPage />}
          {route === 'audit' && <AuditPage />}
        </Suspense>
      </Shell>
    </OrgContext.Provider>
  );
}

function Shell({
  children,
  controls,
  onLogout,
  route,
  org,
}: {
  children: ReactNode;
  controls: ReactNode;
  onLogout: () => void;
  route: Route;
  org: Org | null;
}) {
  const { t } = useApp();
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        {t('app.skip')}
      </a>
      <aside className="sidebar">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" className="brand-shield" />
            <path d="m10 16 4 4 8-9" className="brand-check" />
          </svg>
          <div>
            <strong>{t('app.title')}</strong>
            <span className="muted">{t('app.subtitle')}</span>
          </div>
        </div>
        {org ? (
          <div className="org-box">
            <span className="muted">{t('app.org')}</span>
            <strong title={org.id}>{org.name}</strong>
            <a href={href('orgs')} onClick={(e) => {
                e.preventDefault();
                navigate('orgs');
              }}>
              {t('app.switchOrg')}
            </a>
          </div>
        ) : null}
        {org ? (
          <nav aria-label={t('app.mainNav')}>
            <ul className="nav">
              {NAV.map((n) => (
                <li key={n.route}>
                  <a
                    href={href(n.route)}
                    aria-current={route === n.route ? 'page' : undefined}
                    onClick={(e) => {
                      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
                      e.preventDefault();
                      navigate(n.route);
                    }}
                  >
                    {t(n.label)}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        ) : null}
        <div className="sidebar-foot">
          {controls}
          <button type="button" className="btn btn-block" onClick={onLogout}>
            {t('app.logout')}
          </button>
        </div>
      </aside>
      <main id="main" className="main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
