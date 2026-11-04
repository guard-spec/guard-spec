// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';
import { ErrorBanner, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { DEFAULT_SCAN_ROLES, SCAN_ROLES, type GuardSettings, type ScanRole, type SpotlightMode } from '../types';

type Tri = 'default' | 'on' | 'off';

export function GuardPage() {
  const { api, t, notify } = useApp();
  const { org } = useOrg();
  const { data, error, loading } = useLoad(useCallback(() => api.getGuardSettings(org.id), [api, org.id]));
  const [edited, setDraft] = useState<GuardSettings | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (loading && !data) return <Loading />;
  if (error) return <ErrorBanner error={error} />;
  const draft: GuardSettings = edited ?? data ?? {};

  const roleValue = (r: ScanRole): Tri => {
    const v = draft.scan_roles?.[r];
    return v === undefined ? 'default' : v ? 'on' : 'off';
  };
  const setRole = (r: ScanRole, v: Tri) => {
    const roles = Object.fromEntries(Object.entries(draft.scan_roles ?? {}).filter(([k]) => k !== r));
    if (v !== 'default') roles[r] = v === 'on';
    setDraft({ ...draft, scan_roles: roles });
  };

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      const body: GuardSettings = {};
      if (draft.scan_roles && Object.keys(draft.scan_roles).length > 0) body.scan_roles = draft.scan_roles;
      if (draft.spotlight) body.spotlight = draft.spotlight;
      setDraft(await api.putGuardSettings(org.id, body));
      notify(t('common.saved'));
    } catch (e) {
      setSaveError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="narrow">
      <PageHeader title={t('guard.title')} help={t('guard.help')} />
      <ErrorBanner error={saveError} />
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <fieldset>
          <legend>{t('guard.roles')}</legend>
          <table className="settings-table">
            <tbody>
              {SCAN_ROLES.map((r) => (
                <tr key={r}>
                  <th scope="row">
                    <label htmlFor={`role-${r}`}>{t(`guard.role.${r}` as MessageKey)}</label>
                    <div className="mono small muted">{r}</div>
                  </th>
                  <td>
                    <select id={`role-${r}`} value={roleValue(r)} onChange={(e) => setRole(r, e.target.value as Tri)}>
                      <option value="default">{t('guard.default', { value: DEFAULT_SCAN_ROLES[r] ? t('guard.on') : t('guard.off') })}</option>
                      <option value="on">{t('guard.on')}</option>
                      <option value="off">{t('guard.off')}</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </fieldset>
        <div className="field">
          <label htmlFor="spotlight">{t('guard.spotlight')}</label>
          <select
            id="spotlight"
            value={draft.spotlight ?? ''}
            onChange={(e) => {
              const v = e.target.value as SpotlightMode | '';
              const { spotlight: _old, ...rest } = draft;
              setDraft(v ? { ...rest, spotlight: v } : rest);
            }}
          >
            <option value="">{t('guard.default', { value: t('flow.gatewayDefault') })}</option>
            {(['off', 'delimit', 'datamark'] as const).map((m) => (
              <option key={m} value={m}>
                {t(`guard.spotlight.${m}` as MessageKey)}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? t('common.saving') : t('common.save')}
        </button>
      </form>
    </div>
  );
}
