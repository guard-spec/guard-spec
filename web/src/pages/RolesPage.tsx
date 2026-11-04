// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The role-to-capability table (GET /permissions), read only.

import { Check, Minus } from 'lucide-react';
import { FALLBACK_MATRIX, roleHas } from '../auth/permissions';
import { Badge } from '../components/DataTable';
import { PageHeader } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';

export function RolesPage() {
  const { t } = useApp();
  const { permissions, role } = useOrg();
  const matrix = permissions ?? FALLBACK_MATRIX;
  const groups = new Map<string, typeof matrix.capabilities>();
  for (const c of matrix.capabilities) {
    const g = c.key.split('.')[0] ?? c.key;
    groups.set(g, [...(groups.get(g) ?? []), c]);
  }
  return (
    <div>
      <PageHeader title={t('roles.title')} help={t('roles.help')} />
      {permissions ? null : <div className="banner banner-info">{t('roles.builtin')}</div>}
      <div className="role-cards">
        {matrix.roles.map((r) => (
          <div key={r} className={r === role ? 'card role-card role-card-current' : 'card role-card'}>
            <strong>{t(`org.role.${r}` as MessageKey)}</strong>
            {r === role ? <Badge tone="accent">{t('roles.yours')}</Badge> : null}
            <p className="muted small">{t(`roles.desc.${r}` as MessageKey)}</p>
          </div>
        ))}
      </div>
      <div className="card table-wrap">
        <table className="matrix" data-testid="roles-matrix">
          <caption className="sr-only">{t('roles.title')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('roles.capability')}</th>
              {matrix.roles.map((r) => (
                <th key={r} scope="col" className={r === role ? 'matrix-col matrix-current' : 'matrix-col'}>
                  {t(`org.role.${r}` as MessageKey)}
                </th>
              ))}
            </tr>
          </thead>
          {[...groups.entries()].map(([g, caps]) => (
            <tbody key={g}>
              <tr className="matrix-group">
                <th scope="rowgroup" colSpan={matrix.roles.length + 1}>
                  {g}
                </th>
              </tr>
              {caps.map((c) => (
                <tr key={c.key}>
                  <th scope="row">
                    <span className="mono small">{c.key}</span>
                    {c.description ? <div className="muted small">{c.description}</div> : null}
                  </th>
                  {matrix.roles.map((r) => (
                    <td key={r} className={r === role ? 'matrix-col matrix-current' : 'matrix-col'}>
                      {roleHas(matrix, r, c.key) ? (
                        <Check size={16} className="ok-icon" role="img" aria-label={t('roles.allowed')} />
                      ) : (
                        <Minus size={16} className="muted" role="img" aria-label={t('roles.denied')} />
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          ))}
        </table>
      </div>
    </div>
  );
}
