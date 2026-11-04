// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { ArrowLeftRight } from 'lucide-react';
import { Badge } from '../components/DataTable';
import { CopyButton, formatTime, PageHeader } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink } from '../router';

export function OrganizationPage() {
  const { t } = useApp();
  const { org, projects, upstreams, role } = useOrg();
  const def = upstreams?.find((u) => u.id === org.default_upstream_id);
  return (
    <div className="narrow">
      <PageHeader
        title={t('orgPage.title')}
        help={t('orgPage.help')}
        actions={
          <a className="btn btn-icon-text" href={href('orgs')} onClick={onLink('orgs')}>
            <ArrowLeftRight size={14} aria-hidden="true" />
            <span>{t('app.switchOrgLong')}</span>
          </a>
        }
      />
      <section className="card">
        <dl className="kv kv-wide">
          <dt>{t('common.name')}</dt>
          <dd>
            <strong>{org.name}</strong>
          </dd>
          <dt>{t('org.slug')}</dt>
          <dd className="mono">{org.slug}</dd>
          <dt>{t('org.id')}</dt>
          <dd>
            <span className="secret-row">
              <code className="secret">{org.id}</code>
              <CopyButton text={org.id} />
            </span>
          </dd>
          {role ? (
            <>
              <dt>{t('orgPage.yourRole')}</dt>
              <dd>
                <Badge tone="accent">{t(`org.role.${role}` as MessageKey)}</Badge>
              </dd>
            </>
          ) : null}
          {org.tier ? (
            <>
              <dt>{t('orgPage.tier')}</dt>
              <dd>{org.tier}</dd>
            </>
          ) : null}
          <dt>{t('orgPage.auditContent')}</dt>
          <dd>
            <Badge tone={org.audit_store_content ? 'warn' : 'neutral'}>{org.audit_store_content ? t('orgPage.stored') : t('orgPage.notStored')}</Badge>
            <div className="muted small">{t('orgPage.auditContentHelp')}</div>
          </dd>
          <dt>{t('up.orgDefault')}</dt>
          <dd>
            <a href={href('providers')} onClick={onLink('providers')}>
              {def ? (def.display_name ?? def.name) : t('up.gatewayDefault')}
            </a>
          </dd>
          <dt>{t('proj.title')}</dt>
          <dd>
            <a href={href('projects')} onClick={onLink('projects')}>
              {t('orgPage.projects', { count: projects.length })}
            </a>
          </dd>
          <dt>{t('common.created')}</dt>
          <dd>{formatTime(org.created_at)}</dd>
        </dl>
      </section>
    </div>
  );
}
