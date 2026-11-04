// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The simulator on its own page: saved policies of a scope against a test
// request. The flow editor keeps its own simulator for unsaved changes.

import { useEffect, useId, useState } from 'react';
import { PageHeader } from '../components/ui';
import { useApp, useOrg } from '../context';
import { FALLBACK_SCHEMA } from '../flow/schema';
import { Simulator } from '../flow/Simulator';
import { href, onLink } from '../router';
import type { PolicySchema, SimulateResponse } from '../types';

export default function SimulatorPage() {
  const { api, t } = useApp();
  const { org, projects } = useOrg();
  const [schema, setSchema] = useState<PolicySchema>(FALLBACK_SCHEMA);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const scopeId = useId();

  useEffect(() => {
    let live = true;
    api.getPolicySchema().then(
      (s) => live && setSchema(s),
      () => live && setSchema(FALLBACK_SCHEMA),
    );
    return () => {
      live = false;
    };
  }, [api]);

  return (
    <div className="narrow-wide">
      <PageHeader
        title={t('simPage.title')}
        help={t('simPage.help')}
        actions={
          <a className="btn" href={href('flow')} onClick={onLink('flow')}>
            {t('simPage.openFlow')}
          </a>
        }
      />
      <div className="toolbar">
        <div className="field field-inline">
          <label htmlFor={scopeId}>{t('flow.scope')}</label>
          <select
            id={scopeId}
            value={projectId ?? ''}
            onChange={(e) => {
              setProjectId(e.target.value || null);
              setResult(null);
            }}
          >
            <option value="">{t('flow.scopeOrg')}</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {t('flow.scopeProject', { name: p.name })}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="card">
        <Simulator orgId={org.id} schema={schema} makeRequest={(vars) => ({ project_id: projectId, vars })} result={result} onResult={setResult} />
      </div>
    </div>
  );
}
