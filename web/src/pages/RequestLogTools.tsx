// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Tools of the request log (RF-a1dbafea U4): saved filters, and the CSV
// report of the request log per period (GET .../reports/requests.csv).

import { Bookmark, Download, Trash2 } from 'lucide-react';
import { useId, useState } from 'react';
import { Dialog, downloadText } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import type { DashboardWindow } from '../types';
import { DASH_WINDOWS, reportFilename } from './dashboard';
import { currentFilter, loadFilters, storeFilters, withFilter, withoutFilter, type SavedFilter } from './savedFilters';

/** Choose, save and delete named filters of the request log. */
export function SavedFilters({ action, q, onApply }: { action: string; q: string; onApply: (f: SavedFilter) => void }) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const [list, setList] = useState<SavedFilter[]>(() => loadFilters(org.id));
  const [naming, setNaming] = useState<string | null>(null);
  const selectId = useId();
  const nameId = useId();
  const cur = currentFilter(list, action, q);
  const update = (next: SavedFilter[]) => {
    setList(next);
    storeFilters(org.id, next);
  };
  const empty = action === '' && q.trim() === '';

  return (
    <>
      {list.length > 0 ? (
        <div className="field field-inline">
          <label htmlFor={selectId}>{t('filters.saved')}</label>
          <select
            id={selectId}
            value={cur?.name ?? ''}
            onChange={(e) => {
              const f = list.find((x) => x.name === e.target.value);
              if (f) onApply(f);
              else onApply({ name: '', action: '', q: '' });
            }}
          >
            <option value="">{t('filters.none')}</option>
            {list.map((f) => (
              <option key={f.name} value={f.name}>
                {f.name}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      {cur ? (
        <button
          type="button"
          className="btn btn-icon-text"
          aria-label={t('filters.deleteOf', { name: cur.name })}
          onClick={() => {
            update(withoutFilter(list, cur.name));
            notify(t('filters.deleted', { name: cur.name }));
          }}
        >
          <Trash2 size={14} aria-hidden="true" />
          <span>{t('filters.delete')}</span>
        </button>
      ) : (
        <button type="button" className="btn btn-icon-text" disabled={empty} title={empty ? t('filters.emptyHelp') : undefined} onClick={() => setNaming('')}>
          <Bookmark size={14} aria-hidden="true" />
          <span>{t('filters.save')}</span>
        </button>
      )}
      <Dialog
        open={naming !== null}
        title={t('filters.saveTitle')}
        onClose={() => setNaming(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setNaming(null)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!naming?.trim()}
              onClick={() => {
                const name = naming?.trim() ?? '';
                update(withFilter(list, { name, action, q }));
                setNaming(null);
                notify(t('filters.savedOk', { name }));
              }}
            >
              {t('common.save')}
            </button>
          </>
        }
      >
        <div className="field">
          <label htmlFor={nameId}>{t('filters.name')}</label>
          <input id={nameId} maxLength={60} value={naming ?? ''} onChange={(e) => setNaming(e.target.value)} />
          <small className="muted">{t('filters.saveHelp')}</small>
        </div>
      </Dialog>
    </>
  );
}

/** Download the request log of a period as CSV: counts only, never content. */
export function CsvExport() {
  const { api, t, notify } = useApp();
  const { org, projects } = useOrg();
  const [open, setOpen] = useState(false);
  const [range, setRange] = useState<DashboardWindow>('24h');
  const [project, setProject] = useState('');
  const [busy, setBusy] = useState(false);
  const projectId = useId();

  const download = async () => {
    setBusy(true);
    try {
      const csv = await api.getRequestsReportCsv(org.id, { window: range, project_id: project || undefined });
      downloadText(reportFilename(org.slug, range, new Date()), csv);
      setOpen(false);
    } catch (e) {
      notify(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className="btn btn-icon-text" onClick={() => setOpen(true)}>
        <Download size={14} aria-hidden="true" />
        <span>{t('dash.csv')}</span>
      </button>
      <Dialog
        open={open}
        title={t('csv.title')}
        onClose={() => setOpen(false)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setOpen(false)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary btn-icon-text" disabled={busy} onClick={() => void download()}>
              <Download size={14} aria-hidden="true" />
              <span>{busy ? t('dash.csvBusy') : t('csv.download')}</span>
            </button>
          </>
        }
      >
        <p className="muted">{t('dash.csvHelp')}</p>
        <fieldset className="plain">
          <legend>{t('dash.windowLabel')}</legend>
          <div className="radio-list">
            {DASH_WINDOWS.map((w) => (
              <label key={w} className="check">
                <input type="radio" name="csv-window" checked={range === w} onChange={() => setRange(w)} />
                <span>{t(`dash.window.${w}` as MessageKey)}</span>
              </label>
            ))}
          </div>
        </fieldset>
        {projects.length > 0 ? (
          <div className="field">
            <label htmlFor={projectId}>{t('dash.project')}</label>
            <select id={projectId} value={project} onChange={(e) => setProject(e.target.value)}>
              <option value="">{t('dash.allProjects')}</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
        ) : null}
      </Dialog>
    </>
  );
}
