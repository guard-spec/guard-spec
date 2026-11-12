// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// What the gateway accepts as input for the organization (migration 030):
// text only or text and allowed files, the most tokens per request, and what
// happens to an allowed file the gateway cannot read. The instance's limits
// (MAX_SCAN_TOKENS, PDF_EXTRACT, UNSCANNED_PARTS) are hard ceilings. An org
// without settings inherits the instance's behaviour. Loosening waits for a
// second admin when the org has two-person approval on.

import { useCallback, useState } from 'react';
import { Badge } from '../components/DataTable';
import { ErrorBanner, Field, Loading, PageHeader, RelativeTime, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink } from '../router';
import type { InputMode, InputSettings, InputSettingsPending, InputSettingsState, UnreadableFileAction } from '../types';
import { DEFAULT_INPUT, inputBody, loosened, pendingText, validateInput, type InputDraft } from './inputSettings';

function isPending(r: InputSettingsState | InputSettingsPending): r is InputSettingsPending {
  return 'approval_required' in r;
}

export function InputPage() {
  const { api, t, notify } = useApp();
  const { org, can } = useOrg();
  const writable = can('org.settings.write');
  const { data, error, loading } = useLoad(useCallback(() => api.getInputSettings(org.id), [api, org.id]));
  const [state, setState] = useState<InputSettingsState | null>(null);
  const [draft, setDraft] = useState<InputDraft | null>(null);
  const [tokensText, setTokensText] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} />;
  const cur = state ?? data;
  if (!cur) return <Loading />;
  const inst = cur.instance;
  const d: InputDraft = draft ?? { inherit: cur.inherit, settings: cur.settings ?? DEFAULT_INPUT };
  const s = d.settings;
  const set = (patch: Partial<InputSettings>) => setDraft({ inherit: false, settings: { ...s, ...patch } });
  const errs = validateInput(d, inst.max_input_tokens_ceiling);
  const target = d.inherit ? null : inputBody(s);
  const loosens = draft ? loosened(cur.settings, target) : [];
  const waits = loosens.length > 0 && cur.two_person_approval;

  const save = async () => {
    if (errs.length > 0) return;
    setBusy(true);
    setSaveError(null);
    try {
      const r = target === null ? await api.resetInputSettings(org.id, reason || undefined) : await api.putInputSettings(org.id, target, reason || undefined);
      if (isPending(r)) {
        setState(r.state);
        notify(r.already_pending ? t('input.alreadyPending') : r.applied_now ? t('input.partlyApplied') : t('input.requested'));
      } else {
        setState(r);
        notify(t('common.saved'));
      }
      setDraft(null);
      setTokensText(null);
      setReason('');
    } catch (e) {
      setSaveError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const yesNo = (v: boolean | null) => (v === null ? t('input.unknown') : v ? t('guard.on') : t('guard.off'));

  return (
    <div className="narrow">
      <PageHeader title={t('input.title')} help={t('input.help')} />
      {!writable ? <div className="banner banner-info">{t('input.readOnly')}</div> : null}
      <ErrorBanner error={saveError} />

      {cur.pending ? (
        <div className="banner banner-warn" data-testid="input-pending">
          <div>
            <strong>{t('input.pendingTitle')}</strong> {pendingText(t, cur.pending.payload)} ({t('input.pendingBy', { email: cur.pending.requested_by?.email ?? '—' })},{' '}
            <RelativeTime value={cur.pending.created_at} />
            ).{' '}
            <a href={href('approvals')} onClick={onLink('approvals')}>
              {t('input.pendingLink')}
            </a>
          </div>
        </div>
      ) : null}

      <section className="card" aria-labelledby="input-instance">
        <h2 id="input-instance">
          {t('input.instance')}
        </h2>
        <p className="muted small">{t('input.instanceHelp')}</p>
        {inst.source === 'default' ? <p className="banner banner-warn">{t('input.instanceUnknown', { limit: String(inst.max_input_tokens_ceiling) })}</p> : null}
        <table className="settings-table" data-testid="input-instance">
          <tbody>
            <tr>
              <th scope="row">{t('input.ceiling')}</th>
              <td className="mono">{inst.max_input_tokens_ceiling}</td>
            </tr>
            <tr>
              <th scope="row">MAX_SCAN_TOKENS</th>
              <td className="mono">{inst.max_scan_tokens ?? (inst.source === 'gateway' ? t('input.unset') : t('input.unknown'))}</td>
            </tr>
            <tr>
              <th scope="row">PDF_EXTRACT</th>
              <td>{yesNo(inst.pdf_extract)}</td>
            </tr>
            <tr>
              <th scope="row">UNSCANNED_PARTS</th>
              <td className="mono">{inst.unscanned_parts ?? t('input.unknown')}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <fieldset className="card" disabled={!writable}>
          <legend>{t('input.scope')}</legend>
          <div className="radio-list" role="radiogroup" aria-label={t('input.scope')}>
            <label className="check">
              <input type="radio" name="input-scope" checked={d.inherit} onChange={() => setDraft({ ...d, inherit: true })} />
              <span>
                {t('input.inherit')} {cur.inherit ? <Badge tone="ok">{t('input.current')}</Badge> : null}
              </span>
            </label>
            <label className="check">
              <input type="radio" name="input-scope" checked={!d.inherit} onChange={() => setDraft({ ...d, inherit: false })} />
              <span>{t('input.custom')}</span>
            </label>
          </div>
          <small className="muted">{t('input.inheritHelp')}</small>
        </fieldset>

        {!d.inherit ? (
          <fieldset className="card" disabled={!writable}>
            <legend>{t('input.settings')}</legend>
            <div className="radio-list" role="radiogroup" aria-label={t('input.mode')}>
              {(['text_only', 'hybrid'] as InputMode[]).map((m) => (
                <label key={m} className="check">
                  <input type="radio" name="input-mode" checked={s.input_mode === m} onChange={() => set({ input_mode: m })} />
                  <span>
                    {t(`input.mode.${m}` as MessageKey)}
                    <span className="small muted"> — {t(`input.mode.${m}.help` as MessageKey)}</span>
                  </span>
                </label>
              ))}
            </div>

            <Field
              label={t('input.tokens')}
              help={t('input.tokensHelp', { max: String(inst.max_input_tokens_ceiling) })}
              error={errs.includes('tokens') ? t('input.tokensError', { max: String(inst.max_input_tokens_ceiling) }) : undefined}
            >
              {(p) => (
                <input
                  {...p}
                  inputMode="numeric"
                  placeholder={t('input.tokensPlaceholder', { max: String(inst.max_input_tokens_ceiling) })}
                  value={tokensText ?? (s.max_input_tokens === null ? '' : String(s.max_input_tokens))}
                  onChange={(e) => {
                    const v = e.target.value.trim();
                    setTokensText(v);
                    set({ max_input_tokens: v === '' ? null : /^\d+$/.test(v) ? Number(v) : NaN });
                  }}
                />
              )}
            </Field>

            {s.input_mode === 'hybrid' ? (
              <>
                <fieldset>
                  <legend>{t('input.types')}</legend>
                  <small className="muted">{t('input.typesHelp')}</small>
                  {inst.readable_file_types.map((ft) => (
                    <label key={ft} className="check">
                      <input
                        type="checkbox"
                        checked={s.allowed_file_types.includes(ft)}
                        onChange={(e) =>
                          set({ allowed_file_types: e.target.checked ? [...s.allowed_file_types, ft] : s.allowed_file_types.filter((x) => x !== ft) })
                        }
                      />
                      <span>{t(`input.type.${ft}` as MessageKey)}</span>
                      <span className="mono small muted">{ft}</span>
                    </label>
                  ))}
                  {s.allowed_file_types.includes('pdf') && inst.pdf_extract === false ? (
                    <p className="banner banner-warn">{t('input.pdfExtractOff')}</p>
                  ) : null}
                </fieldset>
                <Field label={t('input.unreadable')} help={t('input.unreadableHelp')}>
                  {(p) => (
                    <select {...p} value={s.unreadable_file_action} onChange={(e) => set({ unreadable_file_action: e.target.value as UnreadableFileAction })}>
                      <option value="block">{t('input.unreadable.block')}</option>
                      <option value="pass">{t('input.unreadable.pass')}</option>
                    </select>
                  )}
                </Field>
              </>
            ) : null}
          </fieldset>
        ) : null}

        {loosens.length > 0 ? (
          <div className={waits ? 'banner banner-warn' : 'banner banner-info'} data-testid="input-loosens">
            {t(waits ? 'input.loosensWait' : 'input.loosensLog', { what: loosens.map((k) => t(`input.loosened.${k}` as MessageKey)).join(', ') })}
          </div>
        ) : null}
        {waits ? (
          <Field label={t('input.reason')}>{(p) => <textarea {...p} rows={2} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}</Field>
        ) : null}

        {writable ? (
          <div className="form-actions">
            <button
              type="button"
              className="btn"
              disabled={!draft || busy}
              onClick={() => {
                setDraft(null);
                setTokensText(null);
              }}
            >
              {t('flow.discard')}
            </button>
            <button type="submit" className="btn btn-primary" disabled={!draft || busy || errs.length > 0}>
              {busy ? t('common.saving') : waits ? t('input.requestApproval') : t('common.save')}
            </button>
          </div>
        ) : null}
      </form>
      {cur.updated_at ? (
        <p className="small muted">
          {t('input.updated')} <RelativeTime value={cur.updated_at} />
        </p>
      ) : null}
    </div>
  );
}

export default InputPage;
