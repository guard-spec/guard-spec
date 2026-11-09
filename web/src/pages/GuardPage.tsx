// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';
import { ErrorBanner, Loading, PageHeader, useLoad } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { guardBody, parseThreshold, parseWindowSize } from '../flow/guardDraft';
import { KeyTip } from '../flow/HelpText';
import {
  DEFAULT_SCAN_ROLES,
  PII_KINDS,
  SCAN_ROLES,
  SCAN_TOKENS,
  UNSCANNED_MODES,
  WINDOW_BYTES,
  WINDOW_TURNS,
  type GuardSettings,
  type IndirectAction,
  type ScanRole,
  type SpotlightMode,
  type UnscannedMode,
} from '../types';

type ThresholdField = 'injection_threshold' | 'indirect_threshold';
type WindowField = 'conversation_window_turns' | 'conversation_window_bytes';

type Tri = 'default' | 'on' | 'off';

export function GuardPage() {
  const { api, t, notify } = useApp();
  const { org, can } = useOrg();
  const writable = can('org.settings.write');
  const { data, error, loading } = useLoad(useCallback(() => api.getGuardSettings(org.id), [api, org.id]));
  const [edited, setDraft] = useState<GuardSettings | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Threshold fields as typed; a value that is not a valid threshold is not saved.
  const [thresholdText, setThresholdText] = useState<Partial<Record<ThresholdField, string>>>({});
  // Window sizes as typed; a value out of bounds is not saved.
  const [windowText, setWindowText] = useState<Partial<Record<WindowField, string>>>({});
  // max_scan_tokens as typed.
  const [tokensText, setTokensText] = useState<string | null>(null);

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
      // Every field, the thresholds the Flow page sets included.
      setDraft(await api.putGuardSettings(org.id, guardBody(draft)));
      setThresholdText({});
      setWindowText({});
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
        <div className="field">
          <label htmlFor="indirect-action">{t('guard.indirectAction')}</label>
          <select
            id="indirect-action"
            value={draft.indirect_action ?? ''}
            onChange={(e) => {
              const v = e.target.value as IndirectAction | '';
              const { indirect_action: _old, ...rest } = draft;
              setDraft(v ? { ...rest, indirect_action: v } : rest);
            }}
          >
            <option value="">{t('guard.default', { value: t('flow.gatewayDefault') })}</option>
            {(['block', 'redact'] as const).map((m) => (
              <option key={m} value={m}>
                {t(`guard.indirectAction.${m}` as MessageKey)}
              </option>
            ))}
          </select>
          <div className="small muted">{t('guard.indirectAction.help')}</div>
        </div>
        <fieldset>
          <legend>{t('guard.window')}</legend>
          <div className="field">
            <select
              id="conversation-window"
              aria-label={t('guard.window')}
              value={draft.conversation_window === undefined ? 'default' : draft.conversation_window ? 'on' : 'off'}
              onChange={(e) => {
                const v = e.target.value as Tri;
                const { conversation_window: _old, ...rest } = draft;
                setDraft(v === 'default' ? rest : { ...rest, conversation_window: v === 'on' });
              }}
            >
              <option value="default">{t('guard.default', { value: t('flow.gatewayDefault') })}</option>
              <option value="on">{t('guard.on')}</option>
              <option value="off">{t('guard.off')}</option>
            </select>
            <div className="small muted">{t('guard.window.help')}</div>
          </div>
          {(
            [
              ['conversation_window_turns', 'guard.window.turns', WINDOW_TURNS],
              ['conversation_window_bytes', 'guard.window.bytes', WINDOW_BYTES],
            ] as const
          ).map(([field, label, bounds]) => {
            const text = windowText[field] ?? (draft[field] === undefined ? '' : String(draft[field]));
            const invalid = parseWindowSize(text, bounds) === 'invalid';
            return (
              <div className="field" key={field}>
                <label htmlFor={`guard-${field}`}>{t(label)}</label>
                <input
                  id={`guard-${field}`}
                  inputMode="numeric"
                  placeholder={t('panel.detectors.default', { value: String(bounds.default) })}
                  value={text}
                  aria-invalid={invalid}
                  disabled={draft.conversation_window === false}
                  onChange={(e) => {
                    const v = e.target.value;
                    setWindowText({ ...windowText, [field]: v });
                    const p = parseWindowSize(v, bounds);
                    if (p === 'invalid') return;
                    const { [field]: _old, ...rest } = draft;
                    setDraft(p === undefined ? rest : { ...rest, [field]: p });
                  }}
                />
                {invalid && <div className="field-error">{t('guard.window.sizeError', { min: String(bounds.min), max: String(bounds.max) })}</div>}
              </div>
            );
          })}
        </fieldset>
        <fieldset>
          <legend>{t('guard.inputPii.legend')}</legend>
          <div className="field">
            <span className="label-row">
              <label className="switch-label" htmlFor="input-pii">
                <span className="switch">
                  <input
                    id="input-pii"
                    type="checkbox"
                    role="switch"
                    // An action needs the check: it is on while one is chosen.
                    checked={draft.input_pii === true || (draft.input_pii_action ?? 'off') !== 'off'}
                    disabled={!writable || (draft.input_pii_action ?? 'off') !== 'off'}
                    onChange={(e) => {
                      const { input_pii: _old, ...rest } = draft;
                      // Off is stored as false, so the page shows what the org chose.
                      setDraft({ ...rest, input_pii: e.target.checked });
                    }}
                  />
                  <span className="switch-track" aria-hidden="true" />
                </span>
                {t('guard.inputPii')}
              </label>
              <KeyTip name={t('guard.inputPii')} k="guard.inputPii.tip" testId="help-input-pii" />
            </span>
            <div className="small muted">{t('guard.inputPii.help')}</div>
          </div>
          <div className="field">
            <label htmlFor="input-pii-action">{t('guard.piiAction')}</label>
            <select
              id="input-pii-action"
              value={draft.input_pii_action ?? 'off'}
              disabled={!writable}
              onChange={(e) => {
                const v = e.target.value as 'off' | 'redact' | 'tokenize';
                const { input_pii_action: _old, input_pii_kinds: kinds, ...rest } = draft;
                setDraft(v === 'off' ? rest : { ...rest, input_pii_action: v, ...(kinds?.length ? { input_pii_kinds: kinds } : {}) });
              }}
            >
              <option value="off">{t('guard.piiAction.off')}</option>
              <option value="tokenize">{t('guard.piiAction.tokenize')}</option>
              <option value="redact">{t('guard.piiAction.redact')}</option>
            </select>
            <div className="small muted" data-testid="pii-action-help">
              {t(`guard.piiAction.${draft.input_pii_action ?? 'off'}Help`)}
            </div>
          </div>
          {draft.input_pii_action && draft.input_pii_action !== 'off' ? (
            <fieldset className="check-group" aria-describedby="pii-kinds-help">
              <legend>{t('guard.piiKinds')}</legend>
              <div className="check-row">
                {PII_KINDS.map((k) => {
                  const chosen = draft.input_pii_kinds ?? [];
                  const all = chosen.length === 0;
                  const on = all || chosen.includes(k);
                  return (
                    <label key={k} className="check">
                      <input
                        type="checkbox"
                        checked={on}
                        disabled={!writable}
                        onChange={(e) => {
                          const current = all ? [...PII_KINDS] : [...chosen];
                          const next = e.target.checked ? [...current, k] : current.filter((x) => x !== k);
                          if (next.length === 0) return; // at least one kind; off is the action above
                          const { input_pii_kinds: _old, ...rest } = draft;
                          // Every kind is stored as none: the default.
                          setDraft(next.length === PII_KINDS.length ? rest : { ...rest, input_pii_kinds: PII_KINDS.filter((x) => next.includes(x)) });
                        }}
                      />
                      {t(`guard.piiKind.${k}`)}
                    </label>
                  );
                })}
              </div>
              <div id="pii-kinds-help" className="small muted">{t('guard.piiKinds.help')}</div>
            </fieldset>
          ) : null}
        </fieldset>
        <fieldset>
          <legend>{t('guard.unscanned.legend')}</legend>
          <div className="field">
            <label htmlFor="unscanned-parts">{t('guard.unscanned')}</label>
            <select
              id="unscanned-parts"
              value={draft.unscanned_parts ?? ''}
              disabled={!writable}
              aria-describedby="unscanned-parts-help"
              onChange={(e) => {
                const v = e.target.value as UnscannedMode | '';
                const { unscanned_parts: _old, ...rest } = draft;
                setDraft(v ? { ...rest, unscanned_parts: v } : rest);
              }}
            >
              <option value="">{t('guard.unscanned.default')}</option>
              {UNSCANNED_MODES.map((m) => (
                <option key={m} value={m}>
                  {t(`guard.unscanned.${m}`)}
                </option>
              ))}
            </select>
            <div id="unscanned-parts-help" className="stack-sm">
              <div className="small muted">{t('guard.unscanned.help')}</div>
              <div className="small muted" data-testid="unscanned-mode-help">
                {t(`guard.unscanned.${draft.unscanned_parts ?? 'default'}Help`)}
              </div>
              <div className="small muted">{t('guard.unscanned.extract')}</div>
            </div>
          </div>
        </fieldset>
        <fieldset>
          <legend>{t('guard.scanTokens.legend')}</legend>
          {(() => {
            const text = tokensText ?? (draft.max_scan_tokens === undefined ? '' : String(draft.max_scan_tokens));
            const invalid = parseWindowSize(text, SCAN_TOKENS) === 'invalid';
            return (
              <div className="field">
                <label htmlFor="guard-max-scan-tokens">{t('guard.scanTokens')}</label>
                <input
                  id="guard-max-scan-tokens"
                  inputMode="numeric"
                  placeholder={t('guard.scanTokens.default')}
                  value={text}
                  aria-invalid={invalid}
                  aria-describedby="guard-max-scan-tokens-help"
                  disabled={!writable}
                  onChange={(e) => {
                    const v = e.target.value;
                    setTokensText(v);
                    const p = parseWindowSize(v, SCAN_TOKENS);
                    if (p === 'invalid') return;
                    const { max_scan_tokens: _old, ...rest } = draft;
                    setDraft(p === undefined ? rest : { ...rest, max_scan_tokens: p });
                  }}
                />
                {invalid && (
                  <div className="field-error">
                    {t('guard.window.sizeError', { min: String(SCAN_TOKENS.min), max: String(SCAN_TOKENS.max) })}
                  </div>
                )}
                <div id="guard-max-scan-tokens-help" className="small muted">
                  {t('guard.scanTokens.help')}
                </div>
              </div>
            );
          })()}
        </fieldset>
        <fieldset>
          <legend>{t('panel.detectors.thresholds')}</legend>
          {(
            [
              ['injection_threshold', 'panel.detectors.injection', 'panel.detectors.injectionHelp', '0.85'],
              ['indirect_threshold', 'panel.detectors.indirect', 'panel.detectors.indirectHelp', 'INDIRECT_BLOCK_THRESHOLD'],
            ] as const
          ).map(([field, label, help, def]) => {
            const text = thresholdText[field] ?? (draft[field] === undefined ? '' : String(draft[field]));
            const invalid = parseThreshold(text) === 'invalid';
            return (
              <div className="field" key={field}>
                <label htmlFor={`guard-${field}`}>{t(label)}</label>
                <input
                  id={`guard-${field}`}
                  inputMode="decimal"
                  placeholder={t('panel.detectors.default', { value: def })}
                  value={text}
                  aria-invalid={invalid}
                  onChange={(e) => {
                    const v = e.target.value;
                    setThresholdText({ ...thresholdText, [field]: v });
                    const p = parseThreshold(v);
                    if (p === 'invalid') return;
                    const { [field]: _old, ...rest } = draft;
                    setDraft(p === undefined ? rest : { ...rest, [field]: p });
                  }}
                />
                {invalid ? <div className="field-error">{t('panel.detectors.thresholdError')}</div> : <div className="small muted">{t(help)}</div>}
              </div>
            );
          })}
        </fieldset>
        <button type="submit" className="btn btn-primary" disabled={
            busy ||
            !writable ||
            Object.values(thresholdText).some((x) => parseThreshold(x) === 'invalid') ||
            parseWindowSize(windowText.conversation_window_turns ?? '', WINDOW_TURNS) === 'invalid' ||
            parseWindowSize(windowText.conversation_window_bytes ?? '', WINDOW_BYTES) === 'invalid' ||
            parseWindowSize(tokensText ?? '', SCAN_TOKENS) === 'invalid'
          } title={writable ? undefined : t('forbidden.readOnly')}>
          {busy ? t('common.saving') : t('common.save')}
        </button>
      </form>
    </div>
  );
}
