// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Fragment, useState, type FormEvent } from 'react';
import { isTotpCode } from '../auth/loginMachine';
import { useApp } from '../context';
import type { TotpSetup } from '../types';
import { QrCode } from './QrCode';
import { CopyButton, Field } from './ui';

/** Scan the QR code (or type the secret), then confirm with a first code. */
export function TotpEnroll({ setup, onConfirm, busy }: { setup: TotpSetup; onConfirm: (code: string) => void; busy?: boolean }) {
  const { t } = useApp();
  const [code, setCode] = useState('');
  const [touched, setTouched] = useState(false);
  const valid = isTotpCode(code.replace(/\s+/g, ''));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid) onConfirm(code.replace(/\s+/g, ''));
  };
  return (
    <form className="totp-enroll" onSubmit={submit}>
      <ol className="steps">
        <li>{t('mfa.step1')}</li>
        <li>{t('mfa.step2')}</li>
      </ol>
      <div className="totp-grid">
        <QrCode text={setup.otpauth_url} label={t('mfa.qrLabel')} />
        <div className="totp-secret">
          <span className="muted small">{t('mfa.secret')}</span>
          <code className="secret" data-testid="totp-secret">
            {/* Groups of four that never break inside; lines wrap between groups. */}
            {(setup.secret.match(/.{1,4}/g) ?? []).map((g, i) => (
              <Fragment key={i}>
                {i > 0 ? ' ' : null}
                <span className="secret-group">{g}</span>
              </Fragment>
            ))}
          </code>
          <CopyButton text={setup.secret} />
        </div>
      </div>
      <Field label={t('mfa.code')} help={t('mfa.codeHelp')} error={touched && !valid ? t('mfa.codeInvalid') : undefined}>
        {(p) => (
          <input
            {...p}
            className="mono code-input"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={7}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
          />
        )}
      </Field>
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        {t('mfa.enable')}
      </button>
    </form>
  );
}
