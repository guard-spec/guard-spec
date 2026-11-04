// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Download } from 'lucide-react';
import { useApp } from '../context';
import { CopyButton, downloadText } from './ui';

/** Recovery codes, shown once: copy or download them. */
export function RecoveryCodes({ codes }: { codes: string[] }) {
  const { t } = useApp();
  const text = codes.join('\n') + '\n';
  return (
    <div className="recovery">
      <p className="banner banner-warn">{t('mfa.codesHelp')}</p>
      <ol className="recovery-codes" data-testid="recovery-codes">
        {codes.map((c) => (
          <li key={c} className="mono">
            {c}
          </li>
        ))}
      </ol>
      <div className="row-gap">
        <CopyButton text={text} />
        <button type="button" className="btn btn-icon-text" onClick={() => downloadText('guard-spec-recovery-codes.txt', text)}>
          <Download size={14} aria-hidden="true" />
          <span>{t('mfa.download')}</span>
        </button>
      </div>
    </div>
  );
}
