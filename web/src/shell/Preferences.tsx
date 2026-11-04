// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { Monitor, Moon, Sun } from 'lucide-react';
import { useId } from 'react';
import { useApp, type ThemePref } from '../context';
import type { Lang } from '../i18n';

const THEMES: { value: ThemePref; icon: typeof Sun; label: 'app.themeLight' | 'app.themeDark' | 'app.themeSystem' }[] = [
  { value: 'light', icon: Sun, label: 'app.themeLight' },
  { value: 'dark', icon: Moon, label: 'app.themeDark' },
  { value: 'system', icon: Monitor, label: 'app.themeSystem' },
];

/** Language and theme: in the profile menu and on the login page. */
export function Preferences() {
  const { t, lang, setLang, themePref, setThemePref } = useApp();
  const langId = useId();
  const themeId = useId();
  return (
    <div className="prefs">
      <div className="prefs-row">
        <label htmlFor={langId}>{t('app.language')}</label>
        <select id={langId} value={lang} onChange={(e) => setLang(e.target.value as Lang)}>
          <option value="en">English</option>
          <option value="vi">Tiếng Việt</option>
        </select>
      </div>
      <div className="prefs-row">
        <span id={themeId}>{t('app.theme')}</span>
        <div className="segmented" role="group" aria-labelledby={themeId}>
          {THEMES.map(({ value, icon: Icon, label }) => (
            <button
              key={value}
              type="button"
              aria-pressed={themePref === value}
              title={t(label)}
              aria-label={`${t('app.theme')}: ${t(label)}`}
              onClick={() => setThemePref(value)}
            >
              <Icon size={14} aria-hidden="true" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
