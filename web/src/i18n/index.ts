// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { en, type MessageKey, type Messages } from './en';
import { vi } from './vi';

export type Lang = 'en' | 'vi';
export type { MessageKey };

const catalogs: Record<Lang, Messages> = { en, vi };

export type Translate = (key: MessageKey, params?: Record<string, string | number>) => string;

export function translator(lang: Lang): Translate {
  const msgs = catalogs[lang];
  return (key, params) => {
    const s = msgs[key];
    if (!params) return s;
    return s.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m));
  };
}
