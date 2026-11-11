// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { translator } from '../i18n';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import type { InputSettings } from '../types';
import { approvalText } from './ApprovalsPage';
import { DEFAULT_INPUT, inputBody, loosened, pendingText, validateInput } from './inputSettings';

const strict: InputSettings = { input_mode: 'text_only', max_input_tokens: 1000, allowed_file_types: [], unreadable_file_action: 'block' };
const loose: InputSettings = { input_mode: 'hybrid', max_input_tokens: null, allowed_file_types: ['pdf'], unreadable_file_action: 'pass' };

describe('input settings', () => {
  it('finds what a change loosens, as the control plane does', () => {
    expect(loosened(null, strict)).toEqual([]);
    expect(loosened(strict, null)).toEqual(['inherit']);
    expect(loosened(strict, loose)).toEqual(['input_mode', 'max_input_tokens', 'allowed_file_types', 'unreadable_file_action']);
    expect(loosened(loose, strict)).toEqual([]);
    expect(loosened(strict, { ...strict, max_input_tokens: 2000 })).toEqual(['max_input_tokens']);
    expect(loosened(strict, { ...strict, max_input_tokens: 500 })).toEqual([]);
  });

  it('checks the token limit against the instance ceiling', () => {
    expect(validateInput({ inherit: false, settings: { ...DEFAULT_INPUT, max_input_tokens: 40000 } }, 40000)).toEqual([]);
    expect(validateInput({ inherit: false, settings: { ...DEFAULT_INPUT, max_input_tokens: 40001 } }, 40000)).toEqual(['tokens']);
    expect(validateInput({ inherit: false, settings: { ...DEFAULT_INPUT, max_input_tokens: 0 } }, 40000)).toEqual(['tokens']);
    expect(validateInput({ inherit: false, settings: { ...DEFAULT_INPUT, max_input_tokens: Number.NaN } }, 40000)).toEqual(['tokens']);
    expect(validateInput({ inherit: true, settings: { ...DEFAULT_INPUT, max_input_tokens: 0 } }, 40000)).toEqual([]);
  });

  it('sends no file types in text_only', () => {
    expect(inputBody({ ...loose, input_mode: 'text_only' }).allowed_file_types).toEqual([]);
    expect(inputBody(loose).allowed_file_types).toEqual(['pdf']);
  });

  it('names a pending loosening', () => {
    const t = translator('en');
    expect(pendingText(t, { loosened: ['allowed_file_types', 'unreadable_file_action'] })).toBe('a file type added, unreadable files forwarded');
    expect(pendingText(t, {})).toBe('');
    expect(approvalText(t, { kind: 'input_settings.loosen', target: 'input_settings' })).toBe('Loosen the input settings');
  });

  it('has every input message in both languages', () => {
    for (const key of Object.keys(en).filter((k) => k.startsWith('input.') || k.startsWith('help.var.input.files'))) {
      expect(vi, key).toHaveProperty(key);
    }
  });
});
