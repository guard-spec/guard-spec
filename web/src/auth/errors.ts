// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { ApiError } from '../api';
import { errorText } from '../context';
import type { MessageKey, Translate } from '../i18n';

/** Error codes of the identity API that get a translated message. */
const CODES: Record<string, MessageKey> = {
  account_exists: 'authErr.account_exists',
  login_method_not_allowed: 'authErr.login_method_not_allowed',
  invalid_code: 'authErr.invalid_code',
  mfa_required_by_org: 'authErr.mfa_required_by_org',
  too_many_attempts: 'authErr.too_many_attempts',
  expired: 'authErr.expired',
  domain_not_allowed: 'authErr.domain_not_allowed',
};

/** The code of an error (the body's code or error), or of an SSO callback ?error=. */
export function errorCode(e: unknown): string | null {
  if (typeof e === 'string') return e;
  if (e instanceof ApiError) {
    const b = (e.body ?? {}) as { code?: unknown; error?: unknown };
    if (typeof b.code === 'string') return b.code;
    if (typeof b.error === 'string' && /^[a-z_]+$/.test(b.error)) return b.error;
    if (e.status === 429) return 'too_many_attempts';
  }
  return null;
}

export function authErrorText(e: unknown, t: Translate): string {
  const code = errorCode(e);
  const key = code ? CODES[code] : undefined;
  if (key) return t(key);
  return typeof e === 'string' ? e : errorText(e);
}
