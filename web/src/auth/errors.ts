// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { ApiError } from '../api';
import { errorText } from '../context';
import type { MessageKey, Translate } from '../i18n';

/** Error codes of the identity API that get a translated message. */
export const CODES: Record<string, MessageKey> = {
  // Sign-in and 2FA
  invalid_credentials: 'authErr.invalid_credentials',
  invalid_code: 'authErr.invalid_code',
  mfa_token_invalid: 'authErr.mfa_token_invalid',
  expired: 'authErr.mfa_token_invalid',
  mfa_locked: 'authErr.mfa_locked',
  mfa_required_by_org: 'authErr.mfa_required_by_org',
  mfa_already_enabled: 'authErr.mfa_already_enabled',
  mfa_setup_missing: 'authErr.mfa_setup_missing',
  mfa_unavailable: 'authErr.mfa_unavailable',
  too_many_attempts: 'authErr.too_many_attempts',
  account_disabled: 'authErr.account_disabled',
  session_revoked: 'authErr.session_revoked',
  no_password: 'authErr.no_password',
  login_method_not_allowed: 'authErr.login_method_not_allowed',
  // SSO callback (#/auth/callback?error=) and identity links
  account_exists: 'authErr.account_exists',
  domain_not_allowed: 'authErr.domain_not_allowed',
  email_not_verified: 'authErr.email_not_verified',
  invalid_state: 'authErr.invalid_state',
  invalid_nonce: 'authErr.invalid_nonce',
  invalid_token: 'authErr.invalid_token',
  exchange_failed: 'authErr.exchange_failed',
  provider_error: 'authErr.provider_error',
  sso_unavailable: 'authErr.sso_unavailable',
  // SAML assertion consumer service (cmd/control-plane/saml.go)
  invalid_response: 'authErr.invalid_response',
  replayed: 'authErr.replayed',
  idp_initiated_disabled: 'authErr.idp_initiated_disabled',
  link_expired: 'authErr.link_expired',
  link_wrong_user: 'authErr.link_wrong_user',
  identity_in_use: 'authErr.identity_in_use',
  identity_exists: 'authErr.identity_exists',
  invalid_max_tokens: 'authErr.invalid_max_tokens',
  // Members, security, instance admin, providers
  would_lock_out: 'authErr.would_lock_out',
  last_owner: 'authErr.last_owner',
  last_instance_admin: 'authErr.last_instance_admin',
  not_sole_authority: 'authErr.not_sole_authority',
  role_not_allowed: 'authErr.role_not_allowed',
  provider_in_use: 'authErr.provider_in_use',
  model_not_allowed: 'authErr.model_not_allowed',
};

/** The code of an error (the body's code or error), or of an SSO callback ?error=. */
export function errorCode(e: unknown): string | null {
  if (typeof e === 'string') return e;
  if (e instanceof ApiError) {
    const b = (e.body ?? {}) as { code?: unknown; error?: unknown };
    if (typeof b.code === 'string') return b.code;
    if (typeof b.error === 'string' && /^[a-z_]+$/.test(b.error)) return b.error;
    // The gateway's OpenAI-style body: {"error": {"code": "model_not_allowed"}}.
    const inner = b.error as { code?: unknown } | null | undefined;
    if (inner && typeof inner === 'object' && typeof inner.code === 'string') return inner.code;
    if (e.status === 429) return 'too_many_attempts';
  }
  return null;
}

/**
 * Codes of the SSO callback (#/auth/callback?error=) that mean something
 * else there: "expired" is a SAML assertion out of its validity period, not
 * an expired 2FA step.
 */
export const CALLBACK_CODES: Record<string, MessageKey> = {
  expired: 'authErr.assertion_expired',
};

/** The message of an SSO callback ?error= code. */
export function callbackErrorText(code: string, t: Translate): string {
  const key = CALLBACK_CODES[code];
  return key ? t(key) : authErrorText(code, t);
}

export function authErrorText(e: unknown, t: Translate): string {
  const code = errorCode(e);
  const key = code ? CODES[code] : undefined;
  if (key) return t(key);
  return typeof e === 'string' ? e : errorText(e);
}
