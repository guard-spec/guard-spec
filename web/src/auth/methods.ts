// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Sign-in methods as the control plane names them (password, google,
// oidc:<provider id>, saml:<provider id>) and as people read them.

import { useEffect, useState } from 'react';
import { useApp } from '../context';
import type { Translate } from '../i18n';
import type { LoginProvider } from '../types';

/** A readable name: the provider's display name, else "SSO"; never a raw id. */
export function methodLabel(key: string, providers: readonly LoginProvider[], t: Translate): string {
  if (key === 'password') return t('sec.methodPasswordShort');
  if (key === 'google') return providers.find((p) => p.type === 'google')?.display_name ?? 'Google';
  if (key.startsWith('oidc:') || key.startsWith('saml:')) {
    const id = key.slice(5);
    return providers.find((p) => p.id === id)?.display_name ?? t('sec.methodSso');
  }
  return key;
}

/** The method key of a provider of GET /auth/providers. */
export function methodKey(p: LoginProvider): string {
  if (p.type === 'google') return 'google';
  return p.type === 'saml' ? `saml:${p.id}` : `oidc:${p.id}`;
}

/** GET /auth/providers (public), or [] on a control plane without it. */
export function useLoginProviders(): LoginProvider[] | null {
  const { api } = useApp();
  const [providers, setProviders] = useState<LoginProvider[] | null>(null);
  useEffect(() => {
    let live = true;
    api.listLoginProviders().then(
      (ps) => live && setProviders(ps),
      () => live && setProviders([]),
    );
    return () => {
      live = false;
    };
  }, [api]);
  return providers;
}
