// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Provider presets used when the control plane has no GET /providers/catalog
// yet (identity contract §6). The gateway speaks the OpenAI chat-completions
// format upstream, so Anthropic and Gemini use their OpenAI-compatible
// endpoints.

import { API_KEY_ENV_RE, BACKEND_METHODS, UPSTREAM_NAME_RE, type BackendConfig, type CatalogEntry, type ProviderKind, type UpstreamInput } from '../types';

export const BUILTIN_CATALOG: CatalogEntry[] = [
  {
    id: 'openai',
    display_name: 'OpenAI',
    default_base_url: 'https://api.openai.com/v1',
    key_required: true,
    key_env_hint: 'UPSTREAM_KEY_OPENAI',
    known_models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'o4-mini'],
    docs_url: 'https://platform.openai.com/docs/api-reference/chat',
  },
  {
    id: 'anthropic',
    display_name: 'Anthropic',
    openai_compatible_endpoint: true,
    default_base_url: 'https://api.anthropic.com/v1',
    key_required: true,
    key_env_hint: 'UPSTREAM_KEY_ANTHROPIC',
    known_models: [],
    docs_url: 'https://docs.anthropic.com/en/api/openai-sdk',
  },
  {
    id: 'azure_openai',
    display_name: 'Azure OpenAI',
    needs_api_version: true,
    default_base_url: 'https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT',
    key_required: true,
    key_env_hint: 'UPSTREAM_KEY_AZURE',
    known_models: [],
    docs_url: 'https://learn.microsoft.com/azure/ai-services/openai/reference',
  },
  {
    id: 'gemini',
    display_name: 'Google Gemini',
    openai_compatible_endpoint: true,
    default_base_url: 'https://generativelanguage.googleapis.com/v1beta/openai',
    key_required: true,
    key_env_hint: 'UPSTREAM_KEY_GEMINI',
    known_models: ['gemini-2.5-flash', 'gemini-2.5-pro'],
    docs_url: 'https://ai.google.dev/gemini-api/docs/openai',
  },
  {
    id: 'ollama',
    display_name: 'Ollama',
    default_base_url: 'http://ollama:11434/v1',
    key_required: false,
    known_models: [],
    docs_url: 'https://github.com/ollama/ollama/blob/main/docs/openai.md',
  },
  {
    id: 'vllm',
    display_name: 'vLLM',
    default_base_url: 'http://vllm:8000/v1',
    key_required: false,
    key_env_hint: 'UPSTREAM_KEY_VLLM',
    known_models: [],
    docs_url: 'https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html',
  },
  {
    id: 'openai_compatible',
    display_name: 'OpenAI-compatible',
    default_base_url: 'https://llm.example.com/v1',
    key_required: false,
    known_models: [],
  },
  {
    id: 'custom',
    display_name: 'Custom backend',
    default_base_url: 'https://api.example.com',
    key_required: false,
    key_env_hint: 'UPSTREAM_KEY_<NAME>',
    known_models: [],
    notes: 'Your own JSON API, reached through /v1/backend/{name}/{path}: the gateway scans the fields you list and forwards the request unchanged. It is never a chat upstream.',
  },
];

/** The provider id of a custom backend. */
export const CUSTOM: ProviderKind = 'custom';

/** A new custom backend: POST anywhere, the query field scanned. */
export function defaultBackend(): BackendConfig {
  return { path_prefixes: ['/'], methods: ['POST'], key_header: '', scan: { request: ['$.query'], response: [], all_strings: false, raw_text: false } };
}

/** Why a JSONPath is refused; each has a message (prov.jsonPath.*). */
export type JsonPathError = 'start' | 'descent' | 'name' | 'bracket' | 'index' | 'length';

/**
 * Checks a JSONPath of the subset the gateway reads (internal/jsonpath):
 * $ then .name, .*, [n] or [*] steps. Returns null when valid, else the
 * reason, for the form's message.
 */
export function jsonPathError(s: string): JsonPathError | null {
  if (s.length > 256) return 'length';
  if (!s.startsWith('$')) return 'start';
  let steps = 0;
  for (let i = 1; i < s.length; ) {
    if (++steps > 32) return 'length';
    const c = s[i];
    if (c === '.') {
      i++;
      if (s[i] === '.') return 'descent';
      if (s[i] === '*') {
        i++;
        continue;
      }
      const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i));
      if (!m) return 'name';
      i += m[0].length;
    } else if (c === '[') {
      const end = s.indexOf(']', i);
      if (end < 0) return 'bracket';
      const inner = s.slice(i + 1, end);
      if (inner !== '*') {
        if (!/^\d+$/.test(inner)) return 'bracket';
        if ((inner.length > 1 && inner.startsWith('0')) || Number(inner) > 1 << 20) return 'index';
      }
      i = end + 1;
    } else {
      return 'name';
    }
  }
  return null;
}

const PREFIX_RE = /^\/[A-Za-z0-9._~/-]*$/;

export function prefixValid(p: string): boolean {
  if (p.length > 256 || !PREFIX_RE.test(p)) return false;
  if (p === '/') return true;
  return !p.includes('//') && !p.split('/').some((seg) => seg === '.' || seg === '..');
}

const KEY_HEADER_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const KEY_HEADER_DENIED = /^(host|content-length|content-type|content-encoding|transfer-encoding|connection|upgrade|te|trailer|keep-alive|cookie|set-cookie|forwarded|via|traceparent|tracestate|baggage|expect|user-agent|x-forwarded-.*|proxy-.*)$/i;

export type BackendErrorKind = 'prefixes' | 'methods' | 'keyHeader' | 'request' | 'response' | 'scan';

/** What is wrong with a custom backend's configuration, by field; the first bad path is named. */
export function validateBackend(b: BackendConfig | null | undefined): Partial<Record<BackendErrorKind, { path?: string; reason?: JsonPathError }>> {
  const errs: Partial<Record<BackendErrorKind, { path?: string; reason?: JsonPathError }>> = {};
  if (!b) return { scan: {} };
  const prefixes = b.path_prefixes.map((p) => p.trim()).filter(Boolean);
  const badPrefix = prefixes.find((p) => !prefixValid(p));
  if (prefixes.length === 0 || prefixes.length > 20 || badPrefix !== undefined) errs.prefixes = { path: badPrefix };
  if (b.methods.length === 0 || b.methods.some((m) => !BACKEND_METHODS.includes(m))) errs.methods = {};
  const kh = (b.key_header ?? '').trim();
  if (kh && (!KEY_HEADER_RE.test(kh) || KEY_HEADER_DENIED.test(kh))) errs.keyHeader = {};
  for (const side of ['request', 'response'] as const) {
    const paths = b.scan[side].map((p) => p.trim()).filter(Boolean);
    if (paths.length > 50) errs[side] = {};
    for (const p of paths) {
      const reason = jsonPathError(p);
      if (reason) {
        errs[side] = { path: p, reason };
        break;
      }
    }
  }
  if (!errs.request && b.scan.request.every((p) => !p.trim()) && !b.scan.all_strings) errs.scan = {};
  return errs;
}

/** A human name for a provider id: from the catalog, else the built-in presets, else the id. */
export function providerLabel(catalog: readonly CatalogEntry[], id: string | undefined): string {
  if (!id) return '—';
  return catalog.find((c) => c.id === id)?.display_name ?? BUILTIN_CATALOG.find((c) => c.id === id)?.display_name ?? id;
}

/** Whether the provider is reached through its OpenAI-compatible endpoint (the UI says so). */
export function viaOpenAICompat(catalog: readonly CatalogEntry[], id: ProviderKind | undefined): boolean {
  const e = catalog.find((c) => c.id === id) ?? BUILTIN_CATALOG.find((c) => c.id === id);
  return e?.openai_compatible_endpoint === true;
}

/** Header names whose values are secrets: the control plane refuses them (use api_key_env). */
const SECRET_HEADER = /^(authorization|proxy-authorization|x-api-key|api-key|cookie)$/i;
/** Values that look like a secret token. */
const SECRET_VALUE = /^(sk-|sk_|Bearer\s|ghp_|xox[abp]-|AIza)|^[A-Za-z0-9_-]{32,}$/;

export type ProviderError = 'name' | 'url' | 'env' | 'header' | 'number' | 'defaultModel';

export function validateProvider(u: UpstreamInput): Partial<Record<keyof UpstreamInput, ProviderError>> {
  const errs: Partial<Record<keyof UpstreamInput, ProviderError>> = {};
  if (!UPSTREAM_NAME_RE.test(u.name)) errs.name = 'name';
  try {
    const url = new URL(u.base_url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') errs.base_url = 'url';
  } catch {
    errs.base_url = 'url';
  }
  if (u.api_key_env !== '' && !API_KEY_ENV_RE.test(u.api_key_env)) errs.api_key_env = 'env';
  for (const [k, v] of Object.entries(u.headers ?? {})) {
    if (!k.trim() || SECRET_HEADER.test(k.trim()) || SECRET_VALUE.test(v.trim())) errs.headers = 'header';
  }
  if (!Number.isFinite(u.timeout_ms) || u.timeout_ms < 1000) errs.timeout_ms = 'number';
  if (u.retries !== undefined && (!Number.isInteger(u.retries) || u.retries < 0 || u.retries > 5)) errs.retries = 'number';
  if (u.max_tokens_cap !== undefined && u.max_tokens_cap !== null && (!Number.isInteger(u.max_tokens_cap) || u.max_tokens_cap < 1)) errs.max_tokens_cap = 'number';
  if (u.default_model && u.models && u.models.length > 0 && !u.models.includes(u.default_model)) errs.default_model = 'defaultModel';
  return errs;
}

/** A provider name from a display name: lowercase, digits and dashes. */
export function slugName(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
}
