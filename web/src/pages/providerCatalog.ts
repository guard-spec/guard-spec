// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Provider presets used when the control plane has no GET /providers/catalog
// yet (identity contract §6). The gateway speaks the OpenAI chat-completions
// format upstream, so Anthropic and Gemini use their OpenAI-compatible
// endpoints.

import { API_KEY_ENV_RE, UPSTREAM_NAME_RE, type CatalogEntry, type ProviderKind, type UpstreamInput } from '../types';

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
];

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
