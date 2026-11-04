// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Node ids of the Flow diagram.

const UPSTREAM = 'up:';
const RULE = 'rule:';

export const NODE = {
  request: 'request',
  key: 'key',
  l0: 'l0',
  /** The detection layers L1, L2 and L3, one node. */
  detectors: 'detectors',
  block: 'term:block',
  log: 'term:log',
  allow: 'term:allow',
  /** The gateway's own upstream: UPSTREAM_LLM_URL, or the stub answer. */
  envUpstream: 'up-env',
  output: 'output',
  client: 'client',
  rule: (key: string) => RULE + key,
  ruleKey: (id: string): string | undefined => (id.startsWith(RULE) ? id.slice(RULE.length) : undefined),
  upstream: (name: string) => UPSTREAM + name,
  upstreamName: (id: string): string | undefined => (id.startsWith(UPSTREAM) ? id.slice(UPSTREAM.length) : undefined),
} as const;
