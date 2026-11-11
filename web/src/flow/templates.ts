// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Ready-made rules for a scope without rules. Each condition uses only the
// fields, operators and value types internal/policy leafToCEL accepts (see
// templates.test.ts), so the control plane saves it as is.

import type { MessageKey } from '../i18n';
import type { Action, ConditionGroup, Upstream } from '../types';
import { newKey, type EditableRule } from './model';

export type TemplateId = 'blockInjection' | 'logTools' | 'routeSuspicious' | 'blockHidden';

export interface RuleTemplate {
  id: TemplateId;
  name: MessageKey;
  desc: MessageKey;
  /** For a route template: the upstream it sends to. */
  target?: string;
  action: Action;
  condition: ConditionGroup;
}

/**
 * The templates for a scope. Routing is offered only when an enabled
 * upstream other than the scope's default exists.
 */
export function ruleTemplates(upstreams: readonly Upstream[], defaultUpstream: string | undefined): RuleTemplate[] {
  const out: RuleTemplate[] = [
    {
      id: 'blockInjection',
      name: 'tpl.blockInjection.name',
      desc: 'tpl.blockInjection.desc',
      action: 'block',
      condition: {
        combinator: 'and',
        rules: [
          { field: 'injection.score', operator: '>=', value: '0.7' },
          { field: 'injection.label', operator: '!=', value: 'BENIGN' },
        ],
      },
    },
    {
      id: 'logTools',
      name: 'tpl.logTools.name',
      desc: 'tpl.logTools.desc',
      action: 'log',
      condition: {
        combinator: 'and',
        rules: [
          { field: 'mcp.is_tool_response', operator: '=', value: 'true' },
          { field: 'indirect.score', operator: '>=', value: '0.5' },
        ],
      },
    },
  ];
  const alternative = upstreams.find((u) => u.enabled && u.name !== defaultUpstream);
  if (alternative) {
    out.push({
      id: 'routeSuspicious',
      name: 'tpl.routeSuspicious.name',
      desc: 'tpl.routeSuspicious.desc',
      target: alternative.name,
      action: 'route',
      condition: { combinator: 'and', rules: [{ field: 'injection.score', operator: '>=', value: '0.5' }] },
    });
  }
  out.push({
    id: 'blockHidden',
    name: 'tpl.blockHidden.name',
    desc: 'tpl.blockHidden.desc',
    action: 'block',
    condition: {
      combinator: 'or',
      rules: [
        { field: 'anomaly.has_tag_chars', operator: '=', value: 'true' },
        { field: 'anomaly.has_bidi', operator: '=', value: 'true' },
      ],
    },
  });
  return out;
}

/** A new rule from a template, named in the user's language. */
export function ruleFromTemplate(tpl: RuleTemplate, name: string): EditableRule {
  const rule: EditableRule = {
    key: newKey(),
    name,
    action: tpl.action,
    condition: structuredClone(tpl.condition),
  };
  if (tpl.action === 'route' && tpl.target) rule.route_target = tpl.target;
  return rule;
}

// ── Policy templates (RF-a1dbafea U3) ──────────────────────────────────────

export type PolicyTemplateId = 'pii' | 'otpKyc' | 'banking';

export interface PolicyRuleTemplate {
  name: MessageKey;
  action: Action;
  condition: ConditionGroup;
}

export interface PolicyTemplate {
  id: PolicyTemplateId;
  name: MessageKey;
  desc: MessageKey;
  /** Uses input.pii.*, which needs "Detect personal data in requests" in the guard settings. */
  needsPii: boolean;
  rules: PolicyRuleTemplate[];
}

const has = (kind: string) => ({ field: 'input.pii.kinds', operator: 'contains', value: kind });

/**
 * Whole policies for common cases, created in one click. They start log-only
 * (the request log shows what they would block) so that turning them on is a
 * decision; each condition uses only fields, operators and values the
 * control plane's schema accepts (templates.test.ts).
 */
export const POLICY_TEMPLATES: readonly PolicyTemplate[] = [
  {
    id: 'pii',
    name: 'ptpl.pii.name',
    desc: 'ptpl.pii.desc',
    needsPii: true,
    rules: [
      { name: 'ptpl.pii.card', action: 'block', condition: { combinator: 'and', rules: [has('card')] } },
      { name: 'ptpl.pii.cccd', action: 'block', condition: { combinator: 'and', rules: [has('cccd')] } },
      { name: 'ptpl.pii.other', action: 'log', condition: { combinator: 'and', rules: [{ field: 'input.pii.count', operator: '>=', value: '1' }] } },
    ],
  },
  {
    id: 'otpKyc',
    name: 'ptpl.otpKyc.name',
    desc: 'ptpl.otpKyc.desc',
    needsPii: true,
    rules: [
      {
        name: 'ptpl.otpKyc.extract',
        action: 'block',
        condition: {
          combinator: 'and',
          rules: [
            { field: 'injection.score', operator: '>=', value: '0.5' },
            {
              combinator: 'or',
              rules: [
                { field: 'injection.category', operator: '=', value: 'data_exfiltration' },
                { field: 'injection.category', operator: '=', value: 'prompt_extraction' },
              ],
            },
          ],
        },
      },
      { name: 'ptpl.otpKyc.idDocs', action: 'block', condition: { combinator: 'and', rules: [has('cccd'), has('phone')] } },
      {
        name: 'ptpl.otpKyc.photos',
        action: 'log',
        condition: { combinator: 'and', rules: [{ field: 'input.unscanned.kinds', operator: 'contains', value: 'image' }] },
      },
    ],
  },
  {
    id: 'banking',
    name: 'ptpl.banking.name',
    desc: 'ptpl.banking.desc',
    needsPii: true,
    rules: [
      { name: 'ptpl.banking.strict', action: 'block', condition: { combinator: 'and', rules: [{ field: 'injection.score', operator: '>=', value: '0.6' }] } },
      { name: 'ptpl.banking.indirect', action: 'block', condition: { combinator: 'and', rules: [{ field: 'indirect.score', operator: '>=', value: '0.5' }] } },
      {
        name: 'ptpl.banking.hidden',
        action: 'block',
        condition: {
          combinator: 'or',
          rules: [
            { field: 'anomaly.has_tag_chars', operator: '=', value: 'true' },
            { field: 'anomaly.has_bidi', operator: '=', value: 'true' },
          ],
        },
      },
      { name: 'ptpl.banking.card', action: 'block', condition: { combinator: 'and', rules: [has('card')] } },
    ],
  },
];

/** A free policy name: the template's, or with " 2", " 3"… when taken. */
export function freePolicyName(name: string, taken: (n: string) => boolean): string {
  if (!taken(name)) return name;
  for (let i = 2; ; i++) {
    const n = `${name} ${i}`;
    if (!taken(n)) return n;
  }
}

/** The rules of a policy template, named in the user's language. */
export function policyTemplateRules(tpl: PolicyTemplate, name: (key: MessageKey) => string): EditableRule[] {
  return tpl.rules.map((r) => ({ key: newKey(), name: name(r.name), action: r.action, condition: structuredClone(r.condition) }));
}
