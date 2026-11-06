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
