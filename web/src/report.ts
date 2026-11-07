// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Red-team feedback (docs/red-team.md): a request log row becomes a prefilled
// GitHub issue for the "Bypass" or "False positive" form
// (.github/ISSUE_TEMPLATE/). Everything here runs in the browser; the control
// plane sends nothing anywhere. The stored content goes into the report only
// when the row has it (the org stores content) and the user ticked "include
// the text" after the warning.

import type { AuditRow, GatewayModels } from './types';

export const REPO_URL = 'https://github.com/guard-spec/guard-spec';
export const SECURITY_REPORT_URL = `${REPO_URL}/security/advisories/new`;
export const RED_TEAM_DOC_URL = `${REPO_URL}/blob/main/docs/red-team.md`;

/**
 * Longest new-issue URL we open. GitHub answers 414 somewhere above 8 KB;
 * longer reports are copied to the clipboard and the empty form is opened.
 */
export const MAX_ISSUE_URL = 8000;

export type ReportKind = 'bypass' | 'false_positive';

/** The issue form of each kind (file names in .github/ISSUE_TEMPLATE/). */
export const REPORT_TEMPLATES: Record<ReportKind, string> = {
  bypass: 'bypass_report.yml',
  false_positive: 'false_positive_report.yml',
};

/** "Where it appeared": the options of the forms' `where` dropdown. */
export const WHERE_OPTIONS = ['User prompt', 'RAG document', 'Tool result', 'MCP tool description'] as const;
export type Where = (typeof WHERE_OPTIONS)[number];

/** A request that was allowed or only logged is a bypass candidate; a blocked or routed one a false positive. */
export function defaultKind(action: string): ReportKind {
  return action === 'block' || action === 'route' ? 'false_positive' : 'bypass';
}

/** Detector facts from GET /gateway/models, when the control plane can reach the gateway. */
export interface DetectorInfo {
  version: string | null;
  layers: string | null;
}

export function detectorInfo(g: GatewayModels | null | undefined): DetectorInfo {
  if (!g?.reachable) return { version: null, layers: null };
  const v = g.gateway_version?.trim();
  const version = v ? (/^\d/.test(v) ? `v${v}` : v) : null;
  const parts: string[] = [];
  if (g.layers && g.layers.length > 0) parts.push(g.layers.join(','));
  if (g.l2_model) parts.push(g.l2_model);
  if (g.fusion) parts.push(`fusion ${g.fusion}`);
  if (typeof g.l1_floor === 'number' && g.l1_floor > 0) parts.push(`L1 floor ${g.l1_floor}`);
  return { version, layers: parts.length > 0 ? parts.join(' · ') : null };
}

interface Block {
  type?: unknown;
  text?: unknown;
  content?: unknown;
}

const asBlock = (b: unknown): Block | null => (b !== null && typeof b === 'object' ? (b) : null);

function blockText(content: unknown): string | null {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return null;
  const texts = (content as unknown[])
    .map((x) => {
      if (typeof x === 'string') return x;
      const b = asBlock(x);
      if (typeof b?.text === 'string') return b.text;
      // Anthropic tool_result blocks nest their content.
      if (b?.type === 'tool_result') return blockText(b.content);
      return null;
    })
    .filter((s): s is string => typeof s === 'string' && s.length > 0);
  return texts.length > 0 ? texts.join('\n') : null;
}

/**
 * The text to report from a stored request body: for a chat request the last
 * user message (or the last tool result when the text came from a tool), for
 * other bodies `input` or `prompt`, else the body as stored.
 */
export function extractPrompt(content: string, where: Where = 'User prompt'): string {
  let body: unknown;
  try {
    body = JSON.parse(content);
  } catch {
    return content.trim();
  }
  if (!body || typeof body !== 'object') return content.trim();
  const b = body as { messages?: unknown; input?: unknown; prompt?: unknown };
  if (Array.isArray(b.messages)) {
    const msgs = (b.messages as unknown[]).map((m) => asBlock(m));
    const wantTool = where === 'Tool result' || where === 'RAG document';
    const pick = (pred: (m: { role?: unknown; content?: unknown }) => boolean) => {
      for (let i = msgs.length - 1; i >= 0; i--) {
        const m = msgs[i];
        if (m && pred(m)) {
          const t = blockText(m.content);
          if (t) return t;
        }
      }
      return null;
    };
    const isToolResult = (m: { role?: unknown; content?: unknown }) =>
      m.role === 'tool' || (Array.isArray(m.content) && (m.content as unknown[]).some((x) => asBlock(x)?.type === 'tool_result'));
    const found = (wantTool ? pick(isToolResult) : null) ?? pick((m) => m.role === 'user') ?? pick(() => true);
    if (found) return found.trim();
  }
  const fromInput = blockText(b.input) ?? (typeof b.prompt === 'string' ? b.prompt : null);
  if (fromInput) return fromInput.trim();
  return content.trim();
}

export interface ReportInput {
  kind: ReportKind;
  row: AuditRow;
  where: Where;
  detector: DetectorInfo;
  /** The rule's display name ("rule (policy)"), when the rule id resolves. */
  ruleName?: string | null;
  /** The text to include; null unless the user ticked "include the text". */
  prompt: string | null;
}

const num = (n: number | undefined | null) => (typeof n === 'number' && Number.isFinite(n) ? n.toFixed(3) : 'n/a');

/** The "Response or audit fields" block: what the row says about the decision. */
export function auditFields(r: ReportInput): string {
  const row = r.row;
  const flags = [row.had_tag_chars ? 'tag chars' : '', row.had_bidi ? 'bidi controls' : ''].filter(Boolean);
  const lines = [
    `decision: ${row.action}`,
    `injection_score: ${num(row.injection_score)} (fused over the layers that ran)`,
    `label: ${row.injection_label ?? 'n/a'}`,
    `rule: ${row.rule_id ? `${r.ruleName ?? 'unnamed'} [${row.rule_id.slice(0, 8)}]` : 'none (no rule matched)'}`,
    `anomaly_score: ${num(row.anomaly_score)} (L3 embeddings)`,
    `toxicity_score: ${num(row.toxicity_score)}`,
    `flags: ${flags.length > 0 ? flags.join(', ') : 'none'}`,
    `per-layer scores: not kept in the request log (POST /guardrail/scan returns scores.l1 / l2 / l3)`,
    `model: ${row.model ?? 'n/a'}`,
    `version: ${r.detector.version ?? 'unknown'}`,
    `layers: ${r.detector.layers ?? 'unknown'}`,
    `where: ${r.where}`,
    `text included: ${r.prompt ? 'yes (reviewed by the reporter)' : 'no'}`,
    'source: Guard Spec admin UI, Request log → Report',
  ];
  return lines.join('\n');
}

export function reportTitle(r: ReportInput): string {
  const label = r.row.injection_label ?? 'no label';
  const score = num(r.row.injection_score);
  return r.kind === 'bypass' ? `Bypass: ${r.row.action} at ${score} (${label})` : `False positive: ${r.row.action} at ${score} (${label})`;
}

/** The form fields we prefill (ids of the issue forms). Dropdowns and the consent boxes stay with the reporter. */
export function reportFields(r: ReportInput): Record<string, string> {
  const f: Record<string, string> = { title: reportTitle(r), audit: auditFields(r) };
  if (r.prompt) f.prompt = r.prompt;
  if (r.detector.version) f.version = r.detector.version;
  if (r.detector.layers) f.layers = r.detector.layers;
  return f;
}

/** The form's new-issue URL, with the given fields as query parameters. */
export function issueUrl(kind: ReportKind, fields: Record<string, string> = {}): string {
  const q = [`template=${encodeURIComponent(REPORT_TEMPLATES[kind])}`];
  for (const [k, v] of Object.entries(fields)) q.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  return `${REPO_URL}/issues/new?${q.join('&')}`;
}

/** The whole report as Markdown, for the clipboard when the URL is too long. */
export function reportMarkdown(r: ReportInput): string {
  const f = reportFields(r);
  const out = [`Title: ${f.title}`, '', '### Prompt', '', '```text', f.prompt ?? '(not included: paste a synthetic or anonymised version)', '```', ''];
  out.push('### Where it appeared', '', r.where, '');
  out.push('### Guard Spec version', '', f.version ?? '', '');
  out.push('### Detector layers', '', f.layers ?? '', '');
  out.push('### Response or audit fields', '', '```text', f.audit ?? '', '```', '');
  return out.join('\n');
}

export interface IssueLink {
  /** The URL to open: prefilled, or the empty form when the prefilled one is too long. */
  url: string;
  /** true: the prefilled URL was too long; the report must go through the clipboard. */
  tooLong: boolean;
  /** What to copy when tooLong. */
  clipboard: string;
}

export function issueLink(r: ReportInput, max = MAX_ISSUE_URL): IssueLink {
  const full = issueUrl(r.kind, reportFields(r));
  if (full.length <= max) return { url: full, tooLong: false, clipboard: '' };
  return { url: issueUrl(r.kind), tooLong: true, clipboard: reportMarkdown(r) };
}
