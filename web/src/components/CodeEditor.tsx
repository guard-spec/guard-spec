// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// CodeMirror 6 editor in two modes: YAML (config as code) and expression
// (rule conditions).
//
// CSP: CodeMirror (style-mod) adds a <style> element to a document's head,
// which style-src 'self' blocks; inside a shadow root it uses a constructable
// stylesheet (adoptedStyleSheets) instead, which the CSP allows. So the editor
// is mounted in an open shadow root. Theme colours come in through CSS custom
// properties, which inherit across the shadow boundary.

import { autocompletion, closeBrackets, type CompletionContext, type CompletionResult } from '@codemirror/autocomplete';
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
import { yaml } from '@codemirror/lang-yaml';
import { bracketMatching, HighlightStyle, indentOnInput, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { lintGutter, setDiagnostics, type Diagnostic } from '@codemirror/lint';
import { unifiedMergeView } from '@codemirror/merge';
import { Compartment, EditorState, type Extension } from '@codemirror/state';
import { EditorView, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers, placeholder as placeholderExt } from '@codemirror/view';
import { tags } from '@lezer/highlight';
import { useEffect, useLayoutEffect, useRef } from 'react';

export interface EditorDiagnostic {
  from: number;
  to?: number;
  message: string;
  severity?: 'error' | 'warning' | 'info';
}

/** A tokenizer for rule expressions: fields, literals, &&, ||, !, comparisons, in, method calls. */
export const expressionLanguage = StreamLanguage.define<{ inString: boolean }>({
  name: 'guard-expression',
  startState: () => ({ inString: false }),
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^"(?:[^"\\]|\\.)*"?/)) return 'string';
    if (stream.match(/^'(?:[^'\\]|\\.)*'?/)) return 'string';
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return 'number';
    if (stream.match(/^(&&|\|\||==|!=|>=|<=|>|<|!)/)) return 'operator';
    if (stream.match(/^(true|false)\b/)) return 'bool';
    if (stream.match(/^in\b/)) return 'keyword';
    if (stream.match(/^\.(contains|startsWith|endsWith)\b/)) return 'function';
    if (stream.match(/^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*/)) return 'variableName';
    if (stream.match(/^[()[\],]/)) return 'punctuation';
    stream.next();
    return 'invalid';
  },
  tokenTable: {
    function: tags.function(tags.propertyName),
  },
});

const highlight = HighlightStyle.define([
  { tag: tags.string, color: 'var(--cm-string)' },
  { tag: tags.number, color: 'var(--cm-number)' },
  { tag: tags.bool, color: 'var(--cm-number)' },
  { tag: [tags.operator, tags.keyword], color: 'var(--cm-keyword)', fontWeight: '600' },
  { tag: tags.variableName, color: 'var(--cm-variable)' },
  { tag: tags.function(tags.propertyName), color: 'var(--cm-function)' },
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: 'var(--cm-variable)' },
  { tag: tags.comment, color: 'var(--muted)', fontStyle: 'italic' },
  { tag: tags.invalid, color: 'var(--danger)' },
]);

const baseTheme = EditorView.theme({
  '&': { color: 'var(--text)', backgroundColor: 'var(--input-bg)', fontSize: '13px', border: '1px solid var(--border)', borderRadius: '6px' },
  '&.cm-focused': { outline: '2px solid var(--focus)', outlineOffset: '1px' },
  '.cm-content': { fontFamily: 'var(--mono)', caretColor: 'var(--text)' },
  '.cm-gutters': { backgroundColor: 'var(--surface-2)', color: 'var(--muted)', border: 'none', borderRight: '1px solid var(--border)' },
  '.cm-activeLine': { backgroundColor: 'var(--active-line)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--active-line)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'var(--selection) !important' },
  '.cm-cursor': { borderLeftColor: 'var(--text)' },
  '.cm-tooltip': { backgroundColor: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)' },
  '.cm-tooltip-autocomplete ul li[aria-selected]': { backgroundColor: 'var(--accent)', color: 'var(--on-accent)' },
  '.cm-diagnostic-error': { borderLeftColor: 'var(--danger)' },
  // The lint extension draws markers and underlines with data: SVG images,
  // which img-src 'self' blocks: replace them with plain CSS.
  '& .cm-lintRange-error, & .cm-lintRange-warning, & .cm-lintRange-info, & .cm-lintRange-hint': {
    backgroundImage: 'none',
    textDecoration: 'underline wavy var(--danger)',
    textDecorationSkipInk: 'none',
  },
  '& .cm-lint-marker, & .cm-lint-marker-error, & .cm-lint-marker-warning, & .cm-lint-marker-info': {
    content: 'none',
    display: 'inline-block',
    width: '0.7em',
    height: '0.7em',
    margin: '0.25em 0.15em',
    borderRadius: '50%',
    backgroundColor: 'var(--danger)',
  },
  '.cm-placeholder': { color: 'var(--muted)' },
  '.cm-changedLine': { backgroundColor: 'var(--diff-add-bg) !important' },
  '.cm-deletedChunk': { backgroundColor: 'var(--diff-del-bg) !important' },
  '.cm-changedText': { backgroundColor: 'var(--diff-add-text) !important' },
});

const largeTheme = EditorView.theme({
  '&': { height: 'calc(100vh - 240px)', minHeight: '360px' },
  '.cm-scroller': { overflow: 'auto' },
});

const smallTheme = EditorView.theme({
  '&': { minHeight: '72px' },
});

function fieldCompletions(fields: readonly string[]) {
  return (ctx: CompletionContext): CompletionResult | null => {
    const word = ctx.matchBefore(/[A-Za-z_][\w.]*/);
    if (!word || (word.from === word.to && !ctx.explicit)) return null;
    return {
      from: word.from,
      options: [
        ...fields.map((f) => ({ label: f, type: 'variable' })),
        { label: 'in', type: 'keyword' },
        { label: 'true', type: 'keyword' },
        { label: 'false', type: 'keyword' },
      ],
      validFor: /^[\w.]*$/,
    };
  };
}

export interface CodeEditorProps {
  value: string;
  onChange?: (value: string) => void;
  mode: 'yaml' | 'expression';
  ariaLabel: string;
  diagnostics?: EditorDiagnostic[];
  /** Field names offered by completion (expression mode). */
  fields?: readonly string[];
  /** Shows a unified diff against this text. */
  original?: string | null;
  readOnly?: boolean;
  placeholder?: string;
  minHeight?: 'small' | 'large';
  testId?: string;
}

export function CodeEditor(props: CodeEditorProps) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const onChange = useRef(props.onChange);
  useLayoutEffect(() => {
    onChange.current = props.onChange;
  });
  const compartments = useRef({ lang: new Compartment(), diff: new Compartment(), ro: new Compartment(), complete: new Compartment() });

  // Create the view once.
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const shadow = el.shadowRoot ?? el.attachShadow({ mode: 'open' });
    const parent = document.createElement('div');
    shadow.appendChild(parent);
    const c = compartments.current;
    const multiLine = props.mode === 'yaml';
    const extensions: Extension[] = [
      history(),
      closeBrackets(),
      bracketMatching(),
      indentOnInput(),
      highlightActiveLine(),
      syntaxHighlighting(highlight),
      baseTheme,
      (props.minHeight ?? (props.mode === 'yaml' ? 'large' : 'small')) === 'large' ? largeTheme : smallTheme,
      lintGutter(),
      keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
      EditorView.contentAttributes.of({ 'aria-label': props.ariaLabel, ...(props.testId ? { 'data-testid': props.testId } : {}) }),
      EditorView.updateListener.of((u) => {
        if (u.docChanged) onChange.current?.(u.state.doc.toString());
      }),
      c.lang.of(props.mode === 'yaml' ? yaml() : expressionLanguage),
      c.complete.of(props.mode === 'expression' ? autocompletion({ override: [fieldCompletions(props.fields ?? [])] }) : []),
      c.diff.of([]),
      c.ro.of(EditorState.readOnly.of(props.readOnly ?? false)),
    ];
    if (multiLine) extensions.push(lineNumbers(), highlightActiveLineGutter());
    else extensions.push(EditorView.lineWrapping);
    if (props.placeholder) extensions.push(placeholderExt(props.placeholder));
    const v = new EditorView({ parent, root: shadow, state: EditorState.create({ doc: props.value, extensions }) });
    view.current = v;
    return () => {
      v.destroy();
      parent.remove();
      view.current = null;
    };
    // Recreated only when the mode changes; other props are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.mode]);

  // Outside value changes.
  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const cur = v.state.doc.toString();
    if (cur !== props.value) {
      v.dispatch({ changes: { from: 0, to: cur.length, insert: props.value } });
    }
  }, [props.value]);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const len = v.state.doc.length;
    const diags: Diagnostic[] = (props.diagnostics ?? []).map((d) => {
      const from = Math.max(0, Math.min(d.from, len));
      const to = Math.max(from, Math.min(d.to ?? from + 1, len));
      return { from, to: to === from && from < len ? from + 1 : to, message: d.message, severity: d.severity ?? 'error' };
    });
    v.dispatch(setDiagnostics(v.state, diags));
  }, [props.diagnostics, props.value]);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    v.dispatch({
      effects: compartments.current.diff.reconfigure(
        props.original !== null && props.original !== undefined ? unifiedMergeView({ original: props.original, mergeControls: false, gutter: true }) : [],
      ),
    });
  }, [props.original]);

  useEffect(() => {
    const v = view.current;
    if (!v || props.mode !== 'expression') return;
    v.dispatch({ effects: compartments.current.complete.reconfigure(autocompletion({ override: [fieldCompletions(props.fields ?? [])] })) });
  }, [props.fields, props.mode]);

  return <div ref={host} className="code-editor" />;
}
