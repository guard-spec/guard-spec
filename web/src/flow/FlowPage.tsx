// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The Flow page: the request path of a scope as a diagram, with the policy
// rules as editable nodes, a rule editor and a simulator.

import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Connection,
  type Edge,
  type IsValidConnection,
  type NodeChange,
  type OnNodeDrag,
  type XYPosition,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ConfirmDialog, Dialog, ErrorBanner, Field, Loading, PageHeader } from '../components/ui';
import { errorText, useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { href, onLink, setNavigationGuard, takeParam } from '../router';
import type { GatewayModels, GuardSettings, PolicySchema, SimulateRequest, SimulateResponse, SimValue } from '../types';
import { addRule, connectRule, danglingRoutes, deleteRule, findRule, moveRule, moveRuleByPosition, updateRule } from './edit';
import { applyHighlight, buildGraph, simulationPath, type DefaultUpstream, type FlowEdge, type FlowNode } from './graph';
import { guardChanged, saveAll } from './guardDraft';
import { EDGE_KINDS, type EdgeKindHelp, type NodeKind } from './help';
import { EdgeTip, NodeTip } from './HelpText';
import { NODE } from './ids';
import { bounds, fitViewport, layoutGraph, mainAxis, type Direction } from './layout';
import {
  gatewayChain,
  gatewayOrder,
  makeRule,
  newKey,
  policyNameTaken,
  toEditable,
  toWireRules,
  type EditablePolicy,
  type EditableRule,
} from './model';
import { NodePanel } from './NodePanel';
import { DirectionContext, nodeTypes } from './nodes';
import { RulePanel, type TextState } from './RulePanel';
import { FALLBACK_SCHEMA, fieldTypesOf } from './schema';
import { mergeAfterSave } from './save';
import { Simulator } from './Simulator';
import { ruleFromTemplate, ruleTemplates, type RuleTemplate } from './templates';
import { hasErrors, INJECTION_BLOCK, validateCondition } from './validate';

const EDGE_CLASS: Record<string, string> = {
  flow: 'edge-flow',
  next: 'edge-next',
  match: 'edge-match',
  log: 'edge-log',
  default: 'edge-default',
  idle: 'edge-idle',
};

function styleEdges(edges: FlowEdge[]): Edge[] {
  return edges.map((e) => ({
    ...e,
    type: 'smoothstep',
    className: [EDGE_CLASS[e.data?.kind ?? 'flow'], e.className].filter(Boolean).join(' '),
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    labelBgPadding: [4, 2] as [number, number],
    labelBgBorderRadius: 4,
    focusable: false,
  }));
}

export default function FlowPage() {
  return (
    <ReactFlowProvider>
      <FlowPageInner />
    </ReactFlowProvider>
  );
}

function FlowPageInner() {
  const { api, t, theme, notify } = useApp();
  const { org, projects, upstreams, upstreamError, can } = useOrg();
  const writable = can('policies.write');
  const guardWritable = can('org.settings.write');
  const [original, setOriginal] = useState<EditablePolicy[] | null>(null);
  const [policies, setPolicies] = useState<EditablePolicy[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [schema, setSchema] = useState<PolicySchema>(FALLBACK_SCHEMA);
  // The guard settings as saved, and with the edits staged on this page.
  const [guard, setGuard] = useState<GuardSettings | null>(null);
  const [guardDraft, setGuardDraft] = useState<GuardSettings | null>(null);
  const [guardError, setGuardError] = useState<string | null>(null);
  const [invalidGuard, setInvalidGuard] = useState<ReadonlySet<string>>(new Set());
  const [models, setModels] = useState<GatewayModels | null>(null);
  // The open panel of a node other than a rule (a rule uses selected).
  const [nodePanel, setNodePanel] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [dir, setDir] = useState<Direction>('TB');
  const [selected, setSelected] = useState<string | null>(null);
  const [sim, setSim] = useState<SimulateResponse | null>(null);
  const [ruleErrors, setRuleErrors] = useState<Record<string, string>>({});
  const [saveErrors, setSaveErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  // A navigation held by unsaved edits, completed on confirmation.
  const [leaving, setLeaving] = useState<(() => void) | null>(null);
  // The open rule's Text tab: Save waits until its text parses.
  const [textState, setTextState] = useState<TextState>('ok');
  const [activePolicy, setActivePolicy] = useState<string | null>(null);
  // The new-policy dialog; with key, it renames that policy.
  const [newPolicy, setNewPolicy] = useState<{ key?: string; name: string; project: string } | null>(null);
  const [deleting, setDeleting] = useState<EditablePolicy | null>(null);
  const { setViewport } = useReactFlow();
  const paneRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const ps = (await api.listPolicies(org.id)).map(toEditable);
      setPolicies(ps);
      setOriginal(ps);
      setLoadError(null);
      // A link from elsewhere (config export problems) names a policy, maybe a rule.
      const focus = takeParam('policy');
      const ruleName = takeParam('rule');
      const p = focus ? ps.find((x) => x.id === focus) : undefined;
      if (p) {
        setProjectId(p.project_id);
        setActivePolicy(p.key);
        const r = ruleName !== null ? p.rules.find((x) => x.name === ruleName) : undefined;
        if (r) setSelected(r.key);
      }
    } catch (e) {
      setLoadError(errorText(e));
    }
    api.getPolicySchema().then(setSchema, () => setSchema(FALLBACK_SCHEMA));
    api.getGuardSettings(org.id).then(
      (g) => {
        setGuard(g);
        setGuardDraft(g);
        setGuardError(null);
      },
      (e: unknown) => {
        setGuard(null);
        setGuardDraft(null);
        setGuardError(errorText(e));
      },
    );
    api.getGatewayModels().then(setModels, () => setModels(null));
  }, [api, org.id]);

  const onGuardInvalid = useCallback((field: string, invalid: boolean) => {
    setInvalidGuard((s) => {
      if (s.has(field) === invalid) return s;
      const next = new Set(s);
      if (invalid) next.add(field);
      else next.delete(field);
      return next;
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const upstreamNames = useMemo(() => (upstreams ?? []).map((u) => u.name), [upstreams]);
  const fieldTypes = useMemo(() => fieldTypesOf(schema), [schema]);

  const scopePolicies = useMemo(
    () =>
      (policies ?? [])
        .filter((p) => p.project_id === null || p.project_id === projectId)
        .sort(gatewayOrder),
    [policies, projectId],
  );
  const chain = useMemo(() => gatewayChain(policies ?? [], projectId), [policies, projectId]);
  const guardDirty = guardChanged(guard, guardDraft);
  const dirtyCount = (policies ?? []).filter((p) => p.dirty).length + (guardDirty ? 1 : 0);
  const injectionThreshold = guardDraft?.injection_threshold ?? INJECTION_BLOCK;
  // Rules of changed policies whose condition the server would refuse.
  const condErrors = useMemo(
    () =>
      (policies ?? [])
        .filter((p) => p.dirty)
        .flatMap((p) => p.rules)
        .filter((r) => hasErrors(validateCondition(r.condition, schema, { injectionThreshold }))).length,
    [policies, schema, injectionThreshold],
  );

  const defaultUpstream: DefaultUpstream = useMemo(() => {
    const byId = (id: string | null | undefined) => (id ? (upstreams ?? []).find((u) => u.id === id)?.name : undefined);
    const project = projects.find((p) => p.id === projectId);
    const fromProject = byId(project?.default_upstream_id);
    if (fromProject) return { source: 'project', name: fromProject };
    const fromOrg = byId(org.default_upstream_id);
    if (fromOrg) return { source: 'org', name: fromOrg };
    return { source: 'env' };
  }, [upstreams, projects, projectId, org.default_upstream_id]);

  const scopeLabel = projectId ? t('flow.scopeProject', { name: projects.find((p) => p.id === projectId)?.name ?? projectId }) : t('flow.anyKey');

  const graph = useMemo(
    () =>
      buildGraph({
        chain,
        upstreams: upstreams ?? [],
        defaultUpstream,
        guard: guardDraft,
        layers: models && models.configured && models.reachable ? models.layers : undefined,
        scopeLabel,
        fieldTypes,
        ruleErrors,
        t: t as (k: string, p?: Record<string, string | number>) => string,
      }),
    [chain, upstreams, defaultUpstream, guardDraft, models, scopeLabel, fieldTypes, ruleErrors, t],
  );
  const laid = useMemo(() => {
    const nodes = layoutGraph(graph.nodes, graph.edges, dir);
    const path = sim ? simulationPath(graph, sim) : null;
    const hl = applyHighlight({ nodes, edges: graph.edges }, path);
    return {
      nodes: hl.nodes.map((n) => ({
        ...n,
        draggable: n.type === 'rule',
        selectable: true,
        selected: selected !== null ? n.id === NODE.rule(selected) : n.id === nodePanel,
        ariaLabel: n.data.kind === 'rule' ? `${n.data.name}: ${n.data.action}, ${n.data.text}` : n.data.title,
      })),
      edges: styleEdges(hl.edges),
    };
  }, [graph, dir, sim, selected, nodePanel]);

  // The laid-out nodes, with the position of a node being dragged.
  const [drag, setDrag] = useState<{ id: string; position: XYPosition } | null>(null);
  const nodes = useMemo(
    () => (drag ? laid.nodes.map((n) => (n.id === drag.id ? { ...n, position: drag.position } : n)) : laid.nodes),
    [laid.nodes, drag],
  );

  // Open fitted to view: the whole diagram, centred (the fit view control
  // does the same after panning).
  const loaded = policies !== null;
  const box = bounds(laid.nodes);
  const boxKey = `${Math.round(box.width)}x${Math.round(box.height)}`;
  useEffect(() => {
    const pane = paneRef.current;
    if (!pane || !loaded) return;
    const b = bounds(laid.nodes);
    void setViewport(fitViewport(b, { width: pane.clientWidth, height: pane.clientHeight }));
    // Only on a new scope, direction or shape, not on every edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir, projectId, loaded, boxKey, setViewport]);

  const edit = (f: (ps: EditablePolicy[]) => EditablePolicy[]) => {
    setPolicies((ps) => (ps ? f(ps) : ps));
    setSim(null);
  };

  // Opens the side panel of a node: the rule editor, or the node's panel.
  const openNode = useCallback((id: string) => {
    const key = NODE.ruleKey(id);
    if (key) {
      setSelected(key);
      setNodePanel(null);
    } else {
      setSelected(null);
      setNodePanel(id);
    }
  }, []);
  const selectRule = (key: string) => {
    setSelected(key);
    setNodePanel(null);
  };

  // Drags move nodes; a selection (a click, or Enter on a focused node)
  // opens its panel. Layout and highlight come from the model.
  const onNodesChange = useCallback(
    (changes: NodeChange<FlowNode>[]) => {
      for (const c of changes) {
        if (c.type === 'position' && c.position) setDrag({ id: c.id, position: c.position });
        if (c.type === 'select' && c.selected) openNode(c.id);
      }
    },
    [openNode],
  );

  const onNodeDragStop: OnNodeDrag<FlowNode> = (_e, node) => {
    setDrag(null);
    const key = NODE.ruleKey(node.id);
    if (!key || !policies) return;
    const coords = new Map<string, number>();
    for (const n of nodes) {
      const k = NODE.ruleKey(n.id);
      if (k) coords.set(k, mainAxis(n.id === node.id ? node : n, dir));
    }
    const next = moveRuleByPosition(policies, key, coords);
    if (next !== policies) edit(() => next);
  };

  const isValidConnection: IsValidConnection = (c) => {
    if (!NODE.ruleKey(c.source)) return false;
    if (c.target === NODE.block || c.target === NODE.allow || c.target === NODE.log) return true;
    const name = NODE.upstreamName(c.target);
    return name !== undefined && upstreamNames.includes(name);
  };

  const onConnect = (c: Connection) => {
    const key = NODE.ruleKey(c.source);
    if (!key) return;
    edit((ps) => connectRule(ps, key, c.target, upstreamNames));
    selectRule(key);
  };

  const ensurePolicy = (ps: EditablePolicy[]): { ps: EditablePolicy[]; key: string } => {
    const scoped = ps.filter((p) => p.project_id === null || p.project_id === projectId);
    const active = scoped.find((p) => p.key === activePolicy) ?? gatewayChain(ps, projectId)[0] ?? scoped[0];
    if (active) return { ps, key: active.key };
    const draft: EditablePolicy = {
      id: undefined,
      key: newKey('policy'),
      name: 'default',
      description: null,
      project_id: projectId,
      enabled: true,
      log_only: false,
      created_at: '',
      rules: [],
      dirty: true,
    };
    return { ps: [...ps, draft], key: draft.key };
  };

  const onAddRule = () => {
    if (!policies) return;
    const { ps, key } = ensurePolicy(policies);
    const rule = makeRule(t('rule.newName'));
    edit(() => addRule(ps, key, rule));
    setActivePolicy(key);
    selectRule(rule.key);
  };

  const onTemplate = (tpl: RuleTemplate) => {
    if (!policies) return;
    const { ps, key } = ensurePolicy(policies);
    const rule = ruleFromTemplate(tpl, t(tpl.name, { target: tpl.target ?? '' }));
    edit(() => addRule(ps, key, rule));
    setActivePolicy(key);
    selectRule(rule.key);
    notify(t('tpl.added'));
  };

  // Unsaved edits: ask before leaving the page, and before closing the tab.
  const hasEdits = (policies ?? []).some((p) => p.dirty) || guardDirty;
  useEffect(() => {
    if (!hasEdits) return;
    setNavigationGuard((proceed) => {
      setLeaving(() => proceed);
      return true;
    });
    const onUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener('beforeunload', onUnload);
    return () => {
      setNavigationGuard(null);
      window.removeEventListener('beforeunload', onUnload);
    };
  }, [hasEdits]);

  // One save for the staged guard settings and the policies: the guard
  // settings first (one request), then each changed policy. A part that
  // fails keeps its edits and gets its own message; the others are saved.
  const save = async () => {
    if (!policies) return;
    setSaving(true);
    const dirtyPolicies = policies.filter((p) => p.dirty).length;
    const result = await saveAll(api, org.id, { saved: guard, draft: guardDraft }, policies);
    const errors = result.errors.map((e) => t('flow.saveFailed', { name: e.policy, error: e.message }));
    if (result.guardError) errors.unshift(t('flow.guardSaveFailed', { error: result.guardError }));
    if (result.guard) {
      setGuard(result.guard);
      setGuardDraft(result.guard);
    }
    const savedSomething = result.guard !== undefined || result.errors.length < dirtyPolicies;
    if (errors.length > 0 && savedSomething) errors.push(t('flow.partialSave'));
    setSaveErrors(errors);
    setRuleErrors(result.ruleErrors);
    try {
      if (dirtyPolicies > 0) {
        const fresh = (await api.listPolicies(org.id)).map(toEditable);
        const merged = mergeAfterSave(fresh, result.keep);
        setOriginal(fresh);
        setPolicies(merged);
        // Saved rules got server ids: keep the selection on the same rule if it still exists.
        if (errors.length === 0) setSelected((s) => (s && findRule(merged, s) ? s : null));
      }
      if (errors.length === 0) {
        notify(dirtyPolicies > 0 && result.guard ? t('flow.savedAll') : result.guard ? t('flow.guardSaved') : t('flow.savedOk'));
      }
    } catch (e) {
      setSaveErrors([...errors, errorText(e)]);
    } finally {
      setSaving(false);
    }
  };

  const makeSimRequest = (vars: Record<string, SimValue>): SimulateRequest =>
    dirtyCount > 0
      ? { rules: chain.flatMap((p) => toWireRules(p.rules)), project_id: projectId, vars }
      : { policy_id: null, project_id: projectId, vars };

  const nameTaken = newPolicy !== null && policies !== null && policyNameTaken(policies, newPolicy.name, newPolicy.key);
  if (loadError) return <ErrorBanner error={loadError} />;
  if (!policies) return <Loading />;

  const sel = selected ? findRule(policies, selected) : undefined;
  const chainRules = chain.flatMap((p) => p.rules.map((r, i) => ({ p, r, i })));
  const dangling = danglingRoutes(chain, upstreamNames);
  const templates = chainRules.length === 0 ? ruleTemplates(upstreams ?? [], defaultUpstream.name) : [];
  const blocked = textState !== 'ok' || condErrors > 0 || invalidGuard.size > 0;

  return (
    <div className="flow-page">
      <PageHeader
        title={t('flow.title')}
        help={t('flow.help')}
        actions={
          <>
            {dirtyCount > 0 ? <span className="badge badge-warn">{t('flow.unsaved', { count: dirtyCount })}</span> : null}
            <button type="button" className="btn" disabled={dirtyCount === 0 || saving} onClick={() => {
                setPolicies(original);
                setGuardDraft(guard);
                setRuleErrors({});
                setSaveErrors([]);
              }}>
              {t('flow.discard')}
            </button>
            {textState !== 'ok' ? (
              <span className="badge badge-warn" role="status">
                {textState === 'pending' ? t('flow.textPending') : t('flow.textError')}
              </span>
            ) : condErrors > 0 || invalidGuard.size > 0 ? (
              <span className="badge badge-warn" role="status">
                {condErrors > 0 ? t('flow.fixConditions') : t('panel.detectors.thresholdError')}
              </span>
            ) : null}
            <button
              type="button"
              className="btn btn-primary"
              disabled={dirtyCount === 0 || saving || blocked}
              onClick={() => void save()}
            >
              {saving ? t('common.saving') : t('flow.save')}
            </button>
          </>
        }
      />
      <div className="toolbar">
        <div className="field field-inline">
          <label htmlFor="flow-scope">{t('flow.scope')}</label>
          <select
            id="flow-scope"
            value={projectId ?? ''}
            onChange={(e) => {
              setProjectId(e.target.value || null);
              setSim(null);
            }}
          >
            <option value="">{t('flow.scopeOrg')}</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {t('flow.scopeProject', { name: p.name })}
              </option>
            ))}
          </select>
        </div>
        <div className="field field-inline">
          <label htmlFor="flow-dir">{t('flow.layout')}</label>
          <select id="flow-dir" value={dir} onChange={(e) => setDir(e.target.value as Direction)}>
            <option value="LR">{t('flow.layoutLR')}</option>
            <option value="TB">{t('flow.layoutTB')}</option>
          </select>
        </div>
        <button type="button" className="btn" onClick={onAddRule} disabled={!writable}>
          + {t('flow.addRule')}
        </button>
        <button type="button" className="btn" onClick={() => setNewPolicy({ name: '', project: projectId ?? '' })} disabled={!writable}>
          + {t('flow.addPolicy')}
        </button>
      </div>
      {!writable ? (
        <div className="banner banner-info" role="note" data-testid="policies-readonly">
          {t('flow.readOnly')}
        </div>
      ) : null}
      {upstreamError ? <div className="banner banner-warn">{t('common.notAvailable', { error: upstreamError })}</div> : null}
      {saveErrors.map((e) => (
        <ErrorBanner key={e} error={e} onDismiss={() => setSaveErrors((s) => s.filter((x) => x !== e))} />
      ))}
      {dangling.map((r) => (
        <div key={r.key} className="banner banner-warn">
          {t('flow.danglingRoute', { name: r.name })}
        </div>
      ))}

      <div className="flow-layout">
        <div className="flow-main">
          <div className="diagram" role="region" aria-label={t('flow.diagram')} data-testid="diagram" ref={paneRef}>
            <DirectionContext.Provider value={dir}>
              <ReactFlow
                nodes={nodes}
                edges={laid.edges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onNodeDragStop={onNodeDragStop}
                onConnect={onConnect}
                isValidConnection={isValidConnection}
                onNodeClick={(_e, n) => openNode(n.id)}
                colorMode={theme}
                panOnScroll
                zoomOnScroll={false}
                minZoom={0.2}
                maxZoom={1.75}
                nodesConnectable
                elementsSelectable
                deleteKeyCode={null}
                proOptions={{ hideAttribution: false }}
              >
                <Background gap={20} size={1} />
                <Controls showInteractive={false} />
                <MiniMap pannable zoomable className="minimap" />
              </ReactFlow>
            </DirectionContext.Provider>
          </div>
          <FlowLegend />

          <div className="below-grid">
            <section className="card" aria-labelledby="rule-list-title">
              <h2 id="rule-list-title">{t('flow.ruleList')}</h2>
              {chainRules.length === 0 ? <p className="muted">{t('flow.noPolicies')}</p> : null}
              <ol className="rule-list" data-testid="rule-list">
                {chainRules.map(({ p, r, i }, n) => (
                  <li key={r.key} className={selected === r.key ? 'is-selected' : ''}>
                    <span className="rule-pos">{n + 1}</span>
                    <button type="button" className="btn btn-link rule-name" aria-label={t('flow.editRule', { name: r.name })} onClick={() => selectRule(r.key)}>
                      {r.name || t('flow.unnamedRule')}
                    </button>
                    <span className={`action action-${r.action}`}>
                      {r.action}
                      {r.action === 'route' ? <span className="action-target">{` → ${r.route_target ?? '?'}`}</span> : null}
                    </span>
                    <span className="muted small">{p.name}</span>
                    <span className="rule-move">
                      <button
                        type="button"
                        className="btn-icon"
                        aria-label={t('flow.moveUp', { name: r.name })}
                        disabled={i === 0}
                        onClick={() => edit((ps) => moveRule(ps, p.key, i, i - 1))}
                      >
                        ↑
                      </button>
                      <button
                        type="button"
                        className="btn-icon"
                        aria-label={t('flow.moveDown', { name: r.name })}
                        disabled={i === p.rules.length - 1}
                        onClick={() => edit((ps) => moveRule(ps, p.key, i, i + 1))}
                      >
                        ↓
                      </button>
                    </span>
                  </li>
                ))}
              </ol>
            </section>
            <section className="card" aria-labelledby="policies-title">
              <h2 id="policies-title">{t('flow.policies')}</h2>
              <p className="muted small">{t('flow.policyOrder')}</p>
              <ul className="policy-list">
                {scopePolicies.map((p) => (
                  <li key={p.key} className={p.key === activePolicy ? 'is-selected' : ''}>
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={p.enabled}
                        onChange={(e) => edit((ps) => ps.map((x) => (x.key === p.key ? { ...x, enabled: e.target.checked, dirty: true } : x)))}
                      />
                      <span>{p.name}</span>
                    </label>
                    <span className="badge">{p.project_id ? (projects.find((x) => x.id === p.project_id)?.name ?? p.project_id) : t('common.orgWide')}</span>
                    <span className="muted small">{t('policy.rules', { count: p.rules.length })}</span>
                    <label className="check small" title={t('policy.logOnlyHelp')}>
                      <input
                        type="checkbox"
                        checked={p.log_only}
                        disabled={!writable}
                        aria-label={`${t('policy.logOnly')} ${p.name}`}
                        onChange={(e) => edit((ps) => ps.map((x) => (x.key === p.key ? { ...x, log_only: e.target.checked, dirty: true } : x)))}
                      />
                      <span>{t('policy.logOnly')}</span>
                    </label>
                    {p.log_only ? <span className="badge badge-warn">{t('policy.logOnlyBadge')}</span> : null}
                    {p.dirty ? <span className="badge badge-warn">•</span> : null}
                    <span className="spacer" />
                    {p.id ? (
                      <a className="btn btn-small" href={`${href('policy-history')}?policy=${encodeURIComponent(p.id)}`} onClick={onLink('policy-history', { policy: p.id })}>
                        {t('policy.history')}
                      </a>
                    ) : null}
                    <button type="button" className="btn btn-small" aria-pressed={p.key === activePolicy} disabled={!writable} onClick={() => setActivePolicy(p.key)}>
                      + {t('flow.addRule')}
                    </button>
                    <button
                      type="button"
                      className="btn-icon"
                      aria-label={`${t('policy.rename')} ${p.name}`}
                      onClick={() => setNewPolicy({ key: p.key, name: p.name, project: p.project_id ?? '' })}
                    >
                      ✎
                    </button>
                    <button type="button" className="btn-icon" aria-label={`${t('policy.delete')} ${p.name}`} onClick={() => setDeleting(p)}>
                      🗑
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </div>

        <aside className="flow-side">
          {sel ? (
            <RulePanel
              key={sel.rule.key}
              rule={sel.rule}
              policyName={sel.policy.name}
              schema={schema}
              upstreamNames={upstreamNames}
              index={sel.index}
              count={sel.policy.rules.length}
              onChange={(patch: Partial<EditableRule>) => edit((ps) => updateRule(ps, sel.rule.key, patch))}
              onDelete={() => {
                edit((ps) => deleteRule(ps, sel.rule.key));
                setSelected(null);
              }}
              onMove={(d) => edit((ps) => moveRule(ps, sel.policy.key, sel.index, sel.index + d))}
              onClose={() => setSelected(null)}
              onTextState={setTextState}
              readOnly={!writable}
              injectionThreshold={injectionThreshold}
            />
          ) : nodePanel ? (
            <NodePanel
              key={nodePanel}
              nodeId={nodePanel}
              guard={guardDraft}
              savedGuard={guard}
              guardError={guardError}
              guardWritable={guardWritable}
              onGuardChange={setGuardDraft}
              onGuardInvalid={onGuardInvalid}
              models={models}
              upstreams={upstreams ?? []}
              defaultUpstream={defaultUpstream}
              scopeLabel={scopeLabel}
              rules={chainRules.map(({ r }) => r)}
              onSelectRule={selectRule}
              onClose={() => setNodePanel(null)}
            />
          ) : null}
          {chainRules.length === 0 ? (
            <section className="rule-panel templates" aria-labelledby="tpl-title" data-testid="templates">
              <h2 id="tpl-title">{t('tpl.title')}</h2>
              {writable ? (
                <>
                  <p className="muted small">{t('tpl.intro')}</p>
                  <ul className="template-list">
                    {templates.map((tpl) => (
                      <li key={tpl.id}>
                        <div>
                          <strong>{t(tpl.name, { target: tpl.target ?? '' })}</strong>
                          <div className="small muted">{t(tpl.desc)}</div>
                        </div>
                        <button
                          type="button"
                          className="btn btn-small"
                          aria-label={`${t('tpl.add')}: ${t(tpl.name, { target: tpl.target ?? '' })}`}
                          onClick={() => onTemplate(tpl)}
                        >
                          + {t('tpl.add')}
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="muted small">{t('tpl.readOnly')}</p>
              )}
            </section>
          ) : null}
          <Simulator orgId={org.id} schema={schema} makeRequest={makeSimRequest} result={sim} onResult={setSim} />
        </aside>
      </div>

      <Dialog
        open={newPolicy !== null}
        title={newPolicy?.key ? t('policy.rename') : t('policy.new')}
        onClose={() => setNewPolicy(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setNewPolicy(null)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!newPolicy?.name.trim() || nameTaken}
              onClick={() => {
                if (!newPolicy) return;
                const name = newPolicy.name.trim();
                const key = newPolicy.key;
                if (key) {
                  edit((ps) => ps.map((x) => (x.key === key ? { ...x, name, dirty: true } : x)));
                } else {
                  const draft: EditablePolicy = {
                    id: undefined,
                    key: newKey('policy'),
                    name,
                    description: null,
                    project_id: newPolicy.project || null,
                    enabled: true,
                    log_only: false,
                    created_at: '',
                    rules: [],
                    dirty: true,
                  };
                  edit((ps) => [...ps, draft]);
                  setActivePolicy(draft.key);
                }
                setNewPolicy(null);
              }}
            >
              {newPolicy?.key ? t('common.save') : t('common.create')}
            </button>
          </>
        }
      >
        <Field label={t('policy.name')} error={nameTaken ? t('policy.nameTaken') : undefined} help={t('policy.nameHelp')}>
          {(p) => <input {...p} value={newPolicy?.name ?? ''} onChange={(e) => newPolicy && setNewPolicy({ ...newPolicy, name: e.target.value })} />}
        </Field>
        {newPolicy?.key ? null : (
          <Field label={t('policy.project')}>
            {(p) => (
              <select {...p} value={newPolicy?.project ?? ''} onChange={(e) => newPolicy && setNewPolicy({ ...newPolicy, project: e.target.value })}>
                <option value="">{t('common.orgWide')}</option>
                {projects.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
              </select>
            )}
          </Field>
        )}
      </Dialog>

      <ConfirmDialog
        open={leaving !== null}
        title={t('flow.leaveTitle')}
        body={t('flow.leaveBody')}
        confirmLabel={t('flow.leave')}
        danger
        onClose={() => setLeaving(null)}
        onConfirm={() => {
          const proceed = leaving;
          setLeaving(null);
          setNavigationGuard(null);
          proceed?.();
        }}
      />

      <ConfirmDialog
        open={deleting !== null}
        title={t('policy.delete')}
        body={t('common.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          const p = deleting;
          if (!p) return;
          try {
            if (p.id) await api.deletePolicy(org.id, p.id);
            setPolicies((ps) => (ps ? ps.filter((x) => x.key !== p.key) : ps));
            setOriginal((ps) => (ps ? ps.filter((x) => x.key !== p.key) : ps));
            if (sel?.policy.key === p.key) setSelected(null);
            notify(t('common.deleted'));
          } catch (e) {
            notify(errorText(e), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}

const LEGEND_NODES: { kind: NodeKind; label: MessageKey }[] = [
  { kind: 'request', label: 'flow.request' },
  { kind: 'key', label: 'flow.apiKey' },
  { kind: 'sanitizer', label: 'flow.l0' },
  { kind: 'detectors', label: 'flow.detectors' },
  { kind: 'rule', label: 'flow.ruleNode' },
  { kind: 'block', label: 'flow.block' },
  { kind: 'log', label: 'flow.log' },
  { kind: 'allow', label: 'flow.allow' },
  { kind: 'upstream', label: 'nav.providers' },
  { kind: 'envUpstream', label: 'flow.envUpstream' },
  { kind: 'output', label: 'flow.output' },
  { kind: 'client', label: 'flow.client' },
];

const EDGE_LABEL: Record<EdgeKindHelp, MessageKey> = {
  match: 'flow.match',
  noMatch: 'flow.noMatch',
  matchContinue: 'flow.matchContinue',
  default: 'flow.default',
};

/** What each kind of step and edge means, with a help tip each. */
function FlowLegend() {
  const { t } = useApp();
  return (
    <div className="flow-legend" data-testid="flow-legend">
      <p className="muted small">{t('flow.legend')}</p>
      <div className="legend-row">
        <span className="legend-head">{t('flow.legendSteps')}</span>
        {LEGEND_NODES.map((n) => (
          <span key={n.kind} className="legend-item">
            {t(n.label)}
            <NodeTip kind={n.kind} name={t(n.label)} />
          </span>
        ))}
      </div>
      <div className="legend-row">
        <span className="legend-head">{t('flow.legendEdges')}</span>
        {EDGE_KINDS.map((k) => (
          <span key={k} className={`legend-item legend-edge legend-edge-${k}`}>
            {t(EDGE_LABEL[k])}
            <EdgeTip kind={k} name={t(EDGE_LABEL[k])} />
          </span>
        ))}
      </div>
    </div>
  );
}
