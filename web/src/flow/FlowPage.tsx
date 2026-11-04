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
import { navigate } from '../router';
import type { GuardSettings, PolicySchema, SimulateRequest, SimulateResponse, SimValue } from '../types';
import { addRule, connectRule, danglingRoutes, deleteRule, findRule, moveRule, moveRuleByPosition, updateRule } from './edit';
import { applyHighlight, buildGraph, simulationPath, type DefaultUpstream, type FlowEdge, type FlowNode } from './graph';
import { NODE } from './ids';
import { bounds, initialViewport, layoutGraph, mainAxis, type Direction } from './layout';
import { gatewayChain, gatewayOrder, makeRule, newKey, toEditable, toWireRules, type EditablePolicy, type EditableRule } from './model';
import { DirectionContext, nodeTypes } from './nodes';
import { RulePanel } from './RulePanel';
import { FALLBACK_SCHEMA, fieldTypesOf } from './schema';
import { Simulator } from './Simulator';

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

/** Pulls `rule "name"` out of a server validation error. */
export function ruleNameInError(message: string): string | undefined {
  return /rule "((?:[^"\\]|\\.)*)"/.exec(message)?.[1];
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
  const { org, projects, upstreams, upstreamError } = useOrg();
  const [original, setOriginal] = useState<EditablePolicy[] | null>(null);
  const [policies, setPolicies] = useState<EditablePolicy[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [schema, setSchema] = useState<PolicySchema>(FALLBACK_SCHEMA);
  const [guard, setGuard] = useState<GuardSettings | null>(null);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [dir, setDir] = useState<Direction>('TB');
  const [selected, setSelected] = useState<string | null>(null);
  const [sim, setSim] = useState<SimulateResponse | null>(null);
  const [ruleErrors, setRuleErrors] = useState<Record<string, string>>({});
  const [saveErrors, setSaveErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [activePolicy, setActivePolicy] = useState<string | null>(null);
  const [newPolicy, setNewPolicy] = useState<{ name: string; project: string } | null>(null);
  const [deleting, setDeleting] = useState<EditablePolicy | null>(null);
  const { setViewport } = useReactFlow();
  const paneRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const ps = (await api.listPolicies(org.id)).map(toEditable);
      setPolicies(ps);
      setOriginal(ps);
      setLoadError(null);
    } catch (e) {
      setLoadError(errorText(e));
    }
    api.getPolicySchema().then(setSchema, () => setSchema(FALLBACK_SCHEMA));
    api.getGuardSettings(org.id).then(setGuard, () => setGuard(null));
  }, [api, org.id]);

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
  const dirtyCount = (policies ?? []).filter((p) => p.dirty).length;

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
        guard,
        scopeLabel,
        fieldTypes,
        ruleErrors,
        t: t as (k: string, p?: Record<string, string | number>) => string,
      }),
    [chain, upstreams, defaultUpstream, guard, scopeLabel, fieldTypes, ruleErrors, t],
  );
  const laid = useMemo(() => {
    const nodes = layoutGraph(graph.nodes, graph.edges, dir);
    const path = sim ? simulationPath(graph, sim) : null;
    const hl = applyHighlight({ nodes, edges: graph.edges }, path);
    return {
      nodes: hl.nodes.map((n) => ({
        ...n,
        draggable: n.type === 'rule',
        selectable: n.type === 'rule',
        selected: selected !== null && n.id === NODE.rule(selected),
        ariaLabel: n.data.kind === 'rule' ? `${n.data.name}: ${n.data.action}, ${n.data.text}` : n.data.title,
      })),
      edges: styleEdges(hl.edges),
    };
  }, [graph, dir, sim, selected]);

  // The laid-out nodes, with the position of a node being dragged.
  const [drag, setDrag] = useState<{ id: string; position: XYPosition } | null>(null);
  const nodes = useMemo(
    () => (drag ? laid.nodes.map((n) => (n.id === drag.id ? { ...n, position: drag.position } : n)) : laid.nodes),
    [laid.nodes, drag],
  );

  // A readable start: fit the width (zoom 0.6 to 1), top aligned. The fit
  // view control shows the whole diagram.
  const loaded = policies !== null;
  const box = bounds(laid.nodes);
  const boxKey = `${Math.round(box.width)}x${Math.round(box.height)}`;
  useEffect(() => {
    const pane = paneRef.current;
    if (!pane || !loaded) return;
    const b = bounds(laid.nodes);
    void setViewport(initialViewport(b, { width: pane.clientWidth, height: pane.clientHeight }));
    // Only on a new scope, direction or shape, not on every edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir, projectId, loaded, boxKey, setViewport]);

  const edit = (f: (ps: EditablePolicy[]) => EditablePolicy[]) => {
    setPolicies((ps) => (ps ? f(ps) : ps));
    setSim(null);
  };

  // Only drags change node state; selection and layout come from the model.
  const onNodesChange = useCallback((changes: NodeChange<FlowNode>[]) => {
    for (const c of changes) {
      if (c.type === 'position' && c.position) setDrag({ id: c.id, position: c.position });
    }
  }, []);

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
    setSelected(key);
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
    setSelected(rule.key);
  };

  const save = async () => {
    if (!policies) return;
    setSaving(true);
    const errors: string[] = [];
    const ruleErrs: Record<string, string> = {};
    const failed = new Set<string>();
    for (const p of policies.filter((x) => x.dirty)) {
      try {
        const rules = toWireRules(p.rules);
        if (p.id) {
          await api.updatePolicy(org.id, p.id, { name: p.name, rules, enabled: p.enabled });
        } else {
          const created = await api.createPolicy(org.id, { name: p.name, rules, project_id: p.project_id });
          if (!p.enabled) await api.updatePolicy(org.id, created.id, { enabled: false });
        }
      } catch (e) {
        failed.add(p.key);
        const msg = errorText(e);
        errors.push(t('flow.saveFailed', { name: p.name, error: msg }));
        const bad = ruleNameInError(msg);
        for (const r of p.rules) if (bad !== undefined && r.name === bad) ruleErrs[r.key] = msg;
      }
    }
    setSaveErrors(errors);
    setRuleErrors(ruleErrs);
    try {
      const fresh = (await api.listPolicies(org.id)).map(toEditable);
      const keep = policies.filter((p) => failed.has(p.key));
      const merged = [...fresh.map((f) => keep.find((k) => k.id === f.id) ?? f), ...keep.filter((k) => !k.id)];
      setOriginal(fresh);
      setPolicies(merged);
      if (errors.length === 0) {
        notify(t('flow.savedOk'));
        // Saved rules got server ids: keep the selection on the same rule if it still exists.
        setSelected((s) => (s && findRule(merged, s) ? s : null));
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

  if (loadError) return <ErrorBanner error={loadError} />;
  if (!policies) return <Loading />;

  const sel = selected ? findRule(policies, selected) : undefined;
  const chainRules = chain.flatMap((p) => p.rules.map((r, i) => ({ p, r, i })));
  const dangling = danglingRoutes(chain, upstreamNames);

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
                setRuleErrors({});
                setSaveErrors([]);
              }}>
              {t('flow.discard')}
            </button>
            <button type="button" className="btn btn-primary" disabled={dirtyCount === 0 || saving} onClick={() => void save()}>
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
        <button type="button" className="btn" onClick={onAddRule}>
          + {t('flow.addRule')}
        </button>
        <button type="button" className="btn" onClick={() => setNewPolicy({ name: '', project: projectId ?? '' })}>
          + {t('flow.addPolicy')}
        </button>
      </div>
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
                onNodeClick={(_e, n) => {
                  const key = NODE.ruleKey(n.id);
                  if (key) setSelected(key);
                  else if (n.id === NODE.l0 || n.id === NODE.detectors) navigate('guard');
                }}
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
          <p className="muted small">{t('flow.legend')}</p>

          <div className="below-grid">
            <section className="card" aria-labelledby="rule-list-title">
              <h2 id="rule-list-title">{t('flow.ruleList')}</h2>
              {chainRules.length === 0 ? <p className="muted">{t('flow.noPolicies')}</p> : null}
              <ol className="rule-list" data-testid="rule-list">
                {chainRules.map(({ p, r, i }, n) => (
                  <li key={r.key} className={selected === r.key ? 'is-selected' : ''}>
                    <span className="rule-pos">{n + 1}</span>
                    <button type="button" className="btn btn-link rule-name" aria-label={t('flow.editRule', { name: r.name })} onClick={() => setSelected(r.key)}>
                      {r.name || t('flow.unnamedRule')}
                    </button>
                    <span className={`action action-${r.action}`}>
                      {r.action}
                      {r.action === 'route' ? ` → ${r.route_target ?? '?'}` : ''}
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
                    {p.dirty ? <span className="badge badge-warn">•</span> : null}
                    <span className="spacer" />
                    <button type="button" className="btn btn-small" aria-pressed={p.key === activePolicy} onClick={() => setActivePolicy(p.key)}>
                      + {t('flow.addRule')}
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
            />
          ) : null}
          <Simulator orgId={org.id} schema={schema} makeRequest={makeSimRequest} result={sim} onResult={setSim} />
        </aside>
      </div>

      <Dialog
        open={newPolicy !== null}
        title={t('policy.new')}
        onClose={() => setNewPolicy(null)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setNewPolicy(null)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!newPolicy?.name.trim()}
              onClick={() => {
                if (!newPolicy) return;
                const draft: EditablePolicy = {
                  id: undefined,
                  key: newKey('policy'),
                  name: newPolicy.name.trim(),
                  description: null,
                  project_id: newPolicy.project || null,
                  enabled: true,
                  created_at: '',
                  rules: [],
                  dirty: true,
                };
                edit((ps) => [...ps, draft]);
                setActivePolicy(draft.key);
                setNewPolicy(null);
              }}
            >
              {t('common.create')}
            </button>
          </>
        }
      >
        <Field label={t('policy.name')}>
          {(p) => <input {...p} value={newPolicy?.name ?? ''} onChange={(e) => newPolicy && setNewPolicy({ ...newPolicy, name: e.target.value })} />}
        </Field>
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
      </Dialog>

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
