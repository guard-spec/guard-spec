// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Delivery log (contract §5): the notification outbox, filtered by state,
// channel kind and rule, with the (redacted) error of a failed attempt in a
// line under its row.

import { ListChecks } from 'lucide-react';
import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { DataTable, EmptyState, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { PageHeader, RelativeTime, formatTime } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { DeliveryStateBadge, KindLabel, kindLabel, useAlertsApi } from './shared';
import { CHANNEL_KINDS, DELIVERY_STATES, type AlertRule, type Delivery } from './types';

export default function DeliveriesPage() {
  const { t } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const ids = { state: useId(), kind: useId(), rule: useId() };
  const [state, setState] = useState('');
  const [kind, setKind] = useState('');
  const [rule, setRule] = useState('');
  const [rules, setRules] = useState<AlertRule[]>([]);
  useEffect(() => {
    let live = true;
    a.allRules(org.id).then((r) => live && setRules(r), () => undefined);
    return () => {
      live = false;
    };
  }, [a, org.id]);
  const ruleNames = useMemo(() => new Map(rules.map((r) => [r.id, r.name])), [rules]);

  const fetchPage = useCallback(
    (p: { limit: number; cursor?: string }) => a.listDeliveries(org.id, { ...p, state: state || undefined, channel_kind: kind || undefined, rule_id: rule || undefined }),
    [a, org.id, state, kind, rule],
  );
  const filtered = state || kind || rule;
  const paged = usePaged<Delivery>(fetchPage, {
    clientFilter: filtered ? (d) => (!state || d.state === state) && (!kind || d.channel_kind === kind) && (!rule || d.rule_id === rule) : undefined,
  });
  const ruleOf = (d: Delivery) => d.rule_name ?? (d.rule_id ? ruleNames.get(d.rule_id) : undefined) ?? null;

  const columns: Column<Delivery>[] = [
    { key: 'created', header: t('alerts.delivery.created'), className: 'nowrap small', cell: (d) => <RelativeTime value={d.created_at} /> },
    { key: 'state', header: t('alerts.state'), className: 'nowrap', cell: (d) => <DeliveryStateBadge state={d.state} /> },
    {
      key: 'channel',
      header: t('alerts.delivery.channel'),
      className: 'col-target',
      cell: (d) => (
        <div className="cell-stack">
          <span className="nowrap">
            <KindLabel kind={d.channel_kind} />
            {d.channel_name ? <span className="muted small"> · {d.channel_name}</span> : null}
          </span>
          {d.target ? (
            <span className="mono small muted ellipsis" title={d.target}>
              {d.target}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'rule',
      header: t('alerts.rule'),
      className: 'col-rule small',
      cell: (d) => (
        <div className="cell-stack">
          <span className="ellipsis" title={ruleOf(d) ?? undefined}>
            {ruleOf(d) ?? '—'}
          </span>
          <span className="mono muted ellipsis" title={d.alert_id}>
            {d.alert_id.slice(0, 8)}
          </span>
        </div>
      ),
    },
    {
      key: 'attempts',
      header: t('alerts.delivery.attempts'),
      className: 'nowrap small',
      cell: (d) => (
        <div className="cell-stack">
          <span>{d.attempts}</span>
          {d.state === 'pending' || d.state === 'failed' ? (
            d.next_attempt_at ? (
              <span className="muted" title={formatTime(d.next_attempt_at)}>
                {t('alerts.delivery.next')} <RelativeTime value={d.next_attempt_at} />
              </span>
            ) : null
          ) : null}
        </div>
      ),
    },
    { key: 'sent', header: t('alerts.delivery.sent'), className: 'nowrap small col-wide-only', cell: (d) => <RelativeTime value={d.sent_at} /> },
  ];

  return (
    <div>
      <PageHeader title={t('nav.alertDeliveries')} help={t('alerts.deliveries.help')} />
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(d) => d.id}
        rowClassName={(d) => (d.state === 'dead' ? 'row-dead' : '')}
        testId="deliveries-table"
        feature={t('nav.alertDeliveries')}
        rowDetail={(d) =>
          d.last_error ? (
            <div className="delivery-error small" data-testid="delivery-error">
              <strong>{t('alerts.delivery.error')}:</strong> <span className="mono">{d.last_error}</span>
            </div>
          ) : null
        }
        toolbar={
          <>
            <div className="field field-inline">
              <label htmlFor={ids.state}>{t('alerts.state')}</label>
              <select id={ids.state} value={state} onChange={(e) => setState(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {DELIVERY_STATES.map((s) => (
                  <option key={s} value={s}>
                    {t(`alerts.dstate.${s}` as MessageKey)}
                  </option>
                ))}
              </select>
            </div>
            <div className="field field-inline">
              <label htmlFor={ids.kind}>{t('alerts.delivery.channel')}</label>
              <select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {[...CHANNEL_KINDS, 'in_app' as const].map((k) => (
                  <option key={k} value={k}>
                    {kindLabel(k, t)}
                  </option>
                ))}
              </select>
            </div>
            <div className="field field-inline">
              <label htmlFor={ids.rule}>{t('alerts.rule')}</label>
              <select id={ids.rule} value={rule} onChange={(e) => setRule(e.target.value)}>
                <option value="">{t('audit.all')}</option>
                {rules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </div>
          </>
        }
        empty={<EmptyState icon={ListChecks} title={filtered ? t('table.noMatch') : t('alerts.deliveries.empty')} />}
      />
    </div>
  );
}
