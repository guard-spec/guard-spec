<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SIEM export

> Tiếng Việt: [siem.vi.md](siem.vi.md).

Guard Spec sends an organization's events to your SIEM as
[OCSF 1.9.0](https://schema.ocsf.io/1.9.0/) records: prompt-injection
detections, failed logins, role and 2FA changes, policy and upstream changes
and every other admin action. A record holds metadata only (ids, categories,
scores, decisions, hashed addresses), never a prompt, an answer or a secret.

| Destination | How | Secret |
|---|---|---|
| Splunk | HTTP Event Collector (`/services/collector/event`) | HEC token |
| Elasticsearch / OpenSearch | `_bulk`, one `create` per record, `_id` = the record's `metadata.uid` | API key (`base64(id:key)`) |
| Microsoft Sentinel | Azure Monitor Logs Ingestion API (data collection rule) | Entra ID client secret |
| Syslog over TLS | RFC 5424 messages, octet-counting framing (RFC 6587), TLS (RFC 5425); CEF or OCSF JSON | none (TLS) |
| HTTP | `POST` of a JSON array of records | optional bearer token |

## Setting up

1. The operator puts the secret in a `SIEM_*` variable of the control plane
   (or a file / Vault reference, [secrets](security/README.md#where-secrets-come-from))
   and grants it to the organization in `ALERTS_SECRET_ORGS`:
   `SIEM_SPLUNK_TOKEN=siem:<org-id>` (or `siem:*`). A SIEM on a private network
   also needs the organization in `ALERTS_PRIVATE_ORGS`.
2. An admin adds a sink in **Alerts → SIEM export**: the destination, its
   settings, the variable name, optionally the event types (`detection.`,
   `security.login_failed`, ...) and the lowest severity. **Send test** sends one
   `alert.test` record.
3. The sink starts with the events that happen after it was added.

API: `GET|POST /v1/organizations/{org}/siem-sinks`,
`PUT|DELETE .../siem-sinks/{id}`, `POST .../siem-sinks/{id}/test` (admin).

## Delivery

- The control plane checks the sinks every `SIEM_EXPORT_INTERVAL` (default
  `5s`) and sends up to 200 events a sink at a time, about 10 seconds after
  they happen (an event batch that commits late is not skipped).
- **At least once.** A batch that fails is sent again; the SIEM can drop
  duplicates on `metadata.uid` (Elasticsearch does: it is the document id).
- A failing sink waits 10 s, doubling up to 30 minutes, then catches up from
  where it stopped. The page shows the error and the count. Events are kept 30
  days; a sink down longer loses the oldest.
- Several control plane replicas share the work: a sink is leased to one of
  them at a time.
- URLs are checked like alert webhooks: https only, no link-local or metadata
  addresses, no private ones without `ALERTS_PRIVATE_ORGS` and `allow_private`.

## Records

| Event | OCSF class | Notes |
|---|---|---|
| `detection.blocked`, `detection.flagged` | Detection Finding (2004) | `disposition` Blocked, Allowed or Corrected (redacted); `finding_info.types` the categories, `analytic.name` the layer, `confidence_score` the score × 100, `related_events[0].uid` the request id |
| `security.login_failed` | Authentication (3002), Logon, Failure | `user.uid_alt` is the hash of the address, `src_endpoint.ip` |
| `security.mfa_locked` | Account Change (3001), Lock | |
| `security.role_changed`, `security.owner_added` | Account Change (3001), Attach Policy | |
| `upstream.error` | API Activity (6003), Failure | `status_code`, `status_detail` |
| `config.*`, `security.sso_changed`, `activity.*`, `alert.test` | API Activity (6003) | Create, Read, Update, Delete or Other |

Every record has `metadata.product.name` "Guard Spec", `metadata.tenant_uid`
(the organization), `metadata.event_code` (the Guard Spec event type) and
`unmapped` with the event's own attributes. `severity_id`: info 1, warning 3,
critical 5.

### Splunk

```
index=security sourcetype="ocsf:guard-spec" class_uid=2004 disposition=Blocked
| stats count by finding_info.analytic.name, unmapped.model
```

### Elasticsearch / Kibana

Index `guard-spec-ocsf` by default; `@timestamp` is the event time.
`class_uid : 2004 and disposition : "Blocked"`.

### Microsoft Sentinel

Create a data collection endpoint, a custom table `GuardSpecOCSF_CL` with
`TimeGenerated` (datetime), `ClassUid` (int), `SeverityId` (int), `EventType`
(string) and `Event` (dynamic), a data collection rule with the stream
`Custom-GuardSpecOCSF_CL` writing to it, and an Entra ID app with the role
*Monitoring Metrics Publisher* on the rule. The sink takes the endpoint, the
rule's immutable id, the stream, the tenant and client ids, and the client
secret variable. `authority` changes the Entra ID host for sovereign clouds.

```kusto
GuardSpecOCSF_CL
| where ClassUid == 2004 and tostring(Event.disposition) == "Blocked"
| summarize count() by tostring(Event.finding_info.analytic.name), bin(TimeGenerated, 1h)
```

### Syslog

`address` is `host:port` of a TLS receiver (rsyslog `imtcp` with TLS,
syslog-ng `network(transport("tls"))`, a SIEM collector). `format` is `cef`
(default: `CEF:0|Guard Spec|Guard Spec|<version>|<event type>|<title>|<severity>|...`)
or `json` (the OCSF record). `ca_pem` holds the CA certificate when it is not
a public one. Facility local0; severity from the event.

## Checked

The records are checked against the required attributes and values of the
official OCSF 1.9.0 classes and objects
(`internal/siem/testdata/ocsf-1.9.0-required.json`). Delivery is tested
against fake Splunk HEC, Elasticsearch, Logs Ingestion API and TLS syslog
servers, and against Elasticsearch 8.17 (`SIEM_LIVE_ELASTIC_URL`, test
`TestLiveElasticsearch`).
