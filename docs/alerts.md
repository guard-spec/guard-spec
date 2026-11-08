<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Real-time alerts and notifications

Guard Spec turns what the gateway and the control plane see (blocked and
flagged requests, upstream failures, security and configuration changes) into
events, evaluates alert rules over them, and notifies people over Telegram,
Slack, Microsoft Teams, signed webhooks, A2A agents, email and the in-app bell.

Sections 0 to 8 are the contract the backend and the admin UI build against
(RF-35448968). Sections 9 onward cover setup: environment variables, each
channel, webhook verification, metrics and operations. Where the
implementation refines the contract, the text says so and section 13 lists
every difference.

The conventions of the identity work still apply:
- Everything is under `/v1` and uses Bearer JWT.
- Roles are viewer < member < admin < owner.
- Lists return the pagination envelope `{items,next_cursor,total,total_capped}`.
- Secrets live only in env vars, referenced by name (`*_env`).
- RLS is per org.

## 0. Architecture decisions

**Event flow**
- The gateway and the control plane emit events into an in-process bounded
  channel, so the request path never waits. The gateway builds its events
  from the audit entry on the audit goroutine, after the response is sent.
- When the buffer is full, the event is dropped and
  `guardspec_events_dropped_total{source}` is incremented. A batch the
  database refuses is dropped and counted the same way.
- A batch writer (flushing every ≤200 ms or 100 events) inserts the events
  into `events`, one transaction per org with row-level security, and runs
  `NOTIFY guardspec_events, '<org_id>'`.

**Alert worker (runs in the control plane)**
- `LISTEN guardspec_events` (and `guardspec_outbox`), plus a 2 s poll as a
  safety net. The poll asks `alert_work_orgs()` which orgs have unprocessed
  events, deliveries due or firing alerts.
- Evaluates rules, then writes `alerts` and `notification_outbox` rows in one
  transaction.
- The dispatcher claims outbox rows with `FOR UPDATE SKIP LOCKED` and a 60 s
  lease: a row whose replica died returns to the queue.
- Multi-replica safety:
  - each org's rule evaluation runs under `pg_try_advisory_xact_lock(hash(org))`;
  - dedupe uses a unique `(rule_id, dedupe_key, window_start)`, and a partial
    unique index keeps one firing alert per `(rule_id, dedupe_key)`;
  - outbox rows have a unique `idempotency_key`.

**Other decisions**
- No NATS. Postgres LISTEN/NOTIFY is enough at our scale; revisit if events
  exceed about 2k/s.
- Latency target: event to delivery attempt p95 < 5 s, measured in the
  integration test (`TestAlertsLatency`: p95 about 0.2 s on a laptop).
- Payloads never contain prompt or response text.
  - Metadata only: ids, category, score, project, decision, link.
  - Payload samples keep only the known attributes of section 1 (an
    allowlist); anything else an event carries is dropped.
  - An org setting `alerts_include_excerpt` (default false) is out of scope
    for v1 and is not built.

## 1. Event types (`event_type`) and metadata

Every event has:
`{id uuid, org_id, project_id|null, type, severity(info|warning|critical), occurred_at, attrs{...}}`

| type | source | severity | attrs |
|---|---|---|---|
| `detection.blocked` | gateway | warning | request_id, categories[], score, layer, decision, api_key_id, model (+ policy_id when a policy rule matched, signal when the conversation window scored highest, pii_kinds[] and pii_count when the request held personal data) |
| `detection.flagged` | gateway | info | same as above (score ≥ flag threshold, not blocked); warning with `decision: redact` and `redacted` (count) when untrusted content was replaced (`INDIRECT_ACTION=redact`) |
| `upstream.error` | gateway | warning | upstream_id, status, error_kind (timeout\|5xx\|model_not_allowed\|connect), request_id |
| `security.login_failed` | cp | warning | user_id\|null, email_hash, ip, reason |
| `security.mfa_locked` | cp | critical | user_id |
| `security.role_changed` | cp | warning | actor_id, user_id, from, to |
| `security.owner_added` | cp | critical | actor_id, user_id |
| `security.sso_changed` | cp | warning | actor_id, provider_id, action |
| `config.policy_changed` | cp | info | actor_id, policy_id, action |
| `config.upstream_changed` | cp | info | actor_id, upstream_id, action |
| `alert.test` | cp | rule's | actor_id, rule_id (from "Send test") |
| `activity.<action>` | cp | info | actor_id, action (any other activity log action of an org) |

Notes:
- `layer` is `l1`, `l2` or `l3` (the model layer with the highest score),
  `sanitizer` (hidden characters, anomaly score), `indirect` (tool results,
  documents, tool descriptions), `policy` or `scan` (`/guardrail/scan*`).
- `signal` is `conversation` when the conversation window (the most recent
  user turns joined) scored higher than the per-turn text; absent otherwise.
  `layer` is then the layer that scored highest on the window.
- `pii_kinds` and `pii_count` are set when the org turned on personal data
  in requests (`input_pii`) and the request text held some: the kinds
  (`email`, `phone`, `card`, `cccd`, `ipv4`) and how many values, as the
  policy fields `input.pii.kinds` and `input.pii.count`. Never the values.
- `api_key_id` is the shown key prefix (`gs_` and 8 characters), never the key.
- `email_hash` is the first 16 bytes of SHA-256 of the lower-cased address, hex.
- `detection.flagged` fires for allowed requests whose injection score is at
  least `ALERTS_FLAG_THRESHOLD` (default 0.5); a request is blocked at 0.85.
- A request refused for another reason (invalid body, rate limit) emits no
  detection event.
- Retried refusals send one event. A client that resends a refused request
  (Claude Code does, six times) gets the same refusal each time; within the
  gateway's `AUDIT_DEDUPE_WINDOW` (default 10 s) a refusal that matches an
  earlier one (org, API key, layer, label, policy rule, the text that
  triggered it) is counted in the first audit row's `repeat_count` and sends
  no `detection.blocked` event of its own. Events are not updated afterwards,
  so the event does not carry the count; read it from the audit row
  (`request_id`). A rule that counts `detection.blocked` events therefore
  counts refused attempts, not retries. Set `AUDIT_DEDUPE_WINDOW=0` for one
  event per request.

Control-plane events reuse the activity-log hook: every activity write also
emits an event. Instance-level rows (logins, 2FA locks, SSO providers) go to
every org the user (or the acting administrator) belongs to; a failed login
for an unknown email belongs to no org and emits nothing.

## 2. Rules

`alert_rules` columns:
- `id, org_id, name, enabled, event_types text[]`
- `condition text` (policy-text syntax, compiled to CEL over
  `{type, severity, project_id, attrs}`; empty means always)
- `threshold int ≥1` (default 1), `window_seconds` (60..86400, default 300)
- `severity` (the alert severity sent)
- `throttle_seconds` (default 900): at most 1 notification per rule × dedupe
  key per throttle window, across firing episodes
- `group_by text[]` (subset of `project_id`, `attrs.category`,
  `attrs.upstream_id`; this is the dedupe key)
- `quiet_hours {tz, start "22:00", end "07:00", mode: "suppress"|"delay", critical_bypass bool}|null`
- `auto_resolve bool`: when the count in the window drops below threshold,
  send one `resolved` notification
- `recipients {user_ids[], group_ids[], roles[]}` and `channel_ids[]` (shared
  org channels such as a Slack channel webhook)
- `created_by, created_at, updated_at`

Condition fields: `type`, `severity`, `project_id` and `attrs.request_id`,
`attrs.categories` (list), `attrs.category` (the first category when the
event has a list), `attrs.score`, `attrs.layer`, `attrs.decision`,
`attrs.api_key_id`, `attrs.model`, `attrs.upstream_id`, `attrs.status`
(number), `attrs.error_kind`, `attrs.user_id`, `attrs.email_hash`, `attrs.ip`,
`attrs.reason`, `attrs.actor_id`, `attrs.from`, `attrs.to`,
`attrs.provider_id`, `attrs.policy_id`, `attrs.action`, `attrs.pii_kinds`
(list), `attrs.pii_count` (number). An attribute an event lacks reads as
`""`, `0` or `[]`. Examples:

```
attrs.score >= 0.95 && "jailbreak" in attrs.categories
project_id == "1f0c…" && attrs.layer in ["l2", "l3"]
attrs.error_kind == "timeout" || attrs.status >= 500
```

Alert states are `firing` and `resolved`. The `alerts` table stores:
`id, org_id, rule_id, dedupe_key, state, severity, first_at, last_at, count, resolved_at, sample_event_ids uuid[≤10]`
(and `rule_name, group_values, project_id, window_start, suppressed, test`).

How a rule fires: each new event matching the rule's types and condition is
recorded as a hit under its dedupe key; when the hits in the last
`window_seconds` reach `threshold`, the firing alert of that key is created
(or updated), and a notification goes out unless the throttle holds it back.
A firing alert whose window count falls below the threshold is resolved;
rules with `auto_resolve` send one `resolved` notification, others resolve
quietly. Quiet hours suppress or delay notifications; `critical_bypass` lets
critical alerts through.

## 3. Recipients and personal preferences

- `user_groups {id, org_id, name, description}` and
  `user_group_members {group_id, user_id}`. Only org members may be added;
  leaving the org removes a user from its groups.
- Resolution: user_ids ∪ members(group_ids) ∪ members with role ∈ roles,
  filtered to current, enabled org members.
  - A removed member never receives anything: resolution happens when the
    alert fires, and queued deliveries of a user who left are dropped.
  - Each user then gets their personal channels whose `min_severity` is at
    or below the alert severity, and that are enabled.
- `user_channel_links {user_id, kind: telegram|slack|email, address (chat_id / slack user id / email), verified_at}`
- `user_notification_prefs {user_id, org_id, channel_kind, enabled, min_severity}`.
  Without a row a kind is on from `info`.
- Email goes to the account address unless an email link overrides it, and
  only when SMTP is configured.
- In-app notifications are always on for recipients and are not switchable in v1.

## 4. Channels

`notification_channels` columns:
`id, org_id, name, kind, config jsonb (non-secret), secret_env text|null, enabled, verified_at, created_at`

| kind | config | secret_env holds |
|---|---|---|
| `telegram` | `{chat_id}` | bot token (`TELEGRAM_BOT_TOKEN_*`). Without it the instance bot, and then `chat_id` is set by `/link` (below), never by the client. |
| `slack` | `{mode: "bot"\|"webhook", channel?}` | bot token or webhook URL (`SLACK_*`) |
| `teams` | `{}` | Workflows webhook URL (Adaptive Card), `TEAMS_*`. No O365 connectors. |
| `webhook` | `{url, allow_private:false}` | HMAC signing secret (`WEBHOOK_SECRET_*`) |
| `a2a` | `{agent_card_url, allow_private:false}` | bearer/API key if the Agent Card demands it (`A2A_*`) |
| `email` | `{to[], lang?: "en"\|"vi"}` (shared mailbox; each address confirms) | — (SMTP comes from global env `SMTP_URL`, `SMTP_FROM`) |

Any logged-in user can create an org and own it, so "an org admin" is
anyone. The rules below hold against that.

Secrets:
- Env var names must match `^[A-Z][A-Z0-9_]{2,63}$`, with a prefix of the
  channel's kind: `TELEGRAM_BOT_TOKEN_`, `SLACK_`, `TEAMS_`,
  `WEBHOOK_SECRET_`, `A2A_`, or `GUARDSPEC_ALERT_` (any kind). Nothing else is
  allowed (this stops reading `DATABASE_URL`), nor the instance tokens
  `TELEGRAM_BOT_TOKEN` and `SLACK_BOT_TOKEN`.
- **Every variable is bound to one kind and to orgs** by the operator in
  `ALERTS_SECRET_ORGS` (`NAME=kind:*` or `NAME=kind:<org-id>,<org-id>`,
  section 9). Unlisted, or named by a channel of another kind or org, a
  variable cannot be used: a Slack token granted as `slack` can never be put
  on an A2A channel aimed at a server its org controls, whatever its prefix.
- The UI shows `secret_set: bool`, never the value.

Verification (`verified: bool` on every channel):
- **Telegram on the instance bot** posts only to a chat that proved it wants
  it. `POST /notification-channels/:id/telegram-link` returns a one-time
  code (hashed, single use, 10 minutes); someone in the chat (a group the
  bot was added to) sends `/link@<bot> <code>`, which sets `config.chat_id`
  and `verified_at`. Until then deliveries and tests fail ("not verified").
  Changing the channel's bot resets the verification. A channel with its own
  `TELEGRAM_BOT_TOKEN_*` names its `chat_id` and is verified (its bot can
  only post where it was added).
- **Email** is double opt-in: each address in `config.to` gets a mail with a
  confirmation link (`GET /v1/integrations/email/confirm?token=…`, single
  use, 7 days); mail goes only to confirmed addresses, listed in
  `addresses [{address, confirmed, confirmed_at, sent_at}]`. A channel is
  verified once an address confirmed. `POST /notification-channels/:id/email-confirmations`
  mails new links to the unconfirmed ones.
- Each org sends at most `ALERTS_EMAIL_DAILY_CAP` emails (default 500) per
  24 hours, confirmation mails included; past it email deliveries are dead
  ("daily email limit").
- Every other kind is verified.

URLs (webhook, A2A) go through the existing SSRF guard (upstreams validation
and dialer):
- https only; no credentials in the URL, and no query parameter that looks
  like one (`token`, `key`, `secret`, `sig`, …): config is readable by viewers;
- `allow_private` (loopback and private addresses, http allowed) only for
  orgs the operator lists in `ALERTS_PRIVATE_ORGS`; for any other org the
  channel is refused (400);
- no redirects; 5 s timeout; response body capped at 64 KiB;
- a dial the address rules refuse reads `address not allowed`, without the
  address, in test results and `last_error`.
The Slack and Teams webhook URLs from `secret_env` and the A2A endpoint
named by an Agent Card pass the same guard.

### Webhook payload v1

```json
{"schema":"guardspec.alert.v1","event_id":"<delivery idempotency key>","alert_id":"…","rule":{"id","name"},
 "state":"firing|resolved","severity":"critical","org_id":"…","project_id":"…|null",
 "count":7,"window_seconds":300,"first_at":"RFC3339","last_at":"RFC3339",
 "group":{"project_id":"…","attrs.category":"jailbreak"},
 "samples":[{"event_id","type","occurred_at","attrs":{…metadata only…}}],
 "links":{"alert":"<PUBLIC_BASE_URL>/ui/alerts/history?id=…","requests":"<PUBLIC_BASE_URL>/ui/requests?…"}}
```

A test notification has `"test": true`.

Headers:
- `X-GuardSpec-Event-Id`: the same idempotency key as `event_id`; a retry
  carries the same value, so receivers drop duplicates by it. It is signed.
- `X-GuardSpec-Timestamp` (unix seconds)
- `X-GuardSpec-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + event_id + "." + body)>`

Receivers reject requests whose timestamp is more than 5 min off. Section 11
has verify snippets for Go, Python and Node.

### A2A

- The client is pinned to **A2A specification v1.0.0** (checked 2026-11-04,
  <https://a2a-protocol.org/latest/specification/>).
- Fetch the Agent Card from `/.well-known/agent-card.json` (of the configured
  URL's origin, or the configured URL when it ends in `.json`) and cache it
  for 10 min.
- POST JSON-RPC to the card's `JSONRPC` interface with:
  - a text part with the summary;
  - a data part holding the webhook payload v1;
  - `messageId` set to the idempotency key;
  - the `A2A-Version` header.
- v1.0 cards (`supportedInterfaces[].protocolVersion` 1.0) get method
  `SendMessage`, role `ROLE_USER` and parts `{"text"}` / `{"data","mediaType"}`.
  Cards that declare protocol 0.3 get the 0.3 form the contract named:
  method `message/send`, role `user`, parts with `kind: text|data`.
- The JSON-RPC endpoint must have the same origin (scheme, host, port) as
  the Agent Card; a card naming another origin is refused, so the secret never
  leaves the origin the org configured.
- Auth follows the card's security scheme (HTTP bearer, or an apiKey in a
  header) using `secret_env`. A card that names a reserved or hop-by-hop
  header (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  `Cookie`, `Proxy-*`, `X-Forwarded-*`, …) or an invalid name is refused.
- Success means a JSON-RPC result (Task or Message). The returned task id is
  recorded as the delivery's `remote_id`. A JSON-RPC error is permanent.

## 5. Delivery

`notification_outbox` columns:
`id, org_id, alert_id, channel_kind, channel_id|null, user_id|null, target (resolved address, not secret), payload jsonb, state(pending|sending|sent|failed|dead), attempts, next_attempt_at, last_error (redacted), idempotency_key unique, created_at, sent_at`
(and `rule_id, last_status, remote_id`).

- Retries: backoff 2 s, 10 s, 60 s, 5 min, 30 min; after 6 attempts the row
  moves to `dead`.
- A 4xx response other than 408/429 is permanent and goes straight to dead,
  as do redirects, a channel that was deleted or disabled, a missing secret,
  and a recipient who left the org.
- 429 honours `Retry-After` (and Telegram's `retry_after`), up to 1 hour.
- `notification_deliveries` is the outbox history view. The UI reads it
  (paginated, filtered by state/channel/rule).
- `last_error` never contains tokens or webhook URLs: secrets are replaced,
  token-shaped strings removed, and every URL is cut to scheme and host.
- `target` of a webhook or A2A channel is its scheme and host only.
- At most 1000 deliveries per org per minute are queued; past that only
  in-app notifications are written (`guardspec_alerts_deliveries_total{result="limited"}`).
- `notifications` (in-app): `id, org_id, user_id, alert_id, title, body, severity, read_at, created_at`.

## 6. API (all under /v1/organizations/:org_id unless noted)

| Method & path | Role | Notes |
|---|---|---|
| GET/POST `/alert-rules`, GET/PATCH/DELETE `/alert-rules/:id` | read: viewer, write: admin | condition validated (400 with parse error and `position`) |
| POST `/alert-rules/:id/test` | admin | emits a synthetic `alert.test` that goes through the full pipeline; returns `{alert_id}` |
| GET/POST `/notification-channels`, GET/PATCH/DELETE `/:id` | read: viewer, write: admin | returns `secret_set` |
| POST `/notification-channels/:id/test` | admin | synchronous send; `{ok, status, latency_ms, error?}` |
| POST `/notification-channels/:id/telegram-link` | admin | Telegram on the instance bot: `{code, command:"/link@<bot> <code>", bot_username, expires_at}`; single use, 10 min |
| POST `/notification-channels/:id/email-confirmations` | admin | mails new confirmation links to unconfirmed addresses (within the daily cap); returns the channel |
| GET `/v1/integrations/email/confirm?token=` | none (the token) | confirmation link of a shared-mailbox address; plain text answer; single use, 7 days |
| GET/POST `/user-groups`, GET/PATCH/DELETE `/:id`, PUT `/:id/members {user_ids[]}` | read: viewer, write: admin | |
| GET `/alerts?state=&rule_id=` , GET `/alerts/:id` | viewer | history |
| GET `/notification-deliveries?state=&channel_kind=&rule_id=` | admin | delivery log |
| GET/PUT `/me/notification-prefs` | self (any role) | `[{channel_kind, enabled, min_severity}]` |
| GET `/v1/me/channel-links`, DELETE `/v1/me/channel-links/:kind` | self | |
| POST `/v1/me/channel-links/telegram/start` | self | `{code, deep_link:"https://t.me/<bot>?start=<code>", expires_at}`; single use, 10 min |
| POST `/v1/me/channel-links/slack` | self | links by looking up the user's email via `users.lookupByEmail` (instance-level `SLACK_BOT_TOKEN`) |
| PUT `/v1/me/channel-links/email {address}` | self | mails a confirmation code to the address; 202 `{kind, address, verified:false, expires_at}`. One code a minute, 30 minutes, 5 attempts. |
| POST `/v1/me/channel-links/email/confirm {code}` | self | the address replaces the account address; returns the link (`verified:true`); 400 for a wrong, expired or used-up code |
| POST `/v1/integrations/telegram/webhook` | Telegram secret header | handles `/start <code>`; verified with `X-Telegram-Bot-Api-Secret-Token` = env `TELEGRAM_WEBHOOK_SECRET`. A long-polling fallback runs when `TELEGRAM_POLLING=1`. |
| GET `/v1/notifications?unread=1`, POST `/v1/notifications/read {ids[]\|all}` | self | |
| GET `/v1/notifications/stream` | self | SSE (`text/event-stream`, heartbeat every 25 s). Auth by Bearer via fetch-stream (no token in the URL). |

**Instance capabilities:** GET `/v1/alerts/capabilities[?org_id=]` (any user) returns:
`{telegram:{enabled, bot_username}, slack_bot:bool, smtp:bool, email_confirmation:bool, email_daily_cap:int, a2a:true, webhook:true, teams:true, allow_private_urls:bool}`

`allow_private_urls` is true only with an `org_id` the caller belongs to and
the operator listed in `ALERTS_PRIVATE_ORGS`; without `org_id` it is false.
`email_confirmation` is true when SMTP is set (confirmations can be sent).

The UI hides link buttons for capabilities that are disabled.

Every write is recorded in the activity log (`alerts.rule.*`,
`alerts.channel.*`, `alerts.group.*`, `alerts.prefs.updated`; link changes as
`alerts.link.*` in the instance log).

Response details:
- Rules are returned as stored: `{id, name, enabled, event_types, condition,
  threshold, window_seconds, severity, throttle_seconds, group_by,
  quiet_hours, auto_resolve, recipients, channel_ids, created_by, created_at,
  updated_at}`. PATCH takes any subset of the writable fields; unknown fields
  are refused (400). References to users, groups or channels outside the org
  are refused (400); another org's ids return 404.
- Channels: `{id, name, kind, config, secret_env, secret_set, enabled,
  created_at, updated_at}`. `kind` cannot change.
- Groups: `{id, name, description, user_ids, member_ids, member_count,
  created_at, updated_at}` (`member_ids` is the same list as `user_ids`); GET
  `/:id` adds `members [{user_id, email, display_name}]`.
- Alerts: `{id, rule_id, rule_name, dedupe_key, group, project_id, state,
  severity, first_at, last_at, count, resolved_at, sample_event_ids,
  suppressed, test}`; GET `/:id` adds `samples [{event_id, type, severity,
  occurred_at, attrs}]` and `deliveries {state: count}`.
- Deliveries: `{id, alert_id, rule_id, rule_name, channel_kind, channel_id,
  channel_name, user_id, target, state, attempts, next_attempt_at, last_error, last_status,
  remote_id, created_at, sent_at}`.
- Links: `{kind, address, verified, verified_at, expires_at?, created_at}`
  (envelope). A personal email address waiting for its code is listed with
  `verified:false` and `expires_at`, next to the verified link it replaces.
- Notifications: `{id, org_id, alert_id, title, body, severity, read_at,
  created_at}`; only orgs the user still belongs to and whose security policy
  (2FA, login methods, session lifetime) the current session satisfies, as
  for that org's own endpoints. The read endpoint marks only those; the
  stream applies the same filter and recomputes it at every heartbeat.
- SSE events: `notification {…}` (the notification JSON) for each new
  notification, `read {ids}` or `read {all:true}` when notifications are
  marked read in any tab, `unread {count}` on connect and after every change, `end {reason}` when the
  session is revoked or expires (checked at every heartbeat), and a
  `: heartbeat` comment every 25 s. At most 5 streams per user.
- Rate limits: rule and channel tests, Telegram codes and Slack links allow
  10 per user per minute; the Telegram webhook 120 per IP per minute.

## 7. UI (sidebar group "Alerts" with the bell icon)

**Pages**
- Alert rules: list plus editor.
  - Event types are multi-select.
  - The condition editor reuses the policy text/query builder.
  - Threshold/window, throttle, group-by, quiet hours, recipients
    (users/groups/roles pickers), shared channels.
  - Actions: "Send test" and enable toggle.
- Channels: list, create/edit form per kind, showing env-name helper text and
  `secret_set`. "Send test" shows per-channel results.
- Groups: CRUD with a members picker.
- Alert history: list and detail.
- Delivery log: paginated, filterable, with error text.

**Elsewhere**
- Header bell: unread count plus a dropdown. It updates live over SSE.
- My account → Notifications:
  - link Telegram (shows the code and deep link, then polls until linked);
  - link Slack;
  - email address;
  - per-channel enable and min severity.

**Requirements**
- Viewers see read-only pages.
- EN/VI i18n.
- No table overflows at 1280px.

## 8. Out of scope (v1)

SMS/voice, PagerDuty/Opsgenie (use webhook), prompt excerpts, per-user quiet hours.

## 9. Environment variables

Control plane:

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_BASE_URL` | — | Origin of the admin UI, for links in notifications and email confirmation links. |
| `ALERTS_SECRET_ORGS` | empty (no channel secret usable) | Which channel kind and which orgs may name each secret variable: `WEBHOOK_SECRET_SIEM=webhook:*;A2A_SOC=a2a:<org-id>,<org-id>;GUARDSPEC_ALERT_OPS=slack:<org-id>`. `*` means every org. Kind `siem` is for [SIEM export](siem.md) sinks (`SIEM_*` variables). One kind per variable. Invalid entries stop the control plane at startup. |
| `ALERTS_PRIVATE_ORGS` | empty | Org ids whose channels with `allow_private` may reach loopback and private addresses (over http too). Metadata and link-local addresses stay refused. Replaces `ALERTS_ALLOW_PRIVATE_URLS`, which now stops the control plane at startup. |
| `ALERTS_EMAIL_DAILY_CAP` | `500` | Emails one org may send per 24 hours (deliveries and confirmation mails). |
| `ALERTS_LANG` | `en` | Language of in-app notifications, personal channels and confirmation mails: `en` or `vi`. |
| `TELEGRAM_BOT_TOKEN` | — | The instance bot: personal chats (`/start`) and shared channels verified with `/link`. |
| `TELEGRAM_BOT_USERNAME` | from `getMe` | The bot's username, for deep links and `/link@<bot>`. |
| `TELEGRAM_WEBHOOK_SECRET` | — | Secret of `setWebhook`; turns on `/v1/integrations/telegram/webhook`. |
| `TELEGRAM_POLLING` | off | `1` long-polls `getUpdates` instead of a webhook (no public URL needed). |
| `SLACK_BOT_TOKEN` | — | Instance Slack bot: personal DMs and `users.lookupByEmail`. Scopes `chat:write`, `users:read.email`, `im:write`. |
| `SMTP_URL` | — | `smtp://user:pass@host:587` (STARTTLS, required unless loopback) or `smtps://user:pass@host:465`. |
| `SMTP_FROM` | — | Sender, such as `Guard Spec <alerts@example.com>`. |
| `ALERTS_TEST_TELEGRAM_API`, `ALERTS_TEST_SLACK_API` | — | Test only: origins that replace `https://api.telegram.org` and `https://slack.com/api`, for fake servers in end-to-end runs. Leave unset in production. |
| channel secrets | — | The variables channels name in `secret_env` (`WEBHOOK_SECRET_*`, `SLACK_*`, `TEAMS_*`, `TELEGRAM_BOT_TOKEN_*`, `A2A_*`, `GUARDSPEC_ALERT_*`; `SIEM_*` for SIEM export sinks), each listed in `ALERTS_SECRET_ORGS`. |

Gateway:

| Variable | Default | Meaning |
|---|---|---|
| `ALERTS_FLAG_THRESHOLD` | `0.5` | Injection score from which an allowed request emits `detection.flagged`. |
| `ALERTS_EVENTS` | on | `off` emits no events. |

Pass every variable to the container; `docker-compose.yml` passes the
instance ones. Channel secret variables you add yourself. With the Helm
chart, the instance ones are under `controlPlane.env` and `gateway.env`;
secrets (`SMTP_URL`, bot tokens, channel secrets, `MFA_ENC_KEY`) go in a
Secret named in `controlPlane.extraEnvFrom`.

To check an SMTP server before relying on it, send two test alerts (English
and Vietnamese) through it:

```sh
SMTP_LIVE_URL='smtp://user:pass@smtp.example.com:587' \
SMTP_LIVE_FROM='Guard Spec <alerts@example.com>' SMTP_LIVE_TO='you@example.com' \
  go test ./internal/alerts/channels -run TestEmailLiveSMTP -count=1 -v
```

`SMTP_LIVE_CA=cert.pem` trusts a test server's self-signed certificate.

## 10. Setting up each channel

Create channels under Alerts → Channels (admin), or with the API:

```sh
curl -X POST "$CP/v1/organizations/$ORG/notification-channels" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"SIEM","kind":"webhook","config":{"url":"https://siem.example.com/guard"},"secret_env":"WEBHOOK_SECRET_SIEM"}'
```

then list the variable with its kind for the org in `ALERTS_SECRET_ORGS`
(`WEBHOOK_SECRET_SIEM=webhook:<org-id>`) and press "Send test".

**Telegram**
1. Create a bot with @BotFather; set `TELEGRAM_BOT_TOKEN` (and
   `TELEGRAM_BOT_USERNAME`).
2. Updates reach the control plane either through a webhook — set
   `TELEGRAM_WEBHOOK_SECRET` and register it once:
   ```sh
   curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
     -d url="$PUBLIC_BASE_URL/v1/integrations/telegram/webhook" \
     -d secret_token="$TELEGRAM_WEBHOOK_SECRET" -d allowed_updates='["message"]'
   ```
   — or with `TELEGRAM_POLLING=1` (one control plane replica only: Telegram
   allows one poller per bot).
3. Personal chats: users press "Link Telegram" under My account →
   Notifications and open the deep link; the bot answers in the chat. Codes
   work once, for 10 minutes, and only in private chats.
4. Group chats on the instance bot: create a `telegram` channel with `{}`,
   add the bot to the group, press "Verify" (`POST …/telegram-link`) and
   send the shown `/link@<bot> <code>` in the group. The bot answers
   "Linked"; the channel now has the group's `chat_id` and `verified: true`.
5. Group chats on your own bot: put its token in `TELEGRAM_BOT_TOKEN_<NAME>`
   (listed as `telegram:` in `ALERTS_SECRET_ORGS`) and create the channel with
   `{"chat_id":"-100…"}`.

**Slack**
- Bot (recommended): create a Slack app with `chat:write` (and
  `users:read.email` for personal links), install it, invite it to the
  channel, put its `xoxb-` token in `SLACK_<NAME>` and create
  `{"mode":"bot","channel":"C0123…"}`. Messages use Block Kit.
- Incoming webhook: create one for the channel, put its URL in
  `SLACK_<NAME>`, create `{"mode":"webhook"}`.
- Personal DMs use the instance `SLACK_BOT_TOKEN`; users press "Link Slack",
  which looks up their account email.

**Microsoft Teams** — Office 365 connectors are retired; use Workflows:
in the channel, Workflows → "Post to a channel when a webhook request is
received", copy the URL into `TEAMS_<NAME>`, create a `teams` channel with
`{}`. Messages are Adaptive Cards 1.4.

**Webhook** — `{"url":"https://…"}` and a random signing secret in
`WEBHOOK_SECRET_<NAME>` (`openssl rand -hex 32`). Verify every delivery
(section 11). Deliveries are retried with the same `event_id`; drop repeats.

**A2A** — `{"agent_card_url":"https://agent.example.com"}`; put the key the
card's security scheme asks for in `A2A_<NAME>`. The card's JSON-RPC
endpoint must be on the same origin.

**Email** — set `SMTP_URL` and `SMTP_FROM`. Personal email goes to the
account address, or to another address once the user confirmed it with the
mailed code. A shared mailbox is an `email` channel with
`{"to":["soc@example.com"],"lang":"vi"}`; each address gets a confirmation
link and receives alerts only after opening it. Templates exist in English
and Vietnamese.

**In-app** — nothing to set up. The bell shows the user's notifications;
the stream is `GET /v1/notifications/stream` with the Bearer header (use a
fetch-based EventSource; tokens in URLs are refused).

## 11. Verifying webhook signatures

The signature is `v1=` and the hex HMAC-SHA256, keyed with the secret, of
the timestamp header, a dot, the event id header, a dot and the raw body:
`timestamp + "." + event_id + "." + body`. Check the timestamp first (at
most 5 minutes off), compare in constant time, and drop repeated
`X-GuardSpec-Event-Id` values (the event id is signed, so it can be trusted
for that). Test vector: secret `secret`, timestamp `1700000000`, event id
`gs1_example`, body `{"a":1}` gives
`v1=30899026f765cd0076ae7cd2e24775790dfdce592d082324de0dc047373712e6`.

Go:

```go
func verify(secret []byte, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-GuardSpec-Timestamp"), 10, 64)
	if err != nil || math.Abs(float64(time.Now().Unix()-ts)) > 300 {
		return nil, errors.New("stale or missing timestamp")
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d.%s.", ts, r.Header.Get("X-GuardSpec-Event-Id"))
	mac.Write(body)
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(r.Header.Get("X-GuardSpec-Signature")), []byte(want)) {
		return nil, errors.New("bad signature")
	}
	return body, nil
}
```

Python:

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes) -> None:
    ts = headers["X-GuardSpec-Timestamp"]
    event_id = headers["X-GuardSpec-Event-Id"]
    if abs(time.time() - int(ts)) > 300:
        raise ValueError("stale timestamp")
    signed = ts.encode() + b"." + event_id.encode() + b"." + body
    want = "v1=" + hmac.new(secret, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(headers["X-GuardSpec-Signature"], want):
        raise ValueError("bad signature")
```

Node:

```js
import crypto from 'node:crypto';

export function verify(secret, headers, rawBody /* Buffer */) {
  const ts = headers['x-guardspec-timestamp'];
  const eventId = headers['x-guardspec-event-id'] ?? '';
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) throw new Error('stale timestamp');
  const want = 'v1=' + crypto.createHmac('sha256', secret).update(`${ts}.${eventId}.`).update(rawBody).digest('hex');
  const got = Buffer.from(headers['x-guardspec-signature'] ?? '');
  if (got.length !== Buffer.byteLength(want) || !crypto.timingSafeEqual(got, Buffer.from(want))) {
    throw new Error('bad signature');
  }
}
```

Verify the raw bytes as received, before any JSON parsing.

## 12. Operations

Metrics (both binaries' metrics ports):
- `guardspec_events_dropped_total{source}`: events lost to a full buffer or a
  failed write (`gateway`, `control_plane`).
- `guardspec_events_written_total{source}`.
- `guardspec_alerts_notified_total{state}`: notifications queued (firing,
  resolved).
- `guardspec_alerts_deliveries_total{kind,result}`: sent, retry, dead,
  limited.
- `guardspec_alerts_delivery_latency_seconds{kind}`: newest event of the
  alert to the first delivery attempt.

Every control plane replica runs the worker; the advisory lock, the unique
constraints and `SKIP LOCKED` keep them from doing the same work twice.
Retention, pruned by the worker at most once a minute per org: rule hits
after a day, processed events and sent or dead deliveries after 30 days, read
in-app notifications after 90 days. Alerts are kept; their samples disappear
with their events. The gateway's p99 is unchanged by events
(`BenchmarkGatewayEvents` in `cmd/gateway`).

## 13. Differences from the agreed contract

- **Reads need viewer, not member** (aligned with the UI, PR #31): GET of
  rules, channels, groups and alert history needs `alerts.read` (viewer).
  Channels show `secret_env` names and `secret_set`, never secret values. The
  delivery log stays admin (`alerts.deliveries.read`).
- **Channel secrets are bound to a kind and to orgs** (security reviews):
  `ALERTS_SECRET_ORGS` entries are `NAME=kind:*` or `NAME=kind:<org>,<org>`;
  a `secret_env` must match its kind's prefix (or `GUARDSPEC_ALERT_`, bound
  to the one listed kind), never the instance tokens. Without it, any user
  (who can create and own an org) could put another org's secret, or a Slack
  token, on an A2A channel aimed at their own server.
- **`ALERTS_PRIVATE_ORGS` replaces `ALERTS_ALLOW_PRIVATE_URLS`**: private
  addresses are per org, not instance-wide.
- **Shared Telegram channels on the instance bot are verified with `/link`**,
  and `chat_id` is set by that, not by the client; otherwise the instance bot
  would post into any chat id.
- **Shared email addresses are double opt-in**, with a per-org daily email
  cap (`ALERTS_EMAIL_DAILY_CAP`, default 500); otherwise the instance SMTP
  account would relay to any address.
- **The webhook signature covers the event id**: `v1=HMAC(secret,
  timestamp + "." + event_id + "." + body)` instead of `timestamp + "." + body`.
- **A2A endpoints must share the Agent Card's origin**, and cards cannot name
  reserved headers for the key.
- **In-app notifications follow each org's session policy** (2FA, login
  methods, session lifetime).
- **Credentials in URL queries are refused** for webhook and A2A URLs
  (config is readable by viewers).
- **A2A v1.0**: the current spec is 1.0.0, whose JSON-RPC method is
  `SendMessage`; `message/send` (named in the contract) is used for agents
  that declare protocol 0.3.
- **Personal email address** (added for the UI): `PUT /v1/me/channel-links/email`
  mails a code, `POST /v1/me/channel-links/email/confirm` activates it.
- **Additions**: `activity.<action>` event types; `position` on condition
  errors; `test` on payloads and alerts; `rule_id`, `last_status`,
  `remote_id`, `channel_name` on deliveries; `user_ids`, `member_ids`,
  `member_count` on groups; the SSE `read`, `unread` and `end` events; the
  1000/minute per-org delivery cap; retention (section 12).

## 14. What the admin UI relies on

The mapping between the UI (PR #31) and this backend.

| UI need | Backend |
|---|---|
| Gating | `GET /v1/permissions` lists `alerts.read` (viewer), `alerts.write` (admin), `alerts.deliveries.read` (admin). The routes enforce the same roles. |
| Read-only pages for viewers | Rules, channels, groups and alert history are readable by viewers; channels carry `secret_env` and `secret_set`, never a secret. |
| Bell, live | `GET /v1/notifications/stream` (Bearer): `event: notification` with the notification JSON, `event: read` with `{ids}` or `{all:true}`, `event: unread` with `{count}`. |
| Unread count | `GET /v1/notifications?unread=1&limit=1` returns `total` (capped at 10 000, `total_capped`). |
| Mark read | `POST /v1/notifications/read` with `{ids:[…]}` or `{all:true}`; every open stream of the user gets `read` and `unread`. |
| Group editor | `GET /user-groups/:id` returns `user_ids[]` (and `members[]` with emails); lists return `member_count`. `PUT /user-groups/:id/members {user_ids}` replaces the members. |
| History and delivery log | Alerts and deliveries carry `rule_name`; deliveries carry `channel_name` (null for personal channels, which carry `user_id`); alert detail carries `samples[]`. |
| Personal preferences | `PUT /organizations/:orgId/me/notification-prefs` takes a bare JSON array `[{channel_kind, enabled, min_severity}]` and returns the full list. |
| Condition editor | `POST`/`PATCH /alert-rules` validate the condition against the alert event fields (`type`, `severity`, `project_id`, `attrs.*`, section 2) and answer 400 `{error: "condition: …", position}` with a readable parse error. `/policy/parse` is not needed. |
| Personal email | `PUT /v1/me/channel-links/email {address}` → 202, a code is mailed; `POST /v1/me/channel-links/email/confirm {code}` activates it. Links carry `verified`; the pending address is listed with `verified:false` and `expires_at`. `DELETE /v1/me/channel-links/email` returns to the account address. |
| Capabilities | `GET /v1/alerts/capabilities?org_id=<current org>`: `allow_private_urls` is per org (only show the `allow_private` checkbox when true); `email_confirmation`, `email_daily_cap`. |
| Channel verification | Channels carry `verified: bool`. Telegram on the instance bot: no `chat_id` input; a "Verify" action calls `POST …/notification-channels/:id/telegram-link` and shows `command` to send in the group, then polls the channel until `verified`. Email: `addresses [{address, confirmed, confirmed_at, sent_at}]`, a "Resend confirmations" action (`POST …/email-confirmations`). |
| Secret helper text | `secret_env` must be listed with the channel's kind in `ALERTS_SECRET_ORGS` (`NAME=kind:org`); the 400 says so. |
