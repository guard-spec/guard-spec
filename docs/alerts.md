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
| `detection.blocked` | gateway | warning | request_id, categories[], score, layer, decision, api_key_id, model (+ policy_id when a policy rule matched) |
| `detection.flagged` | gateway | info | same as above (score ≥ flag threshold, not blocked) |
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
- `api_key_id` is the shown key prefix (`gs_` and 8 characters), never the key.
- `email_hash` is the first 16 bytes of SHA-256 of the lower-cased address, hex.
- `detection.flagged` fires for allowed requests whose injection score is at
  least `ALERTS_FLAG_THRESHOLD` (default 0.5); a request is blocked at 0.85.
- A request refused for another reason (invalid body, rate limit) emits no
  detection event.

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
`attrs.provider_id`, `attrs.policy_id`, `attrs.action`. An attribute an event
lacks reads as `""`, `0` or `[]`. Examples:

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
`id, org_id, name, kind, config jsonb (non-secret), secret_env text|null, enabled, created_at`

| kind | config | secret_env holds |
|---|---|---|
| `telegram` | `{chat_id}` (group chat; personal chats come from links) | bot token (`TELEGRAM_BOT_TOKEN_*`); without it the instance `TELEGRAM_BOT_TOKEN` |
| `slack` | `{mode: "bot"\|"webhook", channel?}` | bot token or webhook URL (`SLACK_*`) |
| `teams` | `{}` | Workflows webhook URL (Adaptive Card), `TEAMS_*`. No O365 connectors. |
| `webhook` | `{url, allow_private:false}` | HMAC signing secret (`WEBHOOK_SECRET_*`) |
| `a2a` | `{agent_card_url, allow_private:false}` | bearer/API key if the Agent Card demands it (`A2A_*`) |
| `email` | `{to[], lang?: "en"\|"vi"}` (shared mailbox) | — (SMTP comes from global env `SMTP_URL`, `SMTP_FROM`) |

Channel rules:
- Env var names must match `^[A-Z][A-Z0-9_]{2,63}$`.
- Names with the prefixes `GUARDSPEC_ALERT_`, `TELEGRAM_BOT_TOKEN_`,
  `SLACK_`, `TEAMS_`, `WEBHOOK_SECRET_` or `A2A_` are allowed. Nothing else is
  allowed (this stops reading `DATABASE_URL`).
  - Each kind reads only its own prefix (or `GUARDSPEC_ALERT_`), and the
    instance tokens `TELEGRAM_BOT_TOKEN` and `SLACK_BOT_TOKEN` are never a
    channel's secret: an A2A channel, which sends its secret to a URL the org
    chooses, cannot name a Slack token.
  - The operator lists which orgs may name which variable in
    `ALERTS_SECRET_ORGS` (section 9). Unlisted, a variable cannot be used.
- The UI shows `secret_set: bool`, never the value.
- Webhook and A2A URLs go through the existing SSRF guard (upstreams
  validation and dialer):
  - https only, unless `allow_private` is set and the instance env
    `ALERTS_ALLOW_PRIVATE_URLS=1` is on;
  - no credentials in the URL, and no query parameter that looks like one
    (`token`, `key`, `secret`, `sig`, …): config is readable by members;
  - no redirects;
  - 5 s timeout;
  - response body capped at 64 KiB.
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
- `X-GuardSpec-Event-Id` (the same idempotency key as `event_id`: a retry
  carries the same value, so receivers can drop duplicates)
- `X-GuardSpec-Timestamp` (unix seconds)
- `X-GuardSpec-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>`

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
- Auth follows the card's security scheme (HTTP bearer, or an apiKey in a
  header) using `secret_env`.
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
| GET/POST `/alert-rules`, GET/PATCH/DELETE `/alert-rules/:id` | read: member, write: admin | condition validated (400 with parse error and `position`) |
| POST `/alert-rules/:id/test` | admin | emits a synthetic `alert.test` that goes through the full pipeline; returns `{alert_id}` |
| GET/POST `/notification-channels`, GET/PATCH/DELETE `/:id` | read: member, write: admin | returns `secret_set` |
| POST `/notification-channels/:id/test` | admin | synchronous send; `{ok, status, latency_ms, error?}` |
| GET/POST `/user-groups`, GET/PATCH/DELETE `/:id`, PUT `/:id/members {user_ids[]}` | read: member, write: admin | |
| GET `/alerts?state=&rule_id=` , GET `/alerts/:id` | member | history |
| GET `/notification-deliveries?state=&channel_kind=&rule_id=` | admin | delivery log |
| GET/PUT `/me/notification-prefs` | self (any role) | `[{channel_kind, enabled, min_severity}]` |
| GET `/v1/me/channel-links`, DELETE `/v1/me/channel-links/:kind` | self | |
| POST `/v1/me/channel-links/telegram/start` | self | `{code, deep_link:"https://t.me/<bot>?start=<code>", expires_at}`; single use, 10 min |
| POST `/v1/me/channel-links/slack` | self | links by looking up the user's email via `users.lookupByEmail` (instance-level `SLACK_BOT_TOKEN`) |
| POST `/v1/integrations/telegram/webhook` | Telegram secret header | handles `/start <code>`; verified with `X-Telegram-Bot-Api-Secret-Token` = env `TELEGRAM_WEBHOOK_SECRET`. A long-polling fallback runs when `TELEGRAM_POLLING=1`. |
| GET `/v1/notifications?unread=1`, POST `/v1/notifications/read {ids[]\|all}` | self | |
| GET `/v1/notifications/stream` | self | SSE (`text/event-stream`, heartbeat every 25 s). Auth by Bearer via fetch-stream (no token in the URL). |

**Instance capabilities:** GET `/v1/alerts/capabilities` (any user) returns:
`{telegram:{enabled, bot_username}, slack_bot:bool, smtp:bool, a2a:true, webhook:true, teams:true, allow_private_urls:bool}`

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
- Groups: `{id, name, description, member_ids, member_count, created_at,
  updated_at}`; GET `/:id` adds `members [{user_id, email, display_name}]`.
- Alerts: `{id, rule_id, rule_name, dedupe_key, group, project_id, state,
  severity, first_at, last_at, count, resolved_at, sample_event_ids,
  suppressed, test}`; GET `/:id` adds `samples [{event_id, type, severity,
  occurred_at, attrs}]` and `deliveries {state: count}`.
- Deliveries: `{id, alert_id, rule_id, rule_name, channel_kind, channel_id,
  user_id, target, state, attempts, next_attempt_at, last_error, last_status,
  remote_id, created_at, sent_at}`.
- Links: `{kind, address, verified_at, created_at}` (envelope).
- Notifications: `{id, org_id, alert_id, title, body, severity, read_at,
  created_at}`; only orgs the user still belongs to.
- SSE events: `unread {count}` on connect and after every change,
  `notification {…}` for each new notification, `end {reason}` when the
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
| `PUBLIC_BASE_URL` | — | Origin of the admin UI, for links in notifications. |
| `ALERTS_SECRET_ORGS` | empty (no channel secret usable) | Which orgs may name which channel secret variable: `WEBHOOK_SECRET_SIEM=*;A2A_SOC=<org-id>,<org-id>`. `*` means every org. Invalid entries stop the control plane at startup. |
| `ALERTS_ALLOW_PRIVATE_URLS` | off | `1` lets channels with `allow_private` reach loopback and private addresses over http. Metadata and link-local addresses stay refused. |
| `ALERTS_LANG` | `en` | Language of in-app notifications and personal channels: `en` or `vi`. |
| `TELEGRAM_BOT_TOKEN` | — | The instance bot: personal chats and `/start` linking. |
| `TELEGRAM_BOT_USERNAME` | from `getMe` | The bot's username, for deep links. |
| `TELEGRAM_WEBHOOK_SECRET` | — | Secret of `setWebhook`; turns on `/v1/integrations/telegram/webhook`. |
| `TELEGRAM_POLLING` | off | `1` long-polls `getUpdates` instead of a webhook (no public URL needed). |
| `SLACK_BOT_TOKEN` | — | Instance Slack bot: personal DMs and `users.lookupByEmail`. Scopes `chat:write`, `users:read.email`, `im:write`. |
| `SMTP_URL` | — | `smtp://user:pass@host:587` (STARTTLS, required unless loopback) or `smtps://user:pass@host:465`. |
| `SMTP_FROM` | — | Sender, such as `Guard Spec <alerts@example.com>`. |
| channel secrets | — | The variables channels name in `secret_env` (`WEBHOOK_SECRET_*`, `SLACK_*`, `TEAMS_*`, `TELEGRAM_BOT_TOKEN_*`, `A2A_*`, `GUARDSPEC_ALERT_*`). |

Gateway:

| Variable | Default | Meaning |
|---|---|---|
| `ALERTS_FLAG_THRESHOLD` | `0.5` | Injection score from which an allowed request emits `detection.flagged`. |
| `ALERTS_EVENTS` | on | `off` emits no events. |

Pass every variable to the container; `docker-compose.yml` passes the
instance ones. Channel secret variables you add yourself.

## 10. Setting up each channel

Create channels under Alerts → Channels (admin), or with the API:

```sh
curl -X POST "$CP/v1/organizations/$ORG/notification-channels" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"SIEM","kind":"webhook","config":{"url":"https://siem.example.com/guard"},"secret_env":"WEBHOOK_SECRET_SIEM"}'
```

then list the variable for the org in `ALERTS_SECRET_ORGS` and press "Send
test".

**Telegram**
1. Create a bot with @BotFather; set `TELEGRAM_BOT_TOKEN` (and
   `TELEGRAM_BOT_USERNAME`).
2. Personal chats: either set `TELEGRAM_WEBHOOK_SECRET` and register the
   webhook once:
   ```sh
   curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
     -d url="$PUBLIC_BASE_URL/v1/integrations/telegram/webhook" \
     -d secret_token="$TELEGRAM_WEBHOOK_SECRET" -d allowed_updates='["message"]'
   ```
   or set `TELEGRAM_POLLING=1` (one control plane replica only: Telegram
   allows one poller per bot).
   Users press "Link Telegram" under My account → Notifications and open the
   deep link; the bot answers in the chat. Codes work once, for 10 minutes,
   and only in private chats.
3. Group chats: add the bot to the group, get the chat id (for example from
   `getUpdates`), create a `telegram` channel with `{"chat_id":"-100…"}`.
   Without `secret_env` it uses the instance bot; with
   `TELEGRAM_BOT_TOKEN_<NAME>` another bot.

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
(section 11). Deliveries are retried with the same `event_id`; make the
receiver idempotent.

**A2A** — `{"agent_card_url":"https://agent.example.com"}`; put the key the
card's security scheme asks for in `A2A_<NAME>`.

**Email** — set `SMTP_URL` and `SMTP_FROM`. Personal email goes to account
addresses; a shared mailbox is an `email` channel with
`{"to":["soc@example.com"],"lang":"vi"}`. Templates exist in English and
Vietnamese.

**In-app** — nothing to set up. The bell shows the user's notifications;
the stream is `GET /v1/notifications/stream` with the Bearer header (use a
fetch-based EventSource; tokens in URLs are refused).

## 11. Verifying webhook signatures

The signature is `v1=` and the hex HMAC-SHA256, keyed with the secret, of
the timestamp header, a dot and the raw body. Check the timestamp first (at
most 5 minutes off), compare in constant time, and drop repeated
`X-GuardSpec-Event-Id` values. Test vector: secret `secret`, timestamp
`1700000000`, body `{"a":1}` gives
`v1=49f24e537407743fa4a0242bb63b94b9a47ee99cbbe071ccd8a22550ae411686`.

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
	fmt.Fprintf(mac, "%d.", ts)
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
    if abs(time.time() - int(ts)) > 300:
        raise ValueError("stale timestamp")
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(headers["X-GuardSpec-Signature"], want):
        raise ValueError("bad signature")
```

Node:

```js
import crypto from 'node:crypto';

export function verify(secret, headers, rawBody /* Buffer */) {
  const ts = headers['x-guardspec-timestamp'];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) throw new Error('stale timestamp');
  const want = 'v1=' + crypto.createHmac('sha256', secret).update(`${ts}.`).update(rawBody).digest('hex');
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

- **Reads need member.** As written in §6, GET of rules, channels, groups
  and alerts needs the member role; viewers get 403 there. "Viewers see
  read-only pages" (§7) can only show what a member may read.
- **`ALERTS_SECRET_ORGS` and per-kind prefixes** (security review): a
  channel's `secret_env` must also start with its own kind's prefix (or
  `GUARDSPEC_ALERT_`), may not be `TELEGRAM_BOT_TOKEN`/`SLACK_BOT_TOKEN`, and
  must be listed for the org in `ALERTS_SECRET_ORGS`. Without this, an org
  admin could name another org's variable on an A2A channel pointing at
  their own server and receive that secret.
- **Credentials in URL queries are refused** for webhook and A2A URLs
  (config is readable by members).
- **A2A v1.0**: the current spec is 1.0.0, whose JSON-RPC method is
  `SendMessage`; `message/send` (named in the contract) is used for agents
  that declare protocol 0.3.
- **Telegram channels need `chat_id`**: a shared channel without one has
  nowhere to post.
- **Email has no link endpoint**: personal email uses the account address;
  §6 has no endpoint to set another one (an unverified address could be used
  to mail third parties).
- **Additions**: `activity.<action>` event types; `position` on condition
  errors; `test` on payloads and alerts; `rule_id`, `last_status`,
  `remote_id` on deliveries; `member_ids`/`member_count` on groups; the SSE
  `end` event; the 1000/minute per-org delivery cap; retention (section 12).
