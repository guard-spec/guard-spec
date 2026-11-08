# Security risks and hardening

> Tiếng Việt: [security-risks.vi.md](security-risks.vi.md).

This page is for the people who deploy and operate Guard Spec. It lists the
risks that remain when Guard Spec is in front of your LLM, and what you can do
about each. For what the gateway does and does not protect against, read
[Security model and limitations](../README.md#security-model-and-limitations)
first. To report a vulnerability, follow [SECURITY.md](../SECURITY.md).

Guard Spec is one layer of defence. It lowers the chance that an injected
instruction reaches the model and limits what the answer can leak. It does not
make an LLM application safe on its own.

## Contents

- [Summary](#summary)
- [Detection risks](#detection-risks)
- [Application and agent risks](#application-and-agent-risks)
- [Deployment risks](#deployment-risks)
- [Identity and access risks](#identity-and-access-risks)
- [Data and privacy risks](#data-and-privacy-risks)
- [Supply chain risks](#supply-chain-risks)
- [Operational risks](#operational-risks)
- [Hardening checklist](#hardening-checklist)

## Summary

| # | Risk | Impact | What reduces it |
|---|---|---|---|
| D1 | An attack is not detected | Injected instructions reach the model | Least-privilege tools, human confirmation, output guard, exemplars |
| D2 | A benign request is blocked | Users are refused | Measure on your traffic, allow exemplars, `DETECTOR_LAYERS` |
| D3 | Model layers silently missing | Only L1 runs; recall drops | `DETECTOR_REQUIRE_ML=true`, alert on `/readyz` `degraded` |
| D4 | Indirect injection in content you do not scan | Tool results or system prompts are not checked | `SCAN_ROLES`, per-org `scan_roles`, `SPOTLIGHT` |
| D5 | Forged history on `/v1/messages` and `/v1/responses` | Unscanned text placed in earlier turns reaches the model | Trust key holders, or `SCAN_HISTORY=full` |
| D6 | Conversation state kept by the upstream (`/v1/responses`) | Earlier turns the gateway cannot see reach the model | `RESPONSES_SERVER_STATE=refuse` (the default); separate upstream keys per org |
| A1 | The agent misuses a tool | Data loss, unwanted actions | Authorisation in your app, egress control, confirmations |
| A2 | Exfiltration through links the guard keeps | Data leaves through the answer | Short host allowlist, disable auto-linking in your UI |
| P1 | Services exposed without TLS | Credentials and prompts readable on the network | TLS at a reverse proxy or load balancer |
| P2 | Control plane or metrics reachable from the internet | Admin login attacks, information leaks | Private network, VPN or SSO in front |
| P3 | Org upstreams point at internal hosts or receive your keys | SSRF, key leakage | `UPSTREAM_ALLOW_PRIVATE=false`, `UPSTREAM_KEY_ORGS` |
| P4 | Rate limits bypassed by volume | Cost, denial of service | WAF or rate limiter in front; limits are per replica |
| I1 | Weak or leaked secrets | Full takeover | Strong secrets in a secret manager, rotation |
| I2 | Lost `MFA_ENC_KEY` | Everyone's 2FA stops working | Back it up with the database |
| I3 | Any user can create an organization | Untrusted admins choose upstreams | P3 settings, restrict who can sign up |
| I4 | 2FA enrolment is trust on first use | An attacker with a password enrols first | Require 2FA early; reset 2FA when in doubt |
| I5 | Wrong `TRUSTED_PROXIES` | Spoofed client IPs in limits and logs | List only your proxies |
| R1 | Prompt content stored in audit rows | Personal data at rest | Keep `AUDIT_STORE_CONTENT` off, set `CONTENT_KEK`, retention |
| R2 | Personal data passes the redactor | Leaks in answers, sent to the provider | `input_pii_action` tokenize or redact; patterns only, add your own checks |
| R3 | Trace IDs or metric labels leak tenant data | Cross-tenant information | Defaults are safe; review before changing them |
| S1 | Tampered image, binary or model | Arbitrary code or a weakened detector | cosign verify, SHA-256 pinned models, digests |
| S2 | Known vulnerabilities in dependencies | Exploitable services | Update to the latest release; watch advisories |
| O1 | Database or admin access misused | Policies changed, audit rows read | Least privilege, activity log, backups |
| O2 | Fail-closed causes an outage | Requests refused (503) | Health checks, replicas, alerts |

## Detection risks

### D1. An attack is not detected

Detection is probabilistic. New phrasings, languages other than English and
Vietnamese, encodings that L1 only partly decodes (such as base64) and
multi-turn attacks that look harmless in each single message can pass. With
the default model layers the eval set shows a true positive rate of about 0.93
at the block threshold (see [Benchmarks](../README.md#benchmarks)); the rest
reach the model.

What to do:

- Design your application as if some injections reach the model: give tools
  the least privilege they need and ask a person to confirm risky actions.
- Keep the output guard on; it limits what a successful injection can leak.
- Add attacks you see in your traffic as block exemplars for your organization
  ([Per-organization exemplars](../README.md#per-organization-exemplars)).
- Report bypasses privately ([SECURITY.md](../SECURITY.md)); they are in scope.

### D2. A benign request is blocked

With L2 and L3, about 1.4% of benign eval prompts are blocked, 3.5% of benign
Vietnamese teencode and 1.7% of English. The Vietnamese eval and training data
is synthetic, so your rate can differ.

What to do:

- Run in front of a copy of your traffic first and read the `block` audit rows.
- Add allow exemplars for false positives you see.
- If a false block costs more than a missed attack for you, run
  `DETECTOR_LAYERS=l1` (about 0.1% false positives, lower recall).

### D3. Model layers silently missing

When the models are missing or fail to load, the gateway logs a warning and
keeps running with L1 only. `/readyz` then shows `"degraded":true`.

What to do:

- Set `DETECTOR_REQUIRE_ML=true` so the gateway refuses to start without the
  model layers, or use the `gateway-full` image, which ships them.
- Alert on `degraded` in `/readyz` and on `guardspec_gateway_detector_errors_total`.

### D4. Indirect injection in content you do not scan

By default the gateway classifies user messages, tool results and MCP tool
descriptions (`SCAN_ROLES=user,tool,tool_descriptions`). System prompts and
the model's tool-call arguments are not classified unless you add them, and
images, audio and other non-text parts are not inspected.

What to do:

- If your system prompt contains user-controlled or retrieved text, add
  `system` to `SCAN_ROLES` or turn it on per organization (`scan_roles`).
- Send retrieved documents through `/guardrail/scan` with `documents[]` before
  you put them in a prompt.
- Turn on `SPOTLIGHT` (`delimit` or `datamark`) so the model can tell data from
  instructions.

### D5. Forged history on `/v1/messages`

Claude Code and other Messages API clients resend the whole conversation on
every turn. With `SCAN_HISTORY=latest` (the default for `/v1/messages`) the
gateway classifies only the trailing turn, the messages after the last
assistant message, plus the system prompt and tools. Earlier tool results
and documents are still checked, from the scan cache or by scanning them
again, so content that was refused or redacted stays refused or redacted.
The user text of earlier turns is not classified again: the gateway trusts
the client that holds the API key not to forge it. A key holder who writes
an injection into an earlier "user" turn gets it past the detector.

What to do:

- Give gateway keys only to clients you trust this far (a developer's own
  Claude Code is one).
- Set `SCAN_HISTORY=full` for keys used by untrusted clients; long sessions
  then reach the 128 KiB limit sooner.

The same applies to the input items of `/v1/responses`: the turns up to the
last item the model produced are history.

### D6. Conversation state kept by the upstream on `/v1/responses`

With `previous_response_id`, `conversation` or `item_reference`, the
Responses API adds earlier turns that the upstream stored. The gateway does
not see them in the request and cannot scan them again. They passed through
the gateway when they were made only if every turn did; and a response id
made with an upstream key that several orgs or applications share can be
referenced by anyone who learns it. By default
(`RESPONSES_SERVER_STATE=refuse`) such requests get a 400.

What to do:

- Keep the default and have clients send the whole conversation in `input`
  (most SDK agent loops can; reasoning models keep their state with
  `include: ["reasoning.encrypted_content"]` and `store: false`).
- If you set `RESPONSES_SERVER_STATE=allow` for compatibility, give each org
  its own upstream key (named upstreams with `UPSTREAM_KEY_*`), and watch for
  audit rows tagged `input:server_state=1`.

## Application and agent risks

### A1. The agent misuses a tool

The gateway sees tool-call arguments and guards their strings, but it does not
execute or authorise tool calls and has no egress control. If the model is
convinced to call a tool, the tool runs.

What to do:

- Authorise every tool call in your application against the end user's
  permissions, not the model's request.
- Restrict network egress from the services that run tools.
- Require confirmation for actions that send data out, spend money or delete.

### A2. Exfiltration through links the guard keeps

The output guard removes images and links to hosts outside the allowlist, but
keeps links to allowlisted hosts and plain-text URLs without a query string.
If your UI turns bare URLs into links, it can still be used to leak data.

What to do:

- Keep the link allowlist short; do not allow hosts where anyone can publish.
- Do not auto-link URLs in model output, and do not load remote images in it.

## Deployment risks

### P1. Services exposed without TLS

The gateway and the control plane serve plain HTTP. API keys, session cookies
and prompts cross the network in clear text unless something in front
terminates TLS.

What to do:

- Put a reverse proxy or load balancer with TLS in front of both services.
- Use `sslmode=require` or stronger in database URLs.
- Set `PUBLIC_BASE_URL` to the `https://` origin of the control plane.

### P2. Control plane or metrics reachable from the internet

The control plane holds the admin UI and API. `/metrics` is served on its own
listener (`METRICS_ADDR`).

What to do:

- Expose only the gateway to your applications. Keep the control plane on a
  private network, behind a VPN or an identity-aware proxy.
- Never route the metrics port through an ingress or public load balancer.
- Leave `ALLOWED_ORIGINS` empty unless another origin really needs the API.

### P3. Org upstreams point at internal hosts or receive your keys

An org admin chooses where its named upstreams point.

What to do:

- Keep `UPSTREAM_ALLOW_PRIVATE=false` (the default) unless every org admin is
  trusted. Cloud metadata addresses are always refused.
- Keep `UPSTREAM_KEY_ORGS` narrow: it decides which org may use which
  `UPSTREAM_KEY_*` variable. The compose file sets both for a single-team
  setup; change them before letting untrusted users create organizations.

### P4. Rate limits bypassed by volume

Rate limits are kept in memory per gateway replica, so the effective limit
grows with the number of replicas, and they do not stop a flood of
connections.

What to do: put a WAF or a shared rate limiter in front of the gateway, and
set provider-side spending limits.

## Identity and access risks

### I1. Weak or leaked secrets

`POSTGRES_PASSWORD`, `GUARDSPEC_APP_PASSWORD`, `JWT_SECRET`, `MFA_ENC_KEY` and
`ADMIN_PASSWORD` protect everything. Outside `GUARD_ENV=dev` the services
refuse missing, default or short secrets, but they cannot tell whether a
secret has leaked.

What to do:

- Generate secrets randomly (`scripts/quickstart.sh` does) and keep them in a
  secret manager, not in Git or in Helm values.
- Give them as files (`NAME_FILE`) or Vault references (`NAME=vault:...`)
  rather than in the environment, where `docker inspect` and process listings
  show them ([where secrets come from](security/README.md#where-secrets-come-from)).
- Never run production with `GUARD_ENV=dev`.
- Rotate `JWT_SECRET` (signs everyone out) and the database passwords if you
  suspect a leak. Revoke API keys you no longer use.

### I2. Lost `MFA_ENC_KEY`

TOTP secrets are encrypted with `MFA_ENC_KEY`. Without the key, nobody's 2FA
works, and the control plane refuses to start while users have 2FA.

What to do: back the key up together with the database, in a different place
from the database backup itself.

### I3. Any user can create an organization

Any signed-in user can create an organization and becomes its admin. See P3
for what that admin can configure.

What to do: if your control plane is reachable by people you do not trust,
use SSO with `allowed_domains` and keep the P3 settings strict.

### I4. 2FA enrolment is trust on first use

When an organization starts requiring 2FA, a member without it enrols at the
next login with only a password. Someone who already has that password can
enrol their own authenticator first.

What to do: require 2FA from the start, and reset a member's 2FA if in doubt.

### I5. Wrong `TRUSTED_PROXIES`

`TRUSTED_PROXIES` decides whose `X-Forwarded-For` is believed. Too broad a
value lets clients choose the address used for rate limits, sessions and the
activity log; an empty value behind a proxy makes every client look the same.

What to do: list exactly the addresses or CIDRs of your proxies.

## Data and privacy risks

### R1. Prompt content stored in audit rows

By default audit rows keep scores, the decision, and a SHA-256 and length of
the body, not the content. `AUDIT_STORE_CONTENT=true`, or the per-org
`audit_store_content` setting, stores prompts and buffered answers.

What to do:

- Keep content storage off unless you need it, and tell your users if you
  turn it on.
- Set a key-encryption key (`CONTENT_KEK`, `CONTENT_KEK_FILE` or a Vault
  Transit key): stored content is then encrypted with a key per organization
  ([Encryption](security/README.md#encryption)); back the key up, and run
  `control-plane keys encrypt-existing` for content stored before.
- Set `AUDIT_RETENTION_DAYS`, encrypt the database at rest and limit who can
  read it.

### R2. Personal data passes the redactor

The output guard redacts e-mail addresses, Vietnamese phone, ID and card
numbers and IPv4 addresses with patterns. Other formats, other countries and
personal data written in words are not caught. Prompts go to the upstream as
they are unless the organization sets `input_pii_action` (below).

What to do: if you must not send personal data to the LLM provider, set
`input_pii_action` to `tokenize` (the answer gets the values back) or
`redact` in the organization's guard settings ([Personal data in
requests](../README.md#personal-data-in-requests)). It only covers what the
patterns find: remove other personal data (names, addresses) in your
application before the request, or use a provider and contract that allow
it.

### R3. Trace IDs or metric labels leak tenant data

Metric labels use fixed value sets, per-tenant labels are off
(`METRICS_TENANT_LABELS=false`) and `traceparent` is not sent upstream
(`OTEL_PROPAGATE_UPSTREAM=false`). Turning these on shares more with your
monitoring system or the provider.

What to do: change these defaults only when the receiving system is trusted.

## Supply chain risks

### S1. Tampered image, binary or model

What to do:

- Verify images and archives with cosign before you deploy them
  ([Verifying releases](../SECURITY.md#verifying-releases)), and deploy by
  digest rather than by tag.
- Download models with `models pull`, which checks the SHA-256 pinned in
  `models/manifest.yaml`. In air-gapped installs, mirror only verified files.

### S2. Known vulnerabilities in dependencies

The project is pre-1.0; security fixes land in the next release only.

What to do: follow the repository's releases and security advisories, upgrade
to the latest `0.x`, and scan the images you run.

## Operational risks

### O1. Database or admin access misused

Anyone with database or instance-admin access can change policies, read audit
rows and create API keys.

What to do: give the application role (`guardspec_app`) to the services only,
keep the owner role for migrations, give people the lowest role they need, and
review the activity log.

### O2. Fail-closed causes an outage

If policies, org settings or the detector cannot run, the gateway refuses the
request (503) instead of passing it through. A database outage therefore stops
LLM traffic.

What to do: run more than one gateway replica, use a highly available
Postgres, and alert on 503 rates and `/readyz`.

## Hardening checklist

- [ ] TLS in front of both services; database connections with `sslmode=require` or stronger
- [ ] Only the gateway is reachable by applications; the control plane and metrics ports are private
- [ ] `GUARD_ENV` is not `dev`; all secrets are random and kept in a secret manager
- [ ] `MFA_ENC_KEY` is backed up separately from the database backup
- [ ] `DETECTOR_REQUIRE_ML=true` or the `gateway-full` image; alerts on `degraded`
- [ ] `UPSTREAM_ALLOW_PRIVATE=false` and a narrow `UPSTREAM_KEY_ORGS`
- [ ] `TRUSTED_PROXIES` lists exactly your proxies
- [ ] `SCAN_ROLES` covers every place untrusted text enters your prompts
- [ ] A short link allowlist; no auto-linking of model output in your UI
- [ ] Content storage off; `AUDIT_RETENTION_DAYS` set
- [ ] SSO or required 2FA for everyone with admin access
- [ ] A WAF or shared rate limiter in front of the gateway; provider spending limits
- [ ] Images and archives verified with cosign; deployed by digest
- [ ] Tools authorised in your application; risky actions confirmed by a person
