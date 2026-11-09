<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SAML SSO and SCIM provisioning

> Tiếng Việt: [sso.vi.md](sso.vi.md).

This guide sets up single sign-on with SAML 2.0 and user provisioning with
SCIM 2.0 for Okta, Microsoft Entra ID, Google Workspace and Keycloak. The
reference (every field, check and endpoint) is in the README,
[Identity, SSO and two-factor authentication](../README.md#identity-sso-and-two-factor-authentication).
OpenID Connect providers are set up as described there as well.

Who does what:

| Step | Who | Where |
|---|---|---|
| Add the SAML provider (instance-wide) | instance administrator | `/v1/admin/identity-providers`, or the Identity providers page → Add SAML provider |
| Restrict login methods, claim a domain (`domain_join`), `scim_revoke_keys` | org owner | `PUT /v1/organizations/:orgId/security`, or the organization's Security page |
| SCIM tokens | org owner (admins can list them) | `/v1/organizations/:orgId/scim/tokens`, or the organization's Security page → SCIM |
| Group to role mappings | org owner (admins can read them) | `/v1/organizations/:orgId/group-roles` |

## Contents

- [Before you start](#before-you-start)
- [1. Add a SAML provider](#1-add-a-saml-provider)
- [2. Configure the identity provider](#2-configure-the-identity-provider)
  - [Okta](#okta)
  - [Microsoft Entra ID](#microsoft-entra-id)
  - [Google Workspace](#google-workspace)
  - [Keycloak](#keycloak)
- [3. Organization settings](#3-organization-settings)
- [4. SCIM provisioning](#4-scim-provisioning)
  - [Okta provisioning](#okta-provisioning)
  - [Entra ID provisioning](#entra-id-provisioning)
  - [Sign-in for SCIM-provisioned users](#sign-in-for-scim-provisioned-users)
- [5. Roles from groups](#5-roles-from-groups)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)

## Before you start

- Set `PUBLIC_BASE_URL` on the control plane to its external `https://`
  origin, such as `https://guard.example.com`. Every URL the identity provider
  is configured with is derived from it; SAML is unavailable without it, and
  changing it later means updating the identity provider.
- The browser must reach the control plane at that origin: the login cookie
  is set for it.
- Clocks: the assertion's validity window is checked with 2 minutes of skew
  for `NotBefore` only. Run NTP on the control plane hosts.

## 1. Add a SAML provider

Download the identity provider's **metadata XML** (each section below says
where). It must list a `SingleSignOnService` with the HTTP-Redirect binding
and a signing certificate; Guard Spec sends its AuthnRequest that way and
reads the certificates and the entity id from it.

```bash
CP=https://guard.example.com/v1
AUTH="Authorization: Bearer $ADMIN_TOKEN"   # an instance administrator
jq -n --rawfile md idp-metadata.xml '{
  type: "saml", display_name: "Okta", saml_metadata: $md,
  allowed_domains: ["example.com"], auto_provision: true,
  trust_email_for_linking: false, saml_groups_attribute: "groups"
}' | curl -s $CP/admin/identity-providers -H "$AUTH" -H 'Content-Type: application/json' -d @- | jq '{id, saml_sp}'
# {"id": "6f1c…", "saml_sp": {"entity_id": "https://guard.example.com/v1/auth/saml/6f1c…/metadata",
#   "acs_url": "https://guard.example.com/v1/auth/saml/6f1c…/acs", "metadata_url": "https://guard.example.com/v1/auth/saml/6f1c…/metadata"}}
```

The identity provider needs the provider's id first, so the usual order is:
create the SAML app at the IdP with placeholder URLs, download its metadata,
add the provider here, then put the real `entity_id` and `acs_url` into the
IdP app. Some identity providers can import
`<PUBLIC_BASE_URL>/v1/auth/saml/<id>/metadata` instead.

| Value | Where it goes at the identity provider |
|---|---|
| `entity_id` | Audience, SP entity id, Identifier, Client ID (Keycloak) |
| `acs_url` | Single sign-on URL, Reply URL, ACS URL, Recipient and Destination |
| NameID | A stable, unique value per person; identities match on it. Use the persistent format where you can choose (Guard Spec's AuthnRequest asks for it) |
| email | An attribute named `email` (or one of the usual names, or set `saml_email_attribute`); the NameID is used when it is an email and no attribute is sent |
| display name | Optional: `displayName` (or `saml_name_attribute`) |
| groups | Optional, for [roles from groups](#5-roles-from-groups): `groups` (or `saml_groups_attribute`) |

Guard Spec does not sign its AuthnRequests and does not accept encrypted
assertions: leave "require signed requests" and assertion encryption off at
the identity provider. The response or the assertion must be signed.

`auto_provision` creates an account at the first login for a new email in
`allowed_domains`; `trust_email_for_linking` lets a login take over an
existing account that has no password and no identity, which is what
SCIM-provisioned accounts need ([below](#sign-in-for-scim-provisioned-users)).

## 2. Configure the identity provider

### Okta

1. **Applications → Create App Integration → SAML 2.0**.
2. General settings: a name; then **Configure SAML**:
   - Single sign-on URL: the `acs_url`; keep **Use this for Recipient URL and
     Destination URL** checked.
   - Audience URI (SP Entity ID): the `entity_id`.
   - Name ID format: Persistent; Application username: Okta username or
     Email.
   - Attribute Statements: `email` → `user.email`; `displayName` →
     `user.displayName` (or `user.firstName + " " + user.lastName`).
   - Group Attribute Statements (for roles): name `groups`, filter
     **Matches regex** `.*`, or **Starts with** a prefix such as `guardspec-`
     to send only the groups you map.
3. Finish, then on **Sign On** open the metadata URL (or **View SAML setup
   instructions** → IDP metadata) and save the XML. Okta's metadata lists the
   HTTP-Redirect binding.
4. **Assignments**: assign the people or groups who may sign in.

### Microsoft Entra ID

1. **Enterprise applications → New application → Create your own
   application** → "Integrate any other application you don't find in the
   gallery (Non-gallery)".
2. **Single sign-on → SAML → Basic SAML Configuration**:
   - Identifier (Entity ID): the `entity_id`.
   - Reply URL (Assertion Consumer Service URL): the `acs_url`.
   - Leave Sign on URL, Relay State and Logout URL empty.
3. **Attributes & Claims**: the default claims already include
   `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   (`user.mail`) and `.../claims/name`, which Guard Spec reads. Make sure
   `user.mail` is set for every user, or change the claim's source to
   `user.userprincipalname` when the UPN is the email.
4. Groups (for roles): **Add a group claim** → "Groups assigned to the
   application"; source attribute **Group ID**. The claim name
   `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` is one
   Guard Spec reads by default. Entra sends group object ids, so the mapping's
   `group_key` is the object id. When a user is in more than 150 groups, Entra
   sends a link instead of the groups, which Guard Spec does not follow:
   "Groups assigned to the application" keeps the list short.
5. **SAML Certificates → Federation Metadata XML**: download it. The token
   signing default (sign the assertion) is accepted.
6. **Users and groups**: assign who may sign in.

### Google Workspace

1. Admin console → **Apps → Web and mobile apps → Add app → Add custom SAML
   app**.
2. Google Identity Provider details: **Download metadata** (option 1).
3. Service provider details:
   - ACS URL: the `acs_url`.
   - Entity ID: the `entity_id`.
   - Leave **Signed response** off or on (the assertion is signed either way).
   - Name ID format: PERSISTENT; Name ID: Basic Information → Primary email.
4. Attribute mapping: Primary email → `email`. Google has no single full-name
   field; map First name to `displayName` or leave the name out (the account
   then has no display name until someone sets one).
5. Groups (for roles): **Group membership** → select the groups, app
   attribute `groups`. Google sends the names of the selected groups the user
   belongs to; use those names as `group_key`.
6. **User access**: turn the app on for the organizational units or groups
   who may sign in.

Google Workspace does not provision custom SAML apps over SCIM: create the
users with `auto_provision` and `domain_join` or with invites.

### Keycloak

1. In the realm: **Clients → Create client**, client type **SAML**, Client ID
   = the `entity_id`.
2. Settings:
   - Valid redirect URIs: the `acs_url`.
   - Name ID format: `persistent` (or `email`); **Force name ID format** off.
   - **Sign documents** on (or Sign assertions on).
3. **Keys**: **Client signature required** off (Guard Spec's AuthnRequests
   are unsigned); **Encrypt assertions** off.
4. **Advanced → Assertion Consumer Service POST Binding URL**: the `acs_url`.
5. **Client scopes → <client>-dedicated → Add mapper → By configuration**:
   - User Property `email`, SAML Attribute Name `email`.
   - Optional: User Property `firstName` (or a User Attribute), SAML Attribute
     Name `displayName`.
   - Groups (for roles): Group list, Group attribute name `groups`,
     **Single Group Attribute** on, **Full group path** off.
6. Metadata: `https://<keycloak>/realms/<realm>/protocol/saml/descriptor`.

Keycloak has no built-in SCIM client; a SCIM plugin can push to Guard Spec's
SCIM endpoint as below.

A Keycloak test stack for the whole flow (`make sso-e2e`) is being added;
see the Makefile once it is there.

## 3. Organization settings

An org owner, in the organization's Security page or with
`PUT /v1/organizations/:orgId/security`:

- `allowed_login_methods`: add `saml:<provider id>`, and drop `password` to
  make SSO the only way in (keep a way in for yourself until SSO works; the
  request is refused if it would lock you out).
- `sso_satisfies_mfa`: SAML sessions count as SSO.
- `domain_join`: `{"domain":"example.com","provider_id":"<SAML provider id>","role":"member"}`
  adds new SSO users of the domain to the org. The domain must be in the
  provider's `allowed_domains`. A claimed domain also lets SCIM link existing
  accounts of the domain and disable them on deactivation (see below).
- `scim_revoke_keys` (default on): revoke the API keys a user created when
  SCIM deactivates them.

## 4. SCIM provisioning

1. An org owner creates a token, in the organization's Security page → SCIM,
   or:

   ```bash
   curl -s $CP/organizations/$ORG/scim/tokens -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"name":"Okta","expires_at":"2027-11-01T00:00:00Z"}' | jq -r .token
   # gss_…   (shown once; Guard Spec keeps only its SHA-256)
   ```

2. The identity provider gets the base URL `<PUBLIC_BASE_URL>/v1/scim/v2` and
   the token as a bearer token. The base URL is the same for every
   organization; the token names the org.
3. Rotate: create a second token, switch the identity provider to it, revoke
   the first (`DELETE .../scim/tokens/:id`). At most 20 active tokens.

What the identity provider's actions do:

| IdP action | Guard Spec |
|---|---|
| Assign a person | `POST /Users`: a new account without a password, or a link to an existing account that is already a member or in a domain the org claims; joins as `member` |
| Update a person | Email (only for accounts SCIM created), display name, external id |
| Unassign or suspend | `active: false`: memberships removed (role kept), API keys the user created revoked (`scim_revoke_keys`), and for accounts the org owns sessions revoked and the account disabled if it is in no other org |
| Reassign | `active: true`: membership back with the mapped or previous role |
| Delete | `DELETE /Users/:id`: deactivates, then forgets the SCIM record; the account is not deleted |
| Push groups | Groups and members, for [roles from groups](#5-roles-from-groups) |

### Okta provisioning

1. In the SAML app: **General → App Settings → Edit → Provisioning: SCIM**,
   save.
2. **Provisioning → Integration → Edit**:
   - SCIM connector base URL: `<PUBLIC_BASE_URL>/v1/scim/v2`.
   - Unique identifier field for users: `userName`.
   - Supported provisioning actions: Push New Users, Push Profile Updates,
     Push Groups.
   - Authentication Mode: **HTTP Header**; Authorization: the `gss_…` token.
   - **Test Connector Configuration**, save.
3. **Provisioning → To App → Edit**: enable Create Users, Update User
   Attributes, Deactivate Users.
4. **Push Groups**: push the groups you map to roles (by name).

Okta deactivates rather than deletes users (`PATCH` with `active: false`),
sends PATCH without a path for profile changes and removes group members
with `members[value eq "<id>"]`; Guard Spec accepts all of these.

### Entra ID provisioning

1. In the enterprise app: **Provisioning → Get started** (or New
   configuration), Provisioning Mode **Automatic**.
2. Admin Credentials: Tenant URL `<PUBLIC_BASE_URL>/v1/scim/v2`, Secret Token
   the `gss_…` token; **Test Connection**.
3. **Mappings → Provision Microsoft Entra ID Users**: `userName` must be an
   email (the default `userPrincipalName` when the UPN is the email; else map
   `mail`). The default `active` mapping
   (`Switch([IsSoftDeleted], , "False", "True", "True", "False")`) is what
   deactivates. Other default attributes are accepted and ignored.
4. **Mappings → Provision Microsoft Entra ID Groups**: keep `displayName`,
   `externalId` and `members`. Check which source attribute feeds
   `externalId`: when it is `objectId`, a SCIM mapping's `group_key` can be
   the same object id the SAML groups claim sends.
5. Settings: Scope **Sync only assigned users and groups**; set Provisioning
   Status **On**. Use **Provision on demand** to try one user.

Entra ID sends `"True"` / `"False"` strings for `active`, capitalized PATCH
ops (`Replace`, `Add`, `Remove`) and member lists in PATCH values; Guard Spec
accepts all of these. Soft-deleted users are deactivated; Entra deletes them
(`DELETE /Users/:id`) later.

### Sign-in for SCIM-provisioned users

A SCIM-created account has no password and no SSO identity yet. Its first
SSO login links the identity by email only when the provider has
`trust_email_for_linking` on; without it the login is refused with
`account_exists`. So, for the provider the users sign in through:

- turn `trust_email_for_linking` on, and
- set `allowed_domains` to your domains, so only emails your IdP controls
  can link.

An existing account SCIM linked (already a member, or in a claimed domain)
keeps its password and email. If it has a password, a SAML login with the
same email is refused with `account_exists`: the user signs in with the
password once and links the provider from **My account** (as for OIDC).
After that, SAML signs in to the same account.

## 5. Roles from groups

`PUT /v1/organizations/:orgId/group-roles` (owner) replaces the org's
mappings:

```bash
curl -s -X PUT $CP/organizations/$ORG/group-roles -H "$AUTH" -H 'Content-Type: application/json' -d '{"items":[
  {"provider_id": null,           "group_key": "guardspec-admins",  "role": "admin"},
  {"provider_id": null,           "group_key": "guardspec-viewers", "role": "viewer"},
  {"provider_id": "<SAML id>",    "group_key": "guardspec-admins",  "role": "admin"}
]}'
```

- `provider_id` null: SCIM groups of this org, matched by display name or
  external id.
- `provider_id` a SAML provider: values of its groups attribute (names for
  Okta, Google and Keycloak; object ids for Entra ID).
- `role`: `viewer`, `member` or `admin`. Owner is never granted or changed
  through a group. Matching is case-insensitive; the highest matching role
  wins.

Once an org maps groups, the identity provider decides the role:

- SCIM: an active SCIM user's role is the highest mapped role of their groups,
  or `member` when none matches; it changes as soon as group membership, a
  group's name or the mappings change.
- SAML: at every login through the provider, in each org the user already
  belongs to that maps at least one group of that provider, the role becomes
  the highest mapped role in the assertion, or `member` when none matches or
  no groups are sent. A login never adds a membership: memberships come from
  invites, `domain_join` or SCIM.
- An org without a mapping (SCIM, or for that SAML provider) keeps the roles
  set by hand.

A role set by hand in an org with mappings is overwritten at the next sync or
login, including downwards.

## Troubleshooting

A refused SAML login lands on `/ui/#/auth/callback?error=<code>`. The control
plane logs the reason (`saml login refused`, with `provider`, `code` and
`reason`), and the instance activity log has `login.failed` with the code.

| Code | Meaning | What to check |
|---|---|---|
| `sso_unavailable` | The provider is disabled, deleted or not SAML, `PUBLIC_BASE_URL` is not set, or its metadata cannot be read | Provider `enabled`; `PUBLIC_BASE_URL`; paste the metadata again. `GET .../start` answers 404 for an unknown or disabled provider and 503 `sso_unavailable` for a misconfigured one |
| `invalid_response` | Signature, issuer, `Destination`, `Recipient`, audience, status, assertion count, missing `AudienceRestriction`, unreadable validity times, expired `SubjectConfirmationData`, or an empty or too long NameID | The IdP's signing certificate is in the metadata (paste it again after a rotation); entity id and ACS URL at the IdP are exactly `saml_sp`'s (scheme, host, no trailing slash); assertion encryption off; the user is assigned to the app (an IdP error status also ends here) |
| `expired` | The assertion is outside its `NotBefore` / `NotOnOrAfter` window | Clocks on the IdP and the control plane |
| `email_not_verified` | No email in the assertion | The email attribute (or `saml_email_attribute`); the user has an email at the IdP |
| `invalid_state` | `InResponseTo` names no pending request (older than 10 minutes, already used, other provider), or the login started in another browser (the `gs_saml` cookie is missing) | Start the login again from Guard Spec; the browser reaches the control plane at `PUBLIC_BASE_URL`; over plain http the cookie is SameSite=Lax and is dropped unless the IdP is on the same site, so use https |
| `idp_initiated_disabled` | The response has no `InResponseTo`: the login was started from the IdP's dashboard | Start from the Guard Spec login page, or turn on `saml_allow_idp_initiated` (see [security notes](#security-notes)) |
| `replayed` | This assertion was already used | A back button or a resent form; start again |
| `domain_not_allowed` | The email's domain is not in `allowed_domains` | The provider's `allowed_domains` |
| `account_exists` | An account with this email exists and cannot be linked (it has a password or another identity, or `trust_email_for_linking` is off) | [Sign-in for SCIM-provisioned users](#sign-in-for-scim-provisioned-users) |
| `account_disabled` | The account is disabled (by an administrator, or by a SCIM deactivation) | Reactivate it at the IdP (SCIM) or as instance administrator |
| `not_provisioned` | No account for this email and `auto_provision` is off | Turn on `auto_provision`, invite the person, or provision them with SCIM |

After the callback, `POST /v1/auth/oidc/exchange` can answer `invalid_code`
(the one-time code lives 60 seconds) and the org can refuse the session with
`login_method_not_allowed` (add `saml:<id>` to `allowed_login_methods`) or
`mfa_required`.

SCIM errors are SCIM error bodies (`status`, `scimType`, `detail`):

| Status, `scimType` | Meaning |
|---|---|
| 401 | Missing, unknown, revoked or expired token (the header must be `Authorization: Bearer gss_…`) |
| 409 `uniqueness` | The `userName` or group name exists in the org, the account is already provisioned, another account has the new email, or "an account with this email exists outside this organization": invite it, or claim its domain with `domain_join` |
| 409 `mutability` | Deactivating the org's only owner: add another owner first |
| 400 `invalidFilter` | Only `attribute eq "value"` on the listed attributes |
| 400 `invalidValue` | A missing or invalid `userName` / `displayName`, `active` not a boolean, a member that is not a SCIM user of the org, too long values |
| 400 `invalidSyntax`, `invalidPath`, `tooMany` | Not a SCIM body or PatchOp, an unsupported group PATCH path, more than 1000 members in one request |
| 429 | More than 600 SCIM requests a minute from one address |

## Security notes

- **IdP-initiated login is off by default** (`saml_allow_idp_initiated`). A
  response without `InResponseTo` cannot be tied to the browser that
  receives it: anyone holding a valid response for their own account can
  post it from a page the victim visits and log the victim into the
  attacker's account (login CSRF), where whatever the victim does lands. The
  replay cache still stops a second use of the same assertion. Turn it on
  only if your users must start from the IdP's dashboard.
- **`trust_email_for_linking`** lets whoever controls an email at the
  identity provider take over an account with that email that has no password
  and no identity. Turn it on only for an identity provider that controls
  those addresses, together with `allowed_domains`.
- **`PUBLIC_BASE_URL` must be `https://`** in production. The login cookie is
  SameSite=None and Secure only then; the SP entity id, the ACS and the SCIM
  base URL all derive from it.
- **SCIM tokens** can create, change, deactivate and delete the org's users:
  only owners create and revoke them, they are shown once and stored as
  SHA-256; set `expires_at` and rotate them. A token's use is recorded
  (`last_used_at`, `scim_token_id` in the activity log).
- **Claiming a domain** with `domain_join` also lets the org's SCIM client
  link existing accounts of that domain, revoke their sessions and disable
  them when the org is their only one.
- **Deactivation and API keys**: with `scim_revoke_keys` on, the keys a user
  created are revoked with them. Keys created before migration 025 have no
  creator and stay; review them after the upgrade.
