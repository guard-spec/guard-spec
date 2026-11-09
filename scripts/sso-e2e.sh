#!/usr/bin/env bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# SSO end-to-end checks against a real identity provider (Keycloak), without
# a browser: curl plays the browser, with a cookie jar per user.
#
#   scripts/sso-e2e.sh          (or: make sso-e2e)
#
# 1. Starts the control plane built from this checkout, Postgres and
#    Keycloak (deploy/compose/sso/compose.yml) as the compose project
#    gs-sso-e2e, on ports of their own, with secrets generated for this run.
# 2. SAML 2.0: creates a SAML provider from Keycloak's IdP metadata, then the
#    matching Keycloak client (its entity id and ACS contain the provider id),
#    maps the Keycloak groups to org roles and runs SP-initiated logins:
#    /start -> Keycloak login form -> credentials -> SAMLResponse -> ACS ->
#    /ui/#/auth/callback?code= -> POST /v1/auth/oidc/exchange -> /v1/auth/me.
#    Negative checks: a replayed SAMLResponse, a response posted without the
#    browser's cookie, an IdP-initiated response while that is off (default),
#    and the replay of an accepted IdP-initiated response once it is allowed.
# 3. OIDC: the same with an OIDC provider and a Keycloak OIDC client.
# 4. SCIM 2.0: an org SCIM token, then an Okta-like sequence with curl
#    (create, get, filter, deactivate, reactivate, group with member, delete),
#    checking memberships, roles and the provisioned user's session.
# 5. Prints PASS / FAIL per check and removes the project (docker compose
#    down -v) unless SSO_E2E_KEEP=1.
#
# Requirements: docker with compose v2, curl, jq, openssl.
#
# Environment (defaults in brackets):
#   SSO_E2E_PROJECT        compose project [gs-sso-e2e]
#   SSO_E2E_CP_PORT        control plane on the host [28081]
#   SSO_E2E_CP_METRICS_PORT control plane metrics [28091]
#   SSO_E2E_PG_PORT        Postgres on the host [25432]
#   SSO_E2E_KC_PORT        Keycloak on the host and its public URL [28180]
#   SSO_E2E_KEEP           1 keeps the stack running afterwards [0]
#   SSO_E2E_NO_BUILD       1 skips building the control plane image [0]
#   SSO_E2E_TIMEOUT        seconds to wait for the services [300]
#
# Every password and key here is a throwaway test value: the Keycloak users'
# passwords are in deploy/compose/sso/realm-guardspec-test.json
# (alice-test-password and so on), the rest is generated for each run.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)

PROJECT=${SSO_E2E_PROJECT:-gs-sso-e2e}
CP_PORT=${SSO_E2E_CP_PORT:-28081}
CP_METRICS_PORT=${SSO_E2E_CP_METRICS_PORT:-28091}
PG_PORT=${SSO_E2E_PG_PORT:-25432}
KC_PORT=${SSO_E2E_KC_PORT:-28180}
KEEP=${SSO_E2E_KEEP:-0}
TIMEOUT=${SSO_E2E_TIMEOUT:-300}

CP="http://localhost:$CP_PORT"
KC="http://localhost:$KC_PORT"
REALM=guardspec-test
KC_REALM="$KC/realms/$REALM"
ORG=00000000-0000-0000-0000-000000000001 # the default org; the bootstrap admin owns it
ADMIN_EMAIL=admin@guardspec.test
IDP_INIT_NAME=guardspec # Keycloak's IdP-initiated SSO URL name of the SAML client

die() {
	echo "sso-e2e: $*" >&2
	exit 1
}

for cmd in docker curl jq openssl; do
	command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required"
done
docker compose version >/dev/null 2>&1 || die "docker compose (v2) is required"

W=$(mktemp -d "${TMPDIR:-/tmp}/sso-e2e.XXXXXX")
ENVF="$W/env"

compose() {
	docker compose -p "$PROJECT" --env-file "$ENVF" --project-directory "$ROOT" \
		-f "$ROOT/docker-compose.yml" -f "$ROOT/docker-compose.override.yml" \
		-f "$ROOT/deploy/compose/sso/compose.yml" "$@"
}

# ── Results ──────────────────────────────────────────────────────────────────

PASSES=0
FAILS=0
FAILED=""
CODE=000
LOC=""

pass() {
	PASSES=$((PASSES + 1))
	echo "PASS  $*"
}

fail() {
	FAILS=$((FAILS + 1))
	FAILED="$FAILED
  - $*"
	echo "FAIL  $*"
	echo "      last response: HTTP $CODE${LOC:+, Location: $LOC}"
	if [ -s "$W/body" ]; then
		echo "      body: $(head -c 500 "$W/body" | tr '\n' ' ')"
	fi
}

# check DESCRIPTION COMMAND...: PASS when the command succeeds.
check() {
	local desc=$1
	shift
	if "$@"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

summary() {
	echo
	echo "sso-e2e: $PASSES passed, $FAILS failed"
	if [ "$FAILS" -gt 0 ]; then
		echo "failed checks:$FAILED"
	fi
}

# abort DESCRIPTION: a failed check the rest depends on.
abort() {
	fail "$*"
	summary
	exit 1
}

cleanup() {
	local rc=$?
	if [ "$rc" -ne 0 ] && [ -f "$ENVF" ]; then
		echo
		echo "sso-e2e: last control plane and Keycloak log lines:"
		compose logs --no-color --tail 40 control-plane keycloak 2>/dev/null || true
	fi
	if [ "$KEEP" = 1 ]; then
		echo "sso-e2e: SSO_E2E_KEEP=1, the stack keeps running: control plane $CP, Keycloak $KC"
		echo "sso-e2e: test secrets are in $ENVF; remove with: docker compose -p $PROJECT down -v"
	else
		compose down -v --remove-orphans >/dev/null 2>&1 || true
		rm -rf "$W"
	fi
	exit "$rc"
}
trap cleanup EXIT

# ── HTTP helpers ─────────────────────────────────────────────────────────────

# req METHOD URL [curl options...]: CODE is the status, the body is in
# $W/body, LOC the Location header. Redirects are never followed.
req() {
	local method=$1 url=$2
	shift 2
	: >"$W/headers"
	CODE=$(curl -sS -X "$method" -o "$W/body" -D "$W/headers" -w '%{http_code}' --max-time 30 "$@" "$url") || CODE=000
	LOC=$(sed -n 's/^[Ll]ocation: *//p' "$W/headers" | tr -d '\r' | tail -n 1)
}

# api METHOD PATH TOKEN [JSON]: a control plane API call.
api() {
	local method=$1 path=$2 token=$3 data=${4:-}
	if [ -n "$data" ]; then
		req "$method" "$CP$path" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' --data "$data"
	else
		req "$method" "$CP$path" -H "Authorization: Bearer $token"
	fi
}

# scim METHOD PATH [JSON]: a SCIM call with the org's SCIM token.
scim() {
	local method=$1 path=$2 data=${3:-}
	if [ -n "$data" ]; then
		req "$method" "$CP/v1/scim/v2$path" -H "Authorization: Bearer $SCIM_TOKEN" \
			-H 'Content-Type: application/scim+json' --data "$data"
	else
		req "$method" "$CP/v1/scim/v2$path" -H "Authorization: Bearer $SCIM_TOKEN"
	fi
}

# kc METHOD PATH [JSON]: Keycloak admin REST API (a fresh admin token each
# time: admin-cli tokens live one minute).
kc() {
	local method=$1 path=$2 data=${3:-} token
	req POST "$KC/realms/master/protocol/openid-connect/token" --data-urlencode grant_type=password \
		--data-urlencode client_id=admin-cli --data-urlencode "username=admin" \
		--data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD"
	token=$(jq -r '.access_token // empty' "$W/body" 2>/dev/null || true)
	[ -n "$token" ] || return 1
	if [ -n "$data" ]; then
		req "$method" "$KC/admin/realms/$REALM$path" -H "Authorization: Bearer $token" \
			-H 'Content-Type: application/json' --data "$data"
	else
		req "$method" "$KC/admin/realms/$REALM$path" -H "Authorization: Bearer $token"
	fi
}

body() { jq -r "$1" "$W/body" 2>/dev/null || true; }
code_is() { [ "$CODE" = "$1" ]; }

html_unescape() {
	sed -e 's/&amp;/\&/g' -e 's/&quot;/"/g' -e 's/&#x2F;/\//g' -e 's/&#x3D;/=/g' -e 's/&#39;/'"'"'/g'
}

# form_action FILE PATTERN: the action of the first <form> tag matching PATTERN.
form_action() {
	tr '\n\r' '  ' <"$1" | grep -o '<form[^>]*>' | grep -i -- "$2" | head -n 1 |
		grep -o 'action="[^"]*"' | sed -e 's/^action="//' -e 's/"$//' | html_unescape
}

# input_value FILE NAME: the value of the input named NAME.
input_value() {
	tr '\n\r' '  ' <"$1" | grep -io "<input[^>]*name=\"$2\"[^>]*>" | head -n 1 |
		grep -o 'value="[^"]*"' | sed -e 's/^value="//' -e 's/"$//' | html_unescape
}

# ── Browser flows ────────────────────────────────────────────────────────────

# kc_login JAR USER PASSWORD: on a Keycloak page in $W/body, submits the login
# form if there is one (with an SSO session Keycloak answers without it).
kc_login() {
	local jar=$1 user=$2 password=$3 action
	if grep -q 'kc-form-login' "$W/body"; then
		action=$(form_action "$W/body" 'kc-form-login')
		[ -n "$action" ] || return 1
		req POST "$action" -b "$jar" -c "$jar" --data-urlencode "username=$user" \
			--data-urlencode "password=$password" --data-urlencode "credentialId="
	fi
}

# saml_extract FILE_PREFIX: reads Keycloak's auto-submit form in $W/body into
# FILE_PREFIX.response (the SAMLResponse, no newline), FILE_PREFIX.relay and
# SAML_ACS (the form action).
saml_extract() {
	local prefix=$1 response
	response=$(input_value "$W/body" SAMLResponse)
	[ -n "$response" ] || return 1
	printf '%s' "$response" >"$prefix.response"
	printf '%s' "$(input_value "$W/body" RelayState)" >"$prefix.relay"
	SAML_ACS=$(form_action "$W/body" 'post')
	[ -n "$SAML_ACS" ]
}

# saml_post JAR FILE_PREFIX: posts a saved SAMLResponse to the ACS like the
# auto-submit form does. JAR "" posts without cookies.
saml_post() {
	local jar=$1 prefix=$2
	local args=(--data-urlencode "SAMLResponse@$prefix.response")
	if [ -s "$prefix.relay" ]; then
		args+=(--data-urlencode "RelayState@$prefix.relay")
	fi
	if [ -n "$jar" ]; then
		args+=(-b "$jar" -c "$jar")
	fi
	req POST "$SAML_ACS" "${args[@]}"
}

# callback_code: the one-time code of a /ui/#/auth/callback?code= redirect.
callback_code() {
	case "$LOC" in
	*"/ui/#/auth/callback?code="*) printf '%s' "${LOC#*code=}" ;;
	*) return 1 ;;
	esac
}

callback_error() {
	case "$LOC" in
	*"/ui/#/auth/callback?error="*) printf '%s' "${LOC#*error=}" ;;
	*) printf '' ;;
	esac
}

# exchange CODE: POST /v1/auth/oidc/exchange; sets SESSION_TOKEN.
exchange() {
	SESSION_TOKEN=""
	req POST "$CP/v1/auth/oidc/exchange" -H 'Content-Type: application/json' \
		--data "$(jq -nc --arg c "$1" '{code: $c}')"
	code_is 200 || return 1
	SESSION_TOKEN=$(body '.token // empty')
	[ -n "$SESSION_TOKEN" ]
}

# saml_browser_login USER PASSWORD: SP-initiated login up to the SAMLResponse
# page; the response is saved to $W/saml-USER.*. Uses the jar $W/jar-USER.
saml_browser_login() {
	local user=$1 password=$2 jar="$W/jar-$1"
	req GET "$CP/v1/auth/saml/$SAML_ID/start" -b "$jar" -c "$jar"
	code_is 302 && [[ $LOC == "$KC_REALM/"* ]] || return 1
	grep -qi 'set-cookie: gs_saml=' "$W/headers" || return 1
	req GET "$LOC" -b "$jar" -c "$jar"
	code_is 200 || return 1
	kc_login "$jar" "$user" "$password" || return 1
	code_is 200 || return 1
	saml_extract "$W/saml-$user"
}

# saml_login USER PASSWORD: a full SAML login; sets SESSION_TOKEN.
saml_login() {
	local user=$1 password=$2
	SESSION_TOKEN=""
	saml_browser_login "$user" "$password" || return 1
	saml_post "$W/jar-$user" "$W/saml-$user"
	code_is 302 || return 1
	local c
	c=$(callback_code) || return 1
	exchange "$c"
}

# idp_initiated USER PASSWORD PREFIX: Keycloak's IdP-initiated SSO URL of the
# SAML client; the SAMLResponse is saved to PREFIX.*.
idp_initiated() {
	local user=$1 password=$2 prefix=$3 jar="$W/jar-$1"
	req GET "$KC_REALM/protocol/saml/clients/$IDP_INIT_NAME" -b "$jar" -c "$jar"
	if code_is 302; then
		req GET "$LOC" -b "$jar" -c "$jar"
	fi
	code_is 200 || return 1
	kc_login "$jar" "$user" "$password" || return 1
	saml_extract "$prefix"
}

# oidc_login USER PASSWORD: a full OIDC login; sets SESSION_TOKEN.
oidc_login() {
	local user=$1 password=$2 jar="$W/jar-oidc-$1"
	SESSION_TOKEN=""
	req GET "$CP/v1/auth/oidc/$OIDC_ID/start" -b "$jar" -c "$jar"
	code_is 302 && [[ $LOC == "$KC_REALM/"* ]] || return 1
	req GET "$LOC" -b "$jar" -c "$jar"
	code_is 200 || return 1
	kc_login "$jar" "$user" "$password" || return 1
	code_is 302 && [[ $LOC == "$CP/v1/auth/oidc/$OIDC_ID/callback"* ]] || return 1
	req GET "$LOC" -b "$jar" -c "$jar"
	code_is 302 || return 1
	local c
	c=$(callback_code) || return 1
	exchange "$c"
}

# me_is TOKEN EMAIL: /v1/auth/me answers for EMAIL.
me_is() {
	api GET /v1/auth/me "$1"
	code_is 200 && [ "$(body .email)" = "$2" ]
}

# member_role EMAIL: the org role of EMAIL ("" when not a member).
member_role() {
	api GET "/v1/organizations/$ORG/members?q=$1" "$ADMIN_TOKEN"
	code_is 200 || return 1
	jq -r --arg e "$1" '.items[] | select(.email == $e) | .role' "$W/body"
}

# role_is EMAIL ROLE: ROLE "" means not a member. A failed listing fails.
role_is() {
	local role
	role=$(member_role "$1") || return 1
	[ "$role" = "$2" ]
}

# ── Stack ────────────────────────────────────────────────────────────────────

port_busy() {
	if command -v lsof >/dev/null 2>&1; then
		lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
	else
		curl -s -o /dev/null --max-time 2 "http://localhost:$1/"
	fi
}

wait_for() {
	local what=$1 url=$2 waited=0
	printf 'sso-e2e: waiting for %s ' "$what"
	until curl -fsS -o /dev/null --max-time 5 "$url" 2>/dev/null; do
		if [ "$waited" -ge "$TIMEOUT" ]; then
			echo
			compose ps -a >&2 || true
			abort "$what is up ($url)"
		fi
		printf '.'
		sleep 3
		waited=$((waited + 3))
	done
	echo " up"
}

ADMIN_PASSWORD=$(openssl rand -hex 16)
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 16)
OIDC_SECRET_KEYCLOAK=$(openssl rand -hex 24)
umask 077
cat >"$ENVF" <<EOF
GUARD_ENV=dev
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
PUBLIC_BASE_URL=$CP
ALLOWED_ORIGINS=$CP
CONTROL_PLANE_PORT=$CP_PORT
CONTROL_PLANE_METRICS_PORT=$CP_METRICS_PORT
POSTGRES_PORT=$PG_PORT
KEYCLOAK_PORT=$KC_PORT
KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASSWORD
OIDC_SECRET_KEYCLOAK=$OIDC_SECRET_KEYCLOAK
EOF
umask 022

# A previous run of this project that was kept (SSO_E2E_KEEP=1) or interrupted.
compose down -v --remove-orphans >/dev/null 2>&1 || true
for p in "$CP_PORT" "$CP_METRICS_PORT" "$PG_PORT" "$KC_PORT"; do
	if port_busy "$p"; then
		die "port $p is in use; pick other ports with SSO_E2E_CP_PORT, SSO_E2E_CP_METRICS_PORT, SSO_E2E_PG_PORT, SSO_E2E_KC_PORT"
	fi
done

echo "sso-e2e: project $PROJECT, control plane $CP, Keycloak $KC"
if [ "${SSO_E2E_NO_BUILD:-0}" != 1 ]; then
	echo "sso-e2e: building the control plane image from this checkout"
	compose build control-plane >"$W/build.log" 2>&1 || {
		tail -n 30 "$W/build.log" >&2
		die "the control plane image did not build"
	}
fi
compose up -d control-plane keycloak keycloak-loopback >"$W/up.log" 2>&1 || {
	cat "$W/up.log" >&2
	die "docker compose up failed"
}
wait_for "the control plane" "$CP/health"
wait_for "Keycloak" "$KC_REALM/.well-known/openid-configuration"

echo
echo "== Setup"
req POST "$CP/v1/auth/login" -H 'Content-Type: application/json' \
	--data "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{email: $e, password: $p}')"
ADMIN_TOKEN=$(body '.token // empty')
[ -n "$ADMIN_TOKEN" ] || abort "the bootstrap admin logs in with a password"
pass "the bootstrap admin logs in with a password"

# The control plane reaches Keycloak at its public URL (keycloak-loopback).
check "keycloak-loopback forwards the control plane's localhost:$KC_PORT to Keycloak" \
	compose exec -T keycloak-loopback wget -q -O /dev/null "$KC_REALM/.well-known/openid-configuration"

# ── SAML ─────────────────────────────────────────────────────────────────────

echo
echo "== SAML 2.0 (SP-initiated)"
req GET "$KC_REALM/protocol/saml/descriptor"
code_is 200 && grep -q 'IDPSSODescriptor' "$W/body" || abort "Keycloak serves the realm's SAML IdP metadata"
IDP_METADATA=$(cat "$W/body")

api POST /v1/admin/identity-providers "$ADMIN_TOKEN" "$(jq -nc --arg md "$IDP_METADATA" '{
	type: "saml", display_name: "Keycloak SAML (test)", saml_metadata: $md,
	allowed_domains: ["example.test"], auto_provision: true, trust_email_for_linking: true,
	saml_groups_attribute: "groups", enabled: true}')"
SAML_ID=$(body '.id // empty')
SAML_ENTITY=$(body '.saml_sp.entity_id // empty')
SAML_ACS_URL=$(body '.saml_sp.acs_url // empty')
code_is 201 && [ -n "$SAML_ID" ] || abort "a SAML provider is created from the Keycloak metadata"
pass "a SAML provider is created from the Keycloak metadata ($SAML_ID)"
check "its SP entity id and ACS use PUBLIC_BASE_URL and the provider id" \
	test "$SAML_ENTITY" = "$CP/v1/auth/saml/$SAML_ID/metadata" -a "$SAML_ACS_URL" = "$CP/v1/auth/saml/$SAML_ID/acs"

req GET "$CP/v1/auth/saml/$SAML_ID/metadata"
check "the SP metadata names the entity id and the ACS" \
	eval 'grep -qF "entityID=\"$SAML_ENTITY\"" "$W/body" && grep -qF "Location=\"$SAML_ACS_URL\"" "$W/body"'

kc POST /clients "$(jq -nc --arg id "$SAML_ENTITY" --arg acs "$SAML_ACS_URL" --arg idp "$IDP_INIT_NAME" '{
	clientId: $id, name: "Guard Spec (SAML, test)", protocol: "saml", enabled: true,
	redirectUris: [$acs], frontchannelLogout: false,
	attributes: {
		"saml.assertion.signature": "true", "saml.server.signature": "true",
		"saml.client.signature": "false", "saml.encrypt": "false",
		"saml.signature.algorithm": "RSA_SHA256",
		"saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
		"saml.authnstatement": "true", "saml.force.post.binding": "true",
		"saml_force_name_id_format": "true", "saml_name_id_format": "persistent",
		"saml_assertion_consumer_url_post": $acs, "saml_idp_initiated_sso_url_name": $idp},
	protocolMappers: [
		{name: "email", protocol: "saml", protocolMapper: "saml-user-property-mapper",
		 config: {"user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic"}},
		{name: "displayName", protocol: "saml", protocolMapper: "saml-user-property-mapper",
		 config: {"user.attribute": "firstName", "attribute.name": "displayName", "attribute.nameformat": "Basic"}},
		{name: "groups", protocol: "saml", protocolMapper: "saml-group-membership-mapper",
		 config: {"attribute.name": "groups", "attribute.nameformat": "Basic", "full.path": "false", "single": "true"}}]}')" || true
code_is 201 || abort "the Keycloak SAML client is created with the provider's entity id and ACS"
pass "the Keycloak SAML client is created with the provider's entity id and ACS"

# Group -> role: example.test users join the org as viewer at their first
# SSO login (domain_join), then their Keycloak groups set the role.
api GET "/v1/organizations/$ORG/security" "$ADMIN_TOKEN"
code_is 200 || abort "the org security settings can be read"
api PUT "/v1/organizations/$ORG/security" "$ADMIN_TOKEN" \
	"$(jq -c --arg p "$SAML_ID" '.domain_join = [{domain: "example.test", provider_id: $p, role: "viewer"}]' "$W/body")"
check "the org claims example.test for the SAML provider (domain_join, role viewer)" code_is 200

group_roles_saml() {
	jq -nc --arg p "$SAML_ID" '[{provider_id: $p, group_key: "gs-admins", role: "admin"},
		{provider_id: $p, group_key: "gs-members", role: "member"}]'
}
api PUT "/v1/organizations/$ORG/group-roles" "$ADMIN_TOKEN" "$(jq -nc --argjson i "$(group_roles_saml)" '{items: $i}')"
check "SAML group roles are set (gs-admins -> admin, gs-members -> member)" code_is 200

if saml_login alice alice-test-password; then
	pass "alice logs in with SAML (start -> Keycloak -> ACS -> code -> exchange -> session token)"
	ALICE_TOKEN=$SESSION_TOKEN
	check "/v1/auth/me shows alice@example.test with the SAML identity" \
		eval 'me_is "$ALICE_TOKEN" alice@example.test && [ "$(body "[.identities[].provider_id] | index(\"$SAML_ID\") != null")" = true ]'
	check "alice's group gs-admins made her an org admin" role_is alice@example.test admin
else
	fail "alice logs in with SAML (start -> Keycloak -> ACS -> code -> exchange -> session token)"
fi

saml_post "$W/jar-alice" "$W/saml-alice"
check "replaying alice's SAMLResponse is refused ($(callback_error))" \
	eval 'code_is 302 && [ -n "$(callback_error)" ] && ! callback_code >/dev/null'

# Login CSRF: the response must come back to the browser that started it.
if saml_browser_login bob bob-test-password; then
	saml_post "" "$W/saml-bob"
	check "a SAMLResponse posted without the browser's gs_saml cookie is refused ($(callback_error))" \
		test "$(callback_error)" = invalid_state
else
	fail "bob reaches the SAMLResponse page"
fi

if saml_login bob bob-test-password; then
	pass "bob logs in with SAML"
	check "/v1/auth/me shows bob@example.test" me_is "$SESSION_TOKEN" bob@example.test
	check "bob's group gs-members made him an org member" role_is bob@example.test member
else
	fail "bob logs in with SAML"
fi

# The IdP decides once groups are mapped: alice leaves gs-admins in Keycloak
# and her next login makes her a member (the default role).
kc GET "/users?username=alice&exact=true" && ALICE_KC=$(body '.[0].id // empty')
kc GET "/groups?search=gs-admins&exact=true" && ADMINS_KC=$(body '.[] | select(.name == "gs-admins") | .id')
if [ -n "${ALICE_KC:-}" ] && [ -n "${ADMINS_KC:-}" ] && kc DELETE "/users/$ALICE_KC/groups/$ADMINS_KC" && code_is 204; then
	if saml_login alice alice-test-password; then
		check "alice, removed from gs-admins in Keycloak, is a member after her next SAML login" \
			role_is alice@example.test member
	else
		fail "alice logs in with SAML again (Keycloak session)"
	fi
	kc PUT "/users/$ALICE_KC/groups/$ADMINS_KC" || true
else
	fail "alice is removed from gs-admins with the Keycloak admin API"
fi

echo
echo "== SAML 2.0 (IdP-initiated)"
if idp_initiated alice alice-test-password "$W/idp1"; then
	check "Keycloak's IdP-initiated response has no InResponseTo" \
		eval 'openssl base64 -d -A <"$W/idp1.response" >"$W/idp1.xml" && grep -q "Assertion" "$W/idp1.xml" && ! grep -q InResponseTo "$W/idp1.xml"'
	saml_post "$W/jar-alice" "$W/idp1"
	check "an IdP-initiated response is refused by default ($(callback_error))" \
		test "$(callback_error)" = idp_initiated_disabled
else
	fail "Keycloak returns an IdP-initiated SAMLResponse for alice"
fi

api PUT "/v1/admin/identity-providers/$SAML_ID" "$ADMIN_TOKEN" '{"saml_allow_idp_initiated": true}'
check "IdP-initiated logins can be allowed on the provider" code_is 200
if idp_initiated alice alice-test-password "$W/idp2"; then
	saml_post "$W/jar-alice" "$W/idp2"
	if c=$(callback_code) && exchange "$c"; then
		pass "an allowed IdP-initiated login gets a session"
	else
		fail "an allowed IdP-initiated login gets a session"
	fi
	saml_post "$W/jar-alice" "$W/idp2"
	check "replaying an accepted IdP-initiated response is refused ($(callback_error))" \
		test "$(callback_error)" = replayed
else
	fail "Keycloak returns a second IdP-initiated SAMLResponse"
fi
api PUT "/v1/admin/identity-providers/$SAML_ID" "$ADMIN_TOKEN" '{"saml_allow_idp_initiated": false}'
check "IdP-initiated logins are turned off again" code_is 200

# ── OIDC ─────────────────────────────────────────────────────────────────────

echo
echo "== OIDC"
api POST /v1/admin/identity-providers "$ADMIN_TOKEN" "$(jq -nc --arg iss "$KC_REALM" '{
	type: "oidc", display_name: "Keycloak OIDC (test)", issuer: $iss, client_id: "guard-spec-oidc",
	client_secret_env: "OIDC_SECRET_KEYCLOAK", allowed_domains: ["example.test"], auto_provision: true,
	enabled: true}')"
OIDC_ID=$(body '.id // empty')
if code_is 201 && [ -n "$OIDC_ID" ]; then
	pass "an OIDC provider is created for the Keycloak realm ($OIDC_ID)"
	kc POST /clients "$(jq -nc --arg cb "$CP/v1/auth/oidc/$OIDC_ID/callback" --arg s "$OIDC_SECRET_KEYCLOAK" '{
		clientId: "guard-spec-oidc", name: "Guard Spec (OIDC, test)", protocol: "openid-connect",
		enabled: true, publicClient: false, secret: $s, redirectUris: [$cb],
		standardFlowEnabled: true, directAccessGrantsEnabled: false, implicitFlowEnabled: false,
		attributes: {"pkce.code.challenge.method": "S256"}}')" || true
	check "the Keycloak OIDC client is created with the provider's callback" code_is 201
	if oidc_login dave dave-test-password; then
		pass "dave logs in with OIDC (start -> Keycloak -> callback -> code -> exchange -> session token)"
		check "/v1/auth/me shows dave@example.test" me_is "$SESSION_TOKEN" dave@example.test
	else
		fail "dave logs in with OIDC (start -> Keycloak -> callback -> code -> exchange -> session token)"
	fi
else
	fail "an OIDC provider is created for the Keycloak realm"
fi

# ── SCIM ─────────────────────────────────────────────────────────────────────

echo
echo "== SCIM 2.0"
api POST "/v1/organizations/$ORG/scim/tokens" "$ADMIN_TOKEN" '{"name": "sso-e2e"}'
SCIM_TOKEN=$(body '.token // empty')
code_is 201 && [ -n "$SCIM_TOKEN" ] || abort "an org SCIM token is created"
pass "an org SCIM token is created"

req GET "$CP/v1/scim/v2/Users" -H 'Authorization: Bearer gss_not-a-token'
check "a wrong SCIM token gets 401" code_is 401
scim GET /ServiceProviderConfig
check "GET /ServiceProviderConfig" eval 'code_is 200 && [ "$(body .patch.supported)" = true ]'

scim POST /Users '{
	"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
	"userName": "carol@example.test", "externalId": "kc-carol",
	"name": {"givenName": "Carol", "familyName": "Provisioned"},
	"emails": [{"value": "carol@example.test", "type": "work", "primary": true}],
	"active": true}'
CAROL=$(body '.id // empty')
code_is 201 && [ -n "$CAROL" ] || abort "SCIM creates carol@example.test"
pass "SCIM creates carol@example.test ($CAROL)"
scim GET "/Users/$CAROL"
check "SCIM GET /Users/:id returns her" eval 'code_is 200 && [ "$(body .userName)" = carol@example.test ] && [ "$(body .active)" = true ]'
scim GET "/Users?filter=$(jq -rn '"userName eq \"carol@example.test\""|@uri')"
check "SCIM filter userName eq finds her" eval 'code_is 200 && [ "$(body .totalResults)" = 1 ]'
check "carol is an org member" role_is carol@example.test member

CAROL_TOKEN=""
if saml_login carol carol-test-password; then
	CAROL_TOKEN=$SESSION_TOKEN
	pass "carol (provisioned, no password) logs in with SAML (linked by the trusted email)"
	api GET "/v1/organizations/$ORG" "$CAROL_TOKEN"
	check "carol's session can read the org" code_is 200
else
	fail "carol (provisioned, no password) logs in with SAML (linked by the trusted email)"
fi

scim PATCH "/Users/$CAROL" '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	"Operations": [{"op": "replace", "value": {"active": false}}]}'
check "SCIM PATCH active=false (Okta style)" eval 'code_is 200 && [ "$(body .active)" = false ]'
check "carol lost her org membership" role_is carol@example.test ""
if [ -n "$CAROL_TOKEN" ]; then
	api GET /v1/auth/me "$CAROL_TOKEN"
	check "carol's session was revoked (/v1/auth/me 401)" code_is 401
fi

scim PATCH "/Users/$CAROL" '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	"Operations": [{"op": "replace", "path": "active", "value": true}]}'
check "SCIM PATCH active=true reactivates her" eval 'code_is 200 && [ "$(body .active)" = true ]'
check "carol is an org member again" role_is carol@example.test member
if saml_login carol carol-test-password; then
	pass "carol logs in with SAML again after the reactivation"
else
	fail "carol logs in with SAML again after the reactivation"
fi

api PUT "/v1/organizations/$ORG/group-roles" "$ADMIN_TOKEN" "$(jq -nc --argjson i "$(group_roles_saml)" \
	'{items: ($i + [{provider_id: null, group_key: "gs-scim-admins", role: "admin"}])}')"
check "a SCIM group role is set (gs-scim-admins -> admin)" code_is 200
scim POST /Groups "$(jq -nc --arg u "$CAROL" '{schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
	displayName: "gs-scim-admins", externalId: "kc-gs-scim-admins", members: [{value: $u}]}')"
GROUP=$(body '.id // empty')
if code_is 201 && [ -n "$GROUP" ]; then
	pass "SCIM creates the group gs-scim-admins with carol as member"
	check "the group's members list carol" eval '[ "$(body ".members | map(.value) | index(\"$CAROL\") != null")" = true ]'
	check "the group made carol an org admin" role_is carol@example.test admin
	scim DELETE "/Groups/$GROUP"
	check "SCIM DELETE /Groups/:id" code_is 204
	scim GET "/Groups/$GROUP"
	check "the deleted group is gone (404)" code_is 404
	check "without a matching group carol falls back to the default role member" role_is carol@example.test member
else
	fail "SCIM creates the group gs-scim-admins with carol as member"
fi

scim DELETE "/Users/$CAROL"
check "SCIM DELETE /Users/:id" code_is 204
check "carol is no org member after the delete" role_is carol@example.test ""
scim GET "/Users/$CAROL"
check "the deleted user is gone from SCIM (404)" code_is 404

summary
[ "$FAILS" -eq 0 ]
