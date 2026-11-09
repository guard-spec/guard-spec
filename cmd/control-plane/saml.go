// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// SSO with SAML 2.0 (migration 025), next to OIDC (oidc.go).
//
// A SAML provider is an identity provider of type saml: the administrator
// pastes the IdP's metadata, which gives its entity id, its SSO URL
// (HTTP-Redirect binding) and its signing certificates. Guard Spec is the
// service provider:
//
//	entity id (audience)  <PUBLIC_BASE_URL>/v1/auth/saml/<id>/metadata
//	ACS (HTTP-POST)       <PUBLIC_BASE_URL>/v1/auth/saml/<id>/acs
//
// GET /start stores the AuthnRequest id for 10 minutes, bound to the browser
// by a random cookie (login CSRF), and redirects to the IdP. POST /acs
// accepts a response only if:
//
//   - the Response or every Assertion is signed by a certificate of the
//     metadata (gosaml2 and goxmldsig verify the signature and use only the
//     signed element, which defeats XML signature wrapping), with exactly
//     one assertion;
//   - the issuer is the IdP's entity id, the Destination and Recipient are
//     the ACS URL, the audience is the SP entity id (an AudienceRestriction
//     is required), and NotBefore / NotOnOrAfter hold (2 minutes of skew for
//     NotBefore);
//   - InResponseTo names a request this browser started; an unsolicited
//     (IdP-initiated) response only when the provider allows it, which is
//     off by default: it cannot be bound to a browser;
//   - the assertion id was not used before (saml_assertions keeps it until
//     the assertion expires).
//
// The NameID is the subject; the email, name and groups come from
// attributes. The rest is the OIDC flow: ssoUser links or creates the user,
// the browser gets a one-time code, POST /auth/oidc/exchange turns it into a
// session (method saml:<id>). Encrypted assertions and single logout are not
// supported.

const (
	samlStateTTL  = 10 * time.Minute
	samlSkew      = 2 * time.Minute
	samlCookie    = "gs_saml"
	samlMaxBody   = 1 << 20 // base64 SAMLResponse
	maxSAMLGroups = 200
)

// Attribute names IdPs commonly use, tried when the provider names none.
var (
	samlEmailAttrs = []string{"email", "mail", "emailaddress", "Email",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}
	samlNameAttrs = []string{"displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "urn:oid:2.16.840.1.113730.3.1.241", "cn"}
	samlGroupAttrs = []string{"groups", "memberOf", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
		"Role", "role"}
)

// samlSPInfo is what the IdP is configured with.
type samlSPInfo struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"metadata_url"`
}

func (id *identity) spInfo(pid uuid.UUID) samlSPInfo {
	base := id.publicURL + "/v1/auth/saml/" + pid.String()
	return samlSPInfo{EntityID: base + "/metadata", ACSURL: base + "/acs", MetadataURL: base + "/metadata"}
}

// withSP adds the service provider's values to a SAML provider's answer.
func (id *identity) withSP(p *providerRow) {
	if p.Type == "saml" && id.publicURL != "" {
		sp := id.spInfo(p.ID)
		p.SAMLSP = &sp
	}
}

// idpMetadata is what Guard Spec uses from an IdP's metadata.
type idpMetadata struct {
	entityID string
	ssoURL   string
	certs    []*x509.Certificate
}

// parseIdPMetadata reads an EntityDescriptor (or the first one of an
// EntitiesDescriptor) with an IDPSSODescriptor.
func parseIdPMetadata(raw string) (idpMetadata, error) {
	var md idpMetadata
	var ed types.EntityDescriptor
	if err := xml.Unmarshal([]byte(raw), &ed); err != nil || ed.IDPSSODescriptor == nil {
		var set struct {
			Entities []types.EntityDescriptor `xml:"EntityDescriptor"`
		}
		if err2 := xml.Unmarshal([]byte(raw), &set); err2 != nil || len(set.Entities) == 0 {
			return md, errors.New("saml_metadata is not SAML IdP metadata (an EntityDescriptor with an IDPSSODescriptor)")
		}
		ed = set.Entities[0]
		if ed.IDPSSODescriptor == nil {
			return md, errors.New("saml_metadata has no IDPSSODescriptor")
		}
	}
	md.entityID = strings.TrimSpace(ed.EntityID)
	if md.entityID == "" || len(md.entityID) > 2048 {
		return md, errors.New("saml_metadata: the entityID is missing or too long")
	}
	for _, s := range ed.IDPSSODescriptor.SingleSignOnServices {
		if s.Binding == saml2.BindingHttpRedirect {
			md.ssoURL = strings.TrimSpace(s.Location)
			break
		}
	}
	if md.ssoURL == "" {
		return md, errors.New("saml_metadata has no SingleSignOnService with the HTTP-Redirect binding")
	}
	if err := validIssuer(md.ssoURL); err != nil {
		return md, fmt.Errorf("saml_metadata: the SSO URL: %w", err)
	}
	for _, kd := range ed.IDPSSODescriptor.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
			if err != nil {
				return md, errors.New("saml_metadata: a signing certificate is not base64")
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return md, fmt.Errorf("saml_metadata: a signing certificate cannot be read: %v", err)
			}
			md.certs = append(md.certs, cert)
		}
	}
	if len(md.certs) == 0 {
		return md, errors.New("saml_metadata has no signing certificate")
	}
	return md, nil
}

func validAttrName(s string) bool {
	return s == "" || (len(s) <= 256 && !strings.ContainsAny(s, " \t\r\n\"<>"))
}

// validateSAML checks a SAML provider and takes the issuer from its metadata.
func (p *providerRow) validateSAML() error {
	p.SAMLMetadata = strings.TrimSpace(p.SAMLMetadata)
	if p.SAMLMetadata == "" {
		return errors.New("saml_metadata is required: paste the identity provider's metadata XML")
	}
	if len(p.SAMLMetadata) > 262144 {
		return errors.New("saml_metadata is too large (at most 256 KiB)")
	}
	md, err := parseIdPMetadata(p.SAMLMetadata)
	if err != nil {
		return err
	}
	p.Issuer = md.entityID
	p.ClientID, p.ClientSecretEnv, p.Scopes = "", "", []string{}
	for _, a := range []*string{&p.SAMLEmailAttribute, &p.SAMLNameAttribute, &p.SAMLGroupsAttribute} {
		*a = strings.TrimSpace(*a)
		if !validAttrName(*a) {
			return fmt.Errorf("attribute name %q is not valid", *a)
		}
	}
	return nil
}

// ── Service provider cache ───────────────────────────────────────────────────

type samlProvider struct {
	row providerRow
	sp  *saml2.SAMLServiceProvider
}

func (id *identity) forgetSAML(pid uuid.UUID) {
	id.oidcMu.Lock()
	delete(id.samlSPs, pid)
	id.oidcMu.Unlock()
}

// samlSP returns the enabled SAML provider pid.
func (id *identity) samlSP(ctx context.Context, pid uuid.UUID) (*samlProvider, error) {
	row, err := id.loadProvider(ctx, pid)
	if err != nil {
		return nil, err
	}
	if !row.Enabled || row.Type != "saml" {
		return nil, errProviderUnavailable
	}
	if id.publicURL == "" {
		return nil, errors.New("PUBLIC_BASE_URL is not set; SAML needs it for the ACS url")
	}
	id.oidcMu.Lock()
	cached, ok := id.samlSPs[pid]
	id.oidcMu.Unlock()
	if ok && cached.row.UpdatedAt.Equal(row.UpdatedAt) {
		return cached, nil
	}
	md, err := parseIdPMetadata(row.SAMLMetadata)
	if err != nil {
		return nil, err
	}
	p, err := buildSAMLProvider(row, md, id.spInfo(pid), id.samlClock)
	if err != nil {
		return nil, err
	}
	id.oidcMu.Lock()
	id.samlSPs[pid] = p
	id.oidcMu.Unlock()
	return p, nil
}

// buildSAMLProvider configures gosaml2 for one provider; clock nil is the
// real clock.
func buildSAMLProvider(row providerRow, md idpMetadata, info samlSPInfo, clock *dsig.Clock) (*samlProvider, error) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      md.ssoURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      md.entityID,
		AssertionConsumerServiceURL: info.ACSURL,
		ServiceProviderIssuer:       info.EntityID,
		AudienceURI:                 info.EntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: md.certs},
		NameIdFormat:                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		AllowMissingAttributes:      true,
		Clock:                       dsig.NewRealClock(),
		MaximumDecompressedBodySize: samlMaxBody,
	}
	if clock != nil {
		sp.Clock = clock
	}
	return &samlProvider{row: row, sp: sp}, nil
}

// samlMetadata is the service provider's metadata, for the IdP.
func (id *identity) samlMetadata(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": errProviderUnavailable.Error()})
	}
	row, err := id.loadProvider(c.Context(), pid)
	if err != nil || row.Type != "saml" {
		return c.Status(404).JSON(fiber.Map{"error": errProviderUnavailable.Error()})
	}
	if id.publicURL == "" {
		return auth.Deny(c, fiber.StatusServiceUnavailable, "sso_unavailable", "PUBLIC_BASE_URL is not set")
	}
	info := id.spInfo(pid)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="`)
	_ = xml.EscapeText(&b, []byte(info.EntityID))
	b.WriteString(`">` + "\n" + `  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" ` +
		`protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + "\n")
	b.WriteString(`    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>` + "\n")
	b.WriteString(`    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>` + "\n")
	b.WriteString(`    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="`)
	_ = xml.EscapeText(&b, []byte(info.ACSURL))
	b.WriteString(`" index="0" isDefault="true"/>` + "\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n")
	c.Set(fiber.HeaderContentType, "application/samlmetadata+xml")
	return c.SendString(b.String())
}

// ── Login ────────────────────────────────────────────────────────────────────

func (id *identity) samlStart(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": errProviderUnavailable.Error()})
	}
	redirect, ok := safeRedirect(c.Query("redirect"))
	if !ok {
		return c.Status(400).JSON(fiber.Map{"error": "redirect must be a path under /ui/"})
	}
	p, err := id.samlSP(c.Context(), pid)
	if errors.Is(err, errProviderUnavailable) {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}
	if err != nil {
		slog.Error("saml provider unavailable", "provider", pid, "err", err)
		return auth.Deny(c, fiber.StatusServiceUnavailable, "sso_unavailable", "this sign-in provider is not configured correctly")
	}
	doc, err := p.sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return serverError(c, err)
	}
	reqID := doc.Root().SelectAttrValue("ID", "")
	if reqID == "" {
		return serverError(c, errors.New("saml: the AuthnRequest has no ID"))
	}
	to, err := p.sp.BuildAuthURLRedirect("", doc)
	if err != nil {
		return serverError(c, err)
	}
	browser, err := randomToken()
	if err != nil {
		return serverError(c, err)
	}
	if _, err := id.db.Exec(c.Context(),
		`INSERT INTO saml_requests (request_id, provider_id, redirect, browser_hash, expires_at)
		 VALUES ($1, $2, $3, $4, NOW() + $5::interval)`, reqID, pid, redirect, tenant.HashKey(browser), samlStateTTL); err != nil {
		return serverError(c, err)
	}
	_, _ = id.db.Exec(c.Context(), `DELETE FROM saml_requests WHERE expires_at < NOW()`)
	c.Cookie(id.samlBrowserCookie(browser, int(samlStateTTL.Seconds())))
	return c.Redirect(to, fiber.StatusFound)
}

// samlBrowserCookie binds a login to the browser. The IdP posts the response
// from its own site: over https the cookie must be SameSite=None to come
// along; over http (development) Lax works when the IdP is same-site.
func (id *identity) samlBrowserCookie(value string, maxAge int) *fiber.Cookie {
	secure := strings.HasPrefix(id.publicURL, "https://")
	same := fiber.CookieSameSiteLaxMode
	if secure {
		same = fiber.CookieSameSiteNoneMode
	}
	return &fiber.Cookie{Name: samlCookie, Value: value, Path: "/v1/auth/saml", MaxAge: maxAge, HTTPOnly: true,
		Secure: secure, SameSite: same}
}

// samlLogin is what a verified response says.
type samlLogin struct {
	assertionID  string
	inResponseTo string
	expires      time.Time
	subject      string
	email        string
	name         string
	groups       []string
}

// errSAML is a refused response; code goes to the UI, reason to the logs.
type errSAML struct{ code, reason string }

func (e *errSAML) Error() string { return "saml: " + e.code + ": " + e.reason }

func refuse(code, format string, args ...any) error {
	return &errSAML{code: code, reason: fmt.Sprintf(format, args...)}
}

// verifyResponse checks an encoded SAMLResponse (see the package comment)
// and reads the login from its one assertion.
func verifyResponse(p *samlProvider, encoded string) (samlLogin, error) {
	var l samlLogin
	if len(encoded) > samlMaxBody {
		return l, refuse("invalid_response", "the response is too large")
	}
	info, err := p.sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		return l, refuse("invalid_response", "%v", err)
	}
	if len(info.Assertions) != 1 {
		return l, refuse("invalid_response", "%d assertions; exactly one is accepted", len(info.Assertions))
	}
	a := info.Assertions[0]
	w := info.WarningInfo
	if w == nil || w.NotInAudience {
		return l, refuse("invalid_response", "the audience is not %s", p.sp.AudienceURI)
	}
	if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
		return l, refuse("invalid_response", "the assertion has no AudienceRestriction")
	}
	now := p.sp.Clock.Now()
	notBefore, err1 := time.Parse(time.RFC3339, a.Conditions.NotBefore)
	notAfter, err2 := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
	if err1 != nil || err2 != nil {
		return l, refuse("invalid_response", "the assertion's validity period cannot be read")
	}
	if now.Add(samlSkew).Before(notBefore) || !now.Before(notAfter) {
		return l, refuse("expired", "the assertion is valid from %s to %s", a.Conditions.NotBefore, a.Conditions.NotOnOrAfter)
	}
	if a.ID == "" || len(a.ID) > 256 {
		return l, refuse("invalid_response", "the assertion has no usable ID")
	}
	scd := a.Subject.SubjectConfirmation.SubjectConfirmationData // checked by gosaml2's Validate
	l.inResponseTo = scd.InResponseTo
	l.assertionID = a.ID
	l.expires = notAfter
	if t, err := time.Parse(time.RFC3339, scd.NotOnOrAfter); err == nil && t.Before(l.expires) {
		l.expires = t
	}
	l.subject = strings.TrimSpace(info.NameID)
	if l.subject == "" || len(l.subject) > 255 {
		return l, refuse("invalid_response", "the NameID is empty or longer than 255 characters")
	}
	email := firstValue(info.Values, attrNames(p.row.SAMLEmailAttribute, samlEmailAttrs))
	if email == "" && strings.Contains(l.subject, "@") {
		email = l.subject
	}
	l.email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(l.email) {
		return l, refuse("email_not_verified", "no email attribute")
	}
	l.name = firstValue(info.Values, attrNames(p.row.SAMLNameAttribute, samlNameAttrs))
	for _, name := range attrNames(p.row.SAMLGroupsAttribute, samlGroupAttrs) {
		if attr, ok := info.Values[name]; ok {
			for _, v := range attr.Values {
				if g := strings.TrimSpace(v.Value); g != "" && len(g) <= 256 && len(l.groups) < maxSAMLGroups {
					l.groups = append(l.groups, g)
				}
			}
			break
		}
	}
	return l, nil
}

// attrNames is the configured attribute, or the usual names.
func attrNames(configured string, defaults []string) []string {
	if configured != "" {
		return []string{configured}
	}
	return defaults
}

func firstValue(values saml2.Values, names []string) string {
	for _, n := range names {
		if v := strings.TrimSpace(values.Get(n)); v != "" {
			return v
		}
	}
	return ""
}

func (id *identity) samlACS(c *fiber.Ctx) error {
	ctx := c.Context()
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return ssoError(c, "invalid_state")
	}
	p, err := id.samlSP(ctx, pid)
	if err != nil {
		slog.Warn("saml acs: provider unavailable", "provider", pid, "err", err)
		return ssoError(c, "sso_unavailable")
	}
	method := p.row.method()
	fail := func(code, reason string) error {
		slog.Warn("saml login refused", "provider", pid, "code", code, "reason", reason)
		logUserEvent(ctx, id.db, uuid.Nil, "login.failed", clientIP(c), map[string]any{"method": method, "reason": code})
		return ssoError(c, code)
	}
	l, err := verifyResponse(p, c.FormValue("SAMLResponse"))
	var se *errSAML
	if errors.As(err, &se) {
		return fail(se.code, se.reason)
	}
	if err != nil {
		return serverError(c, err)
	}

	redirect := defaultReturn
	browser := c.Cookies(samlCookie)
	c.Cookie(id.samlBrowserCookie("", -1))
	if l.inResponseTo != "" {
		var browserHash string
		err := id.db.QueryRow(ctx,
			`DELETE FROM saml_requests WHERE request_id = $1 AND provider_id = $2 AND expires_at > NOW()
			 RETURNING redirect, browser_hash`, l.inResponseTo, pid).Scan(&redirect, &browserHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail("invalid_state", "InResponseTo names no pending request")
		}
		if err != nil {
			return serverError(c, err)
		}
		// The response must come back to the browser that started the login:
		// otherwise an attacker could log a victim into the attacker's account.
		if browser == "" || subtle.ConstantTimeCompare([]byte(tenant.HashKey(browser)), []byte(browserHash)) != 1 {
			return fail("invalid_state", "the login was started in another browser")
		}
	} else if !p.row.SAMLAllowIdPInitiated {
		return fail("idp_initiated_disabled", "unsolicited response (no InResponseTo)")
	}

	// Each assertion logs in once.
	tag, err := id.db.Exec(ctx,
		`INSERT INTO saml_assertions (provider_id, assertion_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		pid, l.assertionID, l.expires.Add(samlSkew))
	if err != nil {
		return serverError(c, err)
	}
	if tag.RowsAffected() == 0 {
		return fail("replayed", "assertion "+l.assertionID+" was already used")
	}
	_, _ = id.db.Exec(ctx, `DELETE FROM saml_assertions WHERE expires_at < NOW()`)

	if !domainAllowed(p.row, l.email, "") {
		return fail("domain_not_allowed", "domain "+emailDomain(l.email))
	}
	user, err := id.ssoUser(ctx, p.row, l.subject, l.email, l.name)
	var ue *errSSO
	if errors.As(err, &ue) {
		logUserEvent(ctx, id.db, user, "login.failed", clientIP(c), map[string]any{"method": method, "reason": ue.code})
		return ssoError(c, ue.code)
	}
	if err != nil {
		return serverError(c, err)
	}
	if len(l.groups) > 0 {
		if err := applySAMLGroupRoles(ctx, id.db, user, pid, l.groups); err != nil {
			slog.Error("saml: group roles", "provider", pid, "err", err)
		}
	}
	code, err := randomToken()
	if err != nil {
		return serverError(c, err)
	}
	if _, err := id.db.Exec(ctx,
		`INSERT INTO oidc_codes (code_hash, user_id, method, redirect, expires_at, purpose)
		 VALUES ($1, $2, $3, $4, NOW() + $5::interval, 'login')`,
		tenant.HashKey(code), user, method, redirect, oidcCodeTTL); err != nil {
		return serverError(c, err)
	}
	return c.Redirect(callbackPath+"?code="+url.QueryEscape(code), fiber.StatusFound)
}
